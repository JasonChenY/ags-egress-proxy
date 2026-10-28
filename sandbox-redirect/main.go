// sandbox-redirect 是方案 A 客户端的 iptables 模式（推荐，性能优于 TUN）：
//
//	-mode redirect  本机出流量，配套 nat OUTPUT + REDIRECT 规则（setup-redirect.sh 模式一）
//	-mode tproxy    网关转发模式，配套 mangle PREROUTING + TPROXY 规则（setup-redirect.sh 模式二）
//
// redirect 模式用 getsockopt(SO_ORIGINAL_DST) 取原始目的地址；
// tproxy 模式下 accepted 连接的 LocalAddr 即原始目的地址（TPROXY 语义）。
// 仅 TCP；UDP 参见 README 限制一节。
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"ags-egress-proxy/common/socks5"
)

const (
	soOriginalDst = 80 // SO_ORIGINAL_DST (Linux)
	ipTransparent = 19 // IP_TRANSPARENT
)

func main() {
	var (
		mode      = flag.String("mode", "redirect", "redirect | tproxy")
		listen    = flag.String("listen", "", "监听地址；默认 redirect=127.0.0.1:15000 / tproxy=0.0.0.0:15001")
		proxyAddr = flag.String("proxy", os.Getenv("AGS_SOCKS_PROXY"), "SOCKS5 网关地址 ip:port（必填）")
	)
	flag.Parse()

	id := os.Getenv("AGS_SANDBOX_ID")
	secret, err := base64.StdEncoding.DecodeString(os.Getenv("AGS_SOCKS_SECRET"))
	if err != nil {
		log.Fatalf("AGS_SOCKS_SECRET 不是合法 base64: %v", err)
	}
	if *proxyAddr == "" || id == "" || len(secret) == 0 {
		log.Fatal("需要 -proxy（或 AGS_SOCKS_PROXY）及环境变量 AGS_SANDBOX_ID / AGS_SOCKS_SECRET")
	}

	if *listen == "" {
		if *mode == "tproxy" {
			*listen = "0.0.0.0:15001"
		} else {
			*listen = "127.0.0.1:15000"
		}
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if *mode != "tproxy" {
				return nil
			}
			// TPROXY 要求监听 socket 设置 IP_TRANSPARENT（bind 前生效）
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipTransparent, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	ln, err := lc.Listen(context.Background(), "tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s 模式监听 %s，上游 %s，id=%s", *mode, *listen, *proxyAddr, id)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handle(c, *mode, *proxyAddr, id, secret)
	}
}

func handle(c net.Conn, mode, proxyAddr, id string, secret []byte) {
	defer c.Close()

	var host string
	var port int
	switch mode {
	case "tproxy":
		la, ok := c.LocalAddr().(*net.TCPAddr)
		if !ok {
			return
		}
		host, port = la.IP.String(), la.Port
	default: // redirect
		dst, err := originalDst(c)
		if err != nil {
			log.Printf("original dst: %v", err)
			return
		}
		host, port = dst.IP.String(), dst.Port
	}

	up, err := socks5.Dial(proxyAddr, host, port, socks5.MakeCredentials(id, secret), 15*time.Second)
	if err != nil {
		log.Printf("socks dial %s:%d: %v", host, port, err)
		return
	}
	defer up.Close()
	socks5.Pipe(c, up)
}

// originalDst 通过 conntrack 取 REDIRECT 前的原始目的地址。
func originalDst(c net.Conn) (*net.TCPAddr, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCPConn")
	}
	f, err := tc.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var sa syscall.RawSockaddrInet4
	salen := uint32(unsafe.Sizeof(sa)) // getsockopt 的 optlen 是 socklen_t* —— 必须传指针
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		f.Fd(),
		uintptr(syscall.IPPROTO_IP),
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&sa)),
		uintptr(unsafe.Pointer(&salen)),
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	ip := make(net.IP, 4)
	copy(ip, sa.Addr[:])
	pb := (*[2]byte)(unsafe.Pointer(&sa.Port)) // 网络字节序
	return &net.TCPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(pb[:]))}, nil
}
