// sandbox-tun2socks 在 AGS 沙箱内把发往 tun0 的 TCP 流量经外部 SOCKS5 网关转出，
// 认证子协商携带沙箱 ID 与 HMAC 签名（方案 A 客户端 · TUN 模式）。
//
// 配套 scripts/setup-tun.sh 建设备与路由；DNS / SOCKS 网关 IP 需在脚本里走
// eth0 直连，避免递归环路。仅支持 TCP（UDP/QUIC 不经过本进程，见 README）。
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"syscall"
	"time"
	"unsafe"

	"ags-egress-proxy/common/socks5"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tunDevice = "/dev/net/tun"
	iffTun    = 0x0001
	iffNoPi   = 0x1000
	// 与 CubeSandbox hypervisor/vmm/src/seccomp_filters.rs 中的常量一致
	tunSetIFF = 0x400454ca
)

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [22]byte // struct ifreq 对齐
}

func openTun(name string) (*os.File, error) {
	f, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevice, err)
	}
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPi
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF: %v", errno)
	}
	return f, nil
}

func main() {
	var (
		proxyAddr = flag.String("proxy", os.Getenv("AGS_SOCKS_PROXY"), "SOCKS5 网关地址 ip:port（必填）")
		dev       = flag.String("dev", "tun0", "TUN 设备名")
		mtu       = flag.Uint("mtu", 1400, "TUN MTU（留出封装余量）")
		localIP   = flag.String("local-ip", "198.18.0.1", "netstack 侧地址，须与 setup-tun.sh 一致")
	)
	flag.Parse()

	id := os.Getenv("AGS_SANDBOX_ID")
	secretB64 := os.Getenv("AGS_SOCKS_SECRET")
	if *proxyAddr == "" || id == "" || secretB64 == "" {
		log.Fatal("需要 -proxy（或 AGS_SOCKS_PROXY）及环境变量 AGS_SANDBOX_ID / AGS_SOCKS_SECRET")
	}
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		log.Fatalf("AGS_SOCKS_SECRET 不是合法 base64: %v", err)
	}

	tunFile, err := openTun(*dev)
	if err != nil {
		log.Fatal(err)
	}
	fd := int(tunFile.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		log.Fatalf("setnonblock: %v", err)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs: []int{fd},
		MTU: uint32(*mtu),
	})
	if err != nil {
		log.Fatalf("fdbased.New: %v", err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		log.Fatalf("CreateNIC: %v", err)
	}
	addr, err := netip.ParseAddr(*localIP)
	if err != nil {
		log.Fatal(err)
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		log.Fatalf("AddProtocolAddress: %v", err)
	}
	// 接受目的地址为任意外部 IP 的包（netstack 只做中间人）
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	fwd := tcp.NewForwarder(s, 4096, 4096, func(r *tcp.ForwarderRequest) {
		reqID := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		// netstack 视角：LocalAddress/LocalPort 即沙箱要访问的外部目的地址
		host := reqID.LocalAddress.String()
		port := int(reqID.LocalPort)
		go serve(ep, &wq, host, port, *proxyAddr, id, secret)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	log.Printf("tun2socks 就绪: dev=%s mtu=%d proxy=%s id=%s", *dev, *mtu, *proxyAddr, id)
	select {} // fdbased endpoint 自带读写 goroutine，主协程阻塞
}

func serve(ep tcpip.Endpoint, wq *waiter.Queue, host string, port int, proxyAddr, id string, secret []byte) {
	local := gonet.NewTCPConn(wq, ep)
	defer local.Close()
	up, err := socks5.Dial(proxyAddr, host, port, socks5.MakeCredentials(id, secret), 15*time.Second)
	if err != nil {
		log.Printf("socks dial %s:%d: %v", host, port, err)
		return
	}
	defer up.Close()
	socks5.Pipe(local, up)
}
