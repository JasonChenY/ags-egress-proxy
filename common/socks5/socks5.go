// Package socks5 提供带沙箱身份认证的 SOCKS5 客户端拨号，以及 HMAC 凭证的
// 构造与校验（客户端与网关共用同一套口径）。
//
// 凭证格式（RFC 1929 用户名口令子协商）：
//
//	UNAME = "<sandboxID>@<unixTS>"
//	PASSWD = base64url(HMAC-SHA256(secret, UNAME))
//
// 时间戳参与签名，网关侧校验 |now-ts| <= maxSkew 防重放。
package socks5

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Credentials 是一次 SOCKS5 用户名口令认证。
// 沙箱客户端用 MakeCredentials 生成 HMAC 凭证；
// 网关后端 socks 出口用静态用户名口令。
type Credentials struct {
	User string
	Pass string
}

// MakeCredentials 生成 "sandboxID@unixTS" / HMAC-SHA256(secret, user)。
func MakeCredentials(sandboxID string, secret []byte) Credentials {
	user := fmt.Sprintf("%s@%d", sandboxID, time.Now().Unix())
	return Credentials{
		User: user,
		Pass: sign(user, secret),
	}
}

// VerifyCredentials 校验凭证并返回 sandboxID。
func VerifyCredentials(creds Credentials, secret []byte, maxSkew time.Duration) (string, error) {
	user := creds.User
	i := strings.LastIndexByte(user, '@')
	if i <= 0 {
		return "", fmt.Errorf("bad username format")
	}
	id, tsStr := user[:i], user[i+1:]
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("bad timestamp")
	}
	if d := time.Since(time.Unix(ts, 0)); d > maxSkew || d < -maxSkew {
		return "", fmt.Errorf("timestamp skew too large")
	}
	if !hmac.Equal([]byte(sign(user, secret)), []byte(creds.Pass)) {
		return "", fmt.Errorf("hmac mismatch")
	}
	return id, nil
}

func sign(user string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(user))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Dial 经 proxyAddr 建立到 host:port 的 SOCKS5 CONNECT 连接。
// host 可以是 IPv4 / IPv6 / 域名（域名用 ATYP=0x03 交给服务端解析）。
func Dial(proxyAddr, host string, port int, creds Credentials, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
	}

	// ① 问候：声明支持 无认证(0x00) / 用户名口令(0x02)
	if _, err := c.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		c.Close()
		return nil, err
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		c.Close()
		return nil, err
	}
	if m[0] != 0x05 {
		c.Close()
		return nil, fmt.Errorf("bad socks version %d", m[0])
	}
	switch m[1] {
	case 0x00:
		// 服务端允许无认证，跳过子协商（后端 socks 常见）
	case 0x02:
		u, p := []byte(creds.User), []byte(creds.Pass)
		if len(u) > 255 || len(p) > 255 {
			c.Close()
			return nil, fmt.Errorf("credential too long")
		}
		auth := make([]byte, 0, 3+len(u)+len(p))
		auth = append(auth, 0x01, byte(len(u)))
		auth = append(auth, u...)
		auth = append(auth, byte(len(p)))
		auth = append(auth, p...)
		if _, err := c.Write(auth); err != nil {
			c.Close()
			return nil, err
		}
		var a [2]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			c.Close()
			return nil, err
		}
		if a[1] != 0x00 {
			c.Close()
			return nil, fmt.Errorf("auth rejected (status %d)", a[1])
		}
	default:
		c.Close()
		return nil, fmt.Errorf("server selected unsupported method 0x%02x", m[1])
	}

	// ② 请求 CONNECT
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			c.Close()
			return nil, fmt.Errorf("host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}

	// ③ 应答
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		c.Close()
		return nil, err
	}
	if h[0] != 0x05 {
		c.Close()
		return nil, fmt.Errorf("bad reply version")
	}
	if h[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("connect failed, rep=0x%02x", h[1])
	}
	switch h[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, c, 4+2)
	case 0x03:
		var l [1]byte
		if _, err = io.ReadFull(c, l[:]); err == nil {
			_, err = io.CopyN(io.Discard, c, int64(l[0])+2)
		}
	case 0x04:
		_, err = io.CopyN(io.Discard, c, 16+2)
	default:
		err = fmt.Errorf("bad atyp in reply")
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Pipe 双向搬运并返回字节数：aToB = a→b（上行），bToA = b→a（下行）。
// 任一方向结束即对另一方向设置 Deadline 促使其退出。
func Pipe(a, b net.Conn) (aToB, bToA int64) {
	done := make(chan struct{}, 2)
	go func() {
		aToB, _ = io.Copy(b, a)
		b.SetDeadline(time.Now())
		done <- struct{}{}
	}()
	go func() {
		bToA, _ = io.Copy(a, b)
		a.SetDeadline(time.Now())
		done <- struct{}{}
	}()
	<-done
	<-done
	return
}
