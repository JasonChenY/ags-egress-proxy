// gateway 是方案 A 的外部 SOCKS5 出口网关：
// 单一入口 → 验签解析沙箱 ID → 按 ID 规则 / 一致性哈希选择出口 → 审计。
//
// 出口（outlet）两种类型：
//	local : 从本机指定源 IP（BindIP）直连目标——多出口 IP 机器
//	socks : 再经一台后端 SOCKS5 转发——出口为独立机器
//
// 路由（routes）按 id_prefix / id_regex 把特定沙箱绑到特定出口；
// 未命中规则的 ID 走 default_strategy（consistent-hash，含虚拟节点）。
package main

import (
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ags-egress-proxy/common/socks5"

	"gopkg.in/yaml.v3"
)

// ---------- 配置 ----------

// audit_log 未配置时的默认审计日志路径
const defaultAuditLog = "/var/log/ags-egress-proxy-audit.log"

type Outlet struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`     // local | socks
	BindIP   string `yaml:"bind_ip"`  // local：源 IP 绑定（多出口机器）
	Address  string `yaml:"address"`  // socks：后端 socks5 地址 ip:port
	Username string `yaml:"username"` // socks：后端认证用户名
	Password string `yaml:"password"` // socks：后端认证口令
}

type RouteRule struct {
	IDPrefix string `yaml:"id_prefix"`
	IDRegex  string `yaml:"id_regex"`
	Outlet   string `yaml:"outlet"`
}

type Config struct {
	Listen         string      `yaml:"listen"`
	Secret         string      `yaml:"secret"`            // base64，与沙箱侧 AGS_SOCKS_SECRET 一致
	MaxSkewSeconds int64       `yaml:"max_skew_seconds"` // 时间戳容差（防重放）
	MaxConnsPerID  int         `yaml:"max_conns_per_id"` // 每 ID 并发上限，0 = 不限
	Outlets        []Outlet    `yaml:"outlets"`
	Routes         []RouteRule `yaml:"routes"`
	DefaultStrategy string    `yaml:"default_strategy"` // consistent-hash | round-robin
	AuditLog       string      `yaml:"audit_log"`       // 审计日志文件，空=默认路径，"-"/"stdout"=标准输出
}

// ---------- 一致性哈希环 ----------

type ringSlot struct {
	h    uint64
	name string
}

type hashRing struct {
	slots []ringSlot // 按 h 升序
}

func fnv64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func newRing(names []string, vnodes int) *hashRing {
	if vnodes <= 0 {
		vnodes = 64
	}
	var r hashRing
	for _, n := range names {
		for i := 0; i < vnodes; i++ {
			r.slots = append(r.slots, ringSlot{fnv64(fmt.Sprintf("%s#%d", n, i)), n})
		}
	}
	sort.Slice(r.slots, func(i, j int) bool { return r.slots[i].h < r.slots[j].h })
	return &r
}

func (r *hashRing) pick(key string) string {
	if len(r.slots) == 0 {
		return ""
	}
	h := fnv64(key)
	i := sort.Search(len(r.slots), func(i int) bool { return r.slots[i].h >= h })
	if i == len(r.slots) {
		i = 0
	}
	return r.slots[i].name
}

// ---------- 网关 ----------

type Gateway struct {
	cfg      *Config
	secret   []byte
	outlets  map[string]*Outlet
	ring     *hashRing
	rr       uint64
	rrMu     sync.Mutex
	regexps  []*regexp.Regexp
	rules    []compiledRule
	mu       sync.Mutex
	conns    map[string]int
	audit    *log.Logger
}

type compiledRule struct {
	re    *regexp.Regexp
	pref  string
	name  string
}

func newGateway(cfg *Config) (*Gateway, error) {
	secret, err := base64.StdEncoding.DecodeString(cfg.Secret)
	if err != nil {
		return nil, fmt.Errorf("secret 不是合法 base64: %w", err)
	}
	if cfg.MaxSkewSeconds == 0 {
		cfg.MaxSkewSeconds = 300
	}
	g := &Gateway{
		cfg:     cfg,
		secret:  secret,
		outlets: make(map[string]*Outlet),
		conns:   make(map[string]int),
	}
	var names []string
	for i := range cfg.Outlets {
		o := &cfg.Outlets[i]
		if o.Type == "" {
			o.Type = "local"
		}
		g.outlets[o.Name] = o
		names = append(names, o.Name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("至少配置一个 outlet")
	}
	g.ring = newRing(names, 64)
	for _, r := range cfg.Routes {
		cr := compiledRule{pref: r.IDPrefix, name: r.Outlet}
		if r.IDRegex != "" {
			re, err := regexp.Compile(r.IDRegex)
			if err != nil {
				return nil, fmt.Errorf("route regex %q: %w", r.IDRegex, err)
			}
			cr.re = re
		}
		g.rules = append(g.rules, cr)
	}
	w := os.Stdout
	auditPath := cfg.AuditLog
	if auditPath == "" {
		auditPath = defaultAuditLog // 未配置 = 默认文件
	}
	if auditPath != "-" && auditPath != "stdout" {
		if dir := filepath.Dir(auditPath); dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil { // 父目录不存在则自动创建
				return nil, err
			}
		}
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return nil, err
		}
		w = f
	}
	g.audit = log.New(w, "", log.LstdFlags|log.Lmicroseconds)
	return g, nil
}

func (g *Gateway) pickOutlet(id string) *Outlet {
	for _, r := range g.rules {
		if r.pref != "" && !strings.HasPrefix(id, r.pref) {
			continue
		}
		if r.re != nil && !r.re.MatchString(id) {
			continue
		}
		if o, ok := g.outlets[r.name]; ok {
			return o
		}
	}
	if g.cfg.DefaultStrategy == "round-robin" {
		g.rrMu.Lock()
		g.rr++
		idx := int(g.rr % uint64(len(g.cfg.Outlets)))
		g.rrMu.Unlock()
		return &g.cfg.Outlets[idx]
	}
	return g.outlets[g.ring.pick(id)] // 默认一致性哈希：同 ID 稳定落同一出口
}

func (g *Gateway) acquire(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cfg.MaxConnsPerID > 0 && g.conns[id] >= g.cfg.MaxConnsPerID {
		return false
	}
	g.conns[id]++
	return true
}

func (g *Gateway) release(id string) {
	g.mu.Lock()
	if g.conns[id] <= 1 {
		delete(g.conns, id)
	} else {
		g.conns[id]--
	}
	g.mu.Unlock()
}

func (g *Gateway) dialOutlet(o *Outlet, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	switch o.Type {
	case "local":
		d := net.Dialer{Timeout: 15 * time.Second}
		if o.BindIP != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(o.BindIP)}
		}
		return d.Dial("tcp", addr)
	case "socks":
		return socks5.Dial(o.Address, host, port,
			socks5.Credentials{User: o.Username, Pass: o.Password}, 15*time.Second)
	}
	return nil, fmt.Errorf("unknown outlet type %q", o.Type)
}

// ---------- SOCKS5 服务端 ----------

func writeReply(c net.Conn, rep byte) error {
	// VER REP RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0
	_, err := c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func readRequest(c net.Conn) (cmd byte, host string, port int, err error) {
	var h [4]byte
	if _, err = io.ReadFull(c, h[:]); err != nil {
		return
	}
	if h[0] != 0x05 {
		err = fmt.Errorf("bad version")
		return
	}
	cmd = h[1]
	switch h[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		var l [1]byte
		if _, err = io.ReadFull(c, l[:]); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		err = fmt.Errorf("bad atyp")
		return
	}
	var p [2]byte
	if _, err = io.ReadFull(c, p[:]); err != nil {
		return
	}
	port = int(binary.BigEndian.Uint16(p[:]))
	return
}

func (g *Gateway) handle(c net.Conn) {
	defer c.Close()
	remote := c.RemoteAddr()

	// ① 问候
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	accept := false
	for _, m := range methods {
		if m == 0x02 {
			accept = true
			break
		}
	}
	if !accept {
		c.Write([]byte{0x05, 0xFF}) // 无可接受方法
		return
	}
	c.Write([]byte{0x05, 0x02})

	// ② 认证子协商：验签 + 解析 sandboxID
	var ah [2]byte
	if _, err := io.ReadFull(c, ah[:]); err != nil || ah[0] != 0x01 {
		c.Write([]byte{0x01, 0x01})
		return
	}
	uname := make([]byte, ah[1])
	if _, err := io.ReadFull(c, uname); err != nil {
		return
	}
	var pl [1]byte
	if _, err := io.ReadFull(c, pl[:]); err != nil {
		return
	}
	passwd := make([]byte, pl[0])
	if _, err := io.ReadFull(c, passwd); err != nil {
		return
	}
	id, err := socks5.VerifyCredentials(
		socks5.Credentials{User: string(uname), Pass: string(passwd)},
		g.secret, time.Duration(g.cfg.MaxSkewSeconds)*time.Second)
	if err != nil {
		c.Write([]byte{0x01, 0x01})
		g.audit.Printf("auth-fail remote=%v user=%q err=%v", remote, string(uname), err)
		return
	}
	c.Write([]byte{0x01, 0x00})

	// ③ 每 ID 并发限流
	if !g.acquire(id) {
		writeReply(c, 0x02) // not allowed
		g.audit.Printf("limit id=%s remote=%v", id, remote)
		return
	}
	defer g.release(id)

	// ④ 请求
	cmd, host, port, err := readRequest(c)
	if err != nil {
		return
	}
	if cmd != 0x01 { // 仅 CONNECT
		writeReply(c, 0x07)
		return
	}

	// ⑤ 选出口并拨号
	outlet := g.pickOutlet(id)
	up, err := g.dialOutlet(outlet, host, port)
	if err != nil {
		writeReply(c, 0x03) // network unreachable
		g.audit.Printf("dial-fail id=%s dst=%s:%d outlet=%s err=%v", id, host, port, outlet.Name, err)
		return
	}
	defer up.Close()
	if err := writeReply(c, 0x00); err != nil {
		return
	}

	// ⑥ 转发 + 审计
	upBytes, downBytes := socks5.Pipe(c, up)
	g.audit.Printf("conn id=%s dst=%s:%d outlet=%s up=%d down=%d",
		id, host, port, outlet.Name, upBytes, downBytes)
}

func main() {
	cfgPath := flag.String("config", "gateway.yaml", "配置文件路径")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":1080"
	}

	g, err := newGateway(&cfg)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("gateway 就绪: listen=%s outlets=%d strategy=%s",
		cfg.Listen, len(cfg.Outlets), orDefault(cfg.DefaultStrategy, "consistent-hash"))

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go g.handle(c)
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
