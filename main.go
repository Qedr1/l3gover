package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/BurntSushi/toml"
	quic "github.com/quic-go/quic-go"
	netlink "github.com/vishvananda/netlink"
)

// ======================= конфиг и типы =======================

type Config struct {
	Tun struct {
		Name       string   `toml:"name"`
		Addr       string   `toml:"addr"`
		LinkMTU    int      `toml:"link_mtu"`
		AddRoute   bool     `toml:"add_route"`
		GrayRoutes []string `toml:"gray_routes"`
		MTU        int      `toml:"mtu"`
	} `toml:"tun"`
	Transport struct {
		Listen    string        `toml:"listen"`
		ALPN      string        `toml:"alpn"`
		Insecure  bool          `toml:"insecure"` // всегда true
		Streams   int           `toml:"streams"`
		UDPRcv    int           `toml:"udp_rbuf"`
		UDPSnd    int           `toml:"udp_wbuf"`
		Idle      time.Duration `toml:"idle"`
		KeepAlive time.Duration `toml:"keepalive"`
	} `toml:"transport"`
	Map struct {
		Path string `toml:"path"`
	} `toml:"map"`
	Batch struct {
		Bytes int           `toml:"bytes"`    // минимум=MTU
		Flush time.Duration `toml:"flush_ms"` // период флеша
	} `toml:"batch"`
	Log struct {
		Level string `toml:"level"`
	} `toml:"log"`
}

type peersTOML struct {
	Peers map[string]string `toml:"peers"`
}

type tunDevice struct {
	fd  int
	wmu sync.Mutex
}

type peerMap struct {
	mu sync.RWMutex
	m  map[uint32]string
}

type streamState struct{ s *quic.Stream }

type quicState struct {
	conn *quic.Conn
	ss   []streamState
	rr   uint64
	dead atomic.Bool
	once sync.Once
}

type dialCache struct {
	mu      sync.RWMutex
	m       map[string]*quicState
	pc      net.PacketConn
	closing atomic.Bool
	udpRcv  int
	udpSnd  int
}

type batchAgg struct {
	ep string
	qs *quicState
	st *streamState
	b  []byte
}

// ======================= системные константы TUN =======================

const (
	iffTUN    = 0x0001
	iffNO_PI  = 0x1000
	TUNSETIFF = 0x400454ca
	IFNAMSIZ  = 16
)

type ifreq struct {
	Name  [IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

// ============================== утилиты ===============================

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Tun.Name == "" {
		cfg.Tun.Name = "tun0"
	}
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 1500
	}
	if cfg.Tun.MTU < 576 || cfg.Tun.MTU > 65535 {
		return cfg, errors.New("mtu вне диапазона")
	}
	if cfg.Transport.Listen == "" {
		cfg.Transport.Listen = "0.0.0.0:5555"
	}
	if cfg.Transport.ALPN == "" {
		cfg.Transport.ALPN = "go-l3-overlay"
	}
	if cfg.Transport.Streams < 1 {
		cfg.Transport.Streams = 4
	}
	if cfg.Transport.UDPRcv == 0 {
		cfg.Transport.UDPRcv = 16 << 20
	}
	if cfg.Transport.UDPSnd == 0 {
		cfg.Transport.UDPSnd = 16 << 20
	}
	if cfg.Transport.Idle == 0 {
		cfg.Transport.Idle = 10 * time.Minute
	}
	cfg.Transport.Insecure = true
	// Батч по умолчанию: 256KiB и 10ms
	if cfg.Batch.Bytes == 0 {
		cfg.Batch.Bytes = 256 << 10
	}
	if cfg.Batch.Bytes < cfg.Tun.MTU {
		cfg.Batch.Bytes = cfg.Tun.MTU
	}
	if cfg.Batch.Flush == 0 {
		cfg.Batch.Flush = 10 * time.Millisecond
	}
	if cfg.Map.Path == "" {
		cfg.Map.Path = "peers.toml"
	}
	return cfg, nil
}

func clamp(x, lo, hi int) int {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// ============================= TUN I/O ================================

func openTUN(name string) (*tunDevice, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("open /dev/net/tun: " + err.Error())
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTUN | iffNO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, errors.New("ioctl TUNSETIFF")
	}
	return &tunDevice{fd: fd}, nil
}

func (t *tunDevice) Read(p []byte) (int, error) { return syscall.Read(t.fd, p) }
func (t *tunDevice) Write(p []byte) (int, error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	return syscall.Write(t.fd, p)
}
func (t *tunDevice) Close() error { return syscall.Close(t.fd) }

func configureTUN(name, cidr string, linkMTU int, addRoute bool) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return errors.New("link not found: " + err.Error())
	}
	if linkMTU > 0 {
		if err := netlink.LinkSetMTU(link, linkMTU); err != nil {
			return errors.New("set mtu: " + err.Error())
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return errors.New("link up: " + err.Error())
	}
	if cidr == "" {
		return nil
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return errors.New("addr parse: " + err.Error())
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return errors.New("IPv4 only")
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip4, Mask: ipnet.Mask}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return errors.New("addr set: " + err.Error())
	}
	if addRoute {
		netIP := ip4.Mask(ipnet.Mask)
		dst := &net.IPNet{IP: netIP, Mask: ipnet.Mask}
		rt := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
		if err := netlink.RouteReplace(rt); err != nil {
			return errors.New("route add: " + err.Error())
		}
	}
	return nil
}

func addGrayRoutes(tunName string, cidrs []string) error {
	if len(cidrs) == 0 {
		return nil
	}
	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return errors.New("link not found: " + err.Error())
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return errors.New("gray-route parse: " + err.Error())
		}
		if ipnet.IP.To4() == nil {
			return errors.New("gray-route: только IPv4")
		}
		rt := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipnet}
		if err := netlink.RouteReplace(rt); err != nil {
			return errors.New("gray-route add: " + err.Error())
		}
	}
	return nil
}

// ======================== мэппинг адресов ========================

func newPeerMap() *peerMap { return &peerMap{m: make(map[uint32]string)} }

func (pm *peerMap) loadFromTOML(path string) error {
	var pf peersTOML
	if _, err := toml.DecodeFile(path, &pf); err != nil {
		return err
	}
	if len(pf.Peers) == 0 {
		return errors.New("empty peers in mapping TOML")
	}
	tmp := make(map[uint32]string, len(pf.Peers))
	for gray, white := range pf.Peers {
		ip := net.ParseIP(strings.TrimSpace(gray))
		if ip == nil || ip.To4() == nil {
			return errors.New("map: IPv4 required: " + gray)
		}
		raddr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(white))
		if err != nil || raddr == nil || raddr.IP == nil {
			return errors.New("map: host:port invalid for " + gray)
		}
		key := binary.BigEndian.Uint32(ip.To4())
		tmp[key] = net.JoinHostPort(raddr.IP.String(), strconv.Itoa(raddr.Port))
	}
	pm.mu.Lock()
	pm.m = tmp
	pm.mu.Unlock()
	return nil
}

func (pm *peerMap) lookup(dstIPv4 []byte) (string, bool) {
	if len(dstIPv4) != 4 {
		return "", false
	}
	key := binary.BigEndian.Uint32(dstIPv4)
	pm.mu.RLock()
	v, ok := pm.m[key]
	pm.mu.RUnlock()
	return v, ok
}

func (pm *peerMap) endpoints() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	seen := make(map[string]struct{}, len(pm.m))
	out := make([]string, 0, len(pm.m))
	for _, ep := range pm.m {
		if _, ok := seen[ep]; ok {
			continue
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}
	return out
}

// ============================= фрейминг ==============================

func writeFrame(dst io.Writer, payload []byte) error {
	if len(payload) > 0xFFFF {
		return errors.New("frame too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := dst.Write(hdr[:]); err != nil {
		return err
	}
	_, err := dst.Write(payload)
	return err
}

func readFrame(src io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(src, hdr[:]); err != nil {
		return 0, err
	}
	ln := int(binary.BigEndian.Uint16(hdr[:]))
	if ln > len(buf) {
		return 0, errors.New("incoming frame larger than buffer")
	}
	_, err := io.ReadFull(src, buf[:ln])
	return ln, err
}

// ============================= IPv4 utils ============================

func ipv4Dst(pkt []byte) ([]byte, bool) {
	if len(pkt) < 20 {
		return nil, false
	}
	vihl := pkt[0]
	if vihl>>4 != 4 {
		return nil, false
	}
	ihl := int(vihl&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, false
	}
	return pkt[16:20], true
}

// ============================= QUIC state ============================

func (qs *quicState) pick() *streamState {
	i := atomic.AddUint64(&qs.rr, 1)
	return &qs.ss[i%uint64(len(qs.ss))]
}

// =========================== кэш QUIC-клиента ========================

func newDialCache(udpRcv, udpSnd int) *dialCache {
	return &dialCache{m: make(map[string]*quicState), udpRcv: udpRcv, udpSnd: udpSnd}
}

func (dc *dialCache) ensureClientPC() error {
	dc.mu.RLock()
	if dc.pc != nil {
		dc.mu.RUnlock()
		return nil
	}
	dc.mu.RUnlock()
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.pc != nil {
		return nil
	}
	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	if uc, ok := c.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(dc.udpRcv)
		_ = uc.SetWriteBuffer(dc.udpSnd)
	}
	dc.pc = c
	return nil
}

func (dc *dialCache) getOrDial(ctx context.Context, endpoint, alpn string, insecure bool, streamCount int, qconf *quic.Config) (*quicState, error) {
	dc.mu.RLock()
	if qs, ok := dc.m[endpoint]; ok && !qs.dead.Load() {
		dc.mu.RUnlock()
		return qs, nil
	}
	dc.mu.RUnlock()
	if dc.closing.Load() {
		return nil, errors.New("dial cache closing")
	}
	if err := dc.ensureClientPC(); err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{NextProtos: []string{alpn}, InsecureSkipVerify: insecure, ServerName: host, MinVersion: tls.VersionTLS13}
	raddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, err
	}
	conn, err := quic.Dial(ctx, dc.pc, raddr, tlsConf, qconf)
	if err != nil {
		return nil, err
	}

	if streamCount < 1 {
		streamCount = 1
	}
	ss := make([]streamState, streamCount)
	for i := range ss {
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			_ = conn.CloseWithError(0, "open stream fail")
			return nil, err
		}
		ss[i] = streamState{s: s}
	}
	qs := &quicState{conn: conn, ss: ss}

	dc.mu.Lock()
	if old, ok := dc.m[endpoint]; ok && !old.dead.Load() {
		dc.mu.Unlock()
		_ = conn.CloseWithError(0, "duplicate")
		return old, nil
	}
	dc.m[endpoint] = qs
	dc.mu.Unlock()
	return qs, nil
}

func (dc *dialCache) registerIncomingConn(endpoint string, conn *quic.Conn, streamCount int) *quicState {
	if streamCount < 1 {
		streamCount = 1
	}
	ss := make([]streamState, streamCount)
	for i := range ss {
		s, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			break
		}
		ss[i] = streamState{s: s}
	}
	qs := &quicState{conn: conn, ss: ss}
	dc.mu.Lock()
	if old, ok := dc.m[endpoint]; ok {
		old.dead.Store(true)
	}
	dc.m[endpoint] = qs
	dc.mu.Unlock()
	go func() { <-conn.Context().Done(); dc.drop(endpoint) }()
	return qs
}

func dialWithRetry(ctx context.Context, dc *dialCache, ep, alpn string, insecure bool, streams int, qconf *quic.Config) (*quicState, error) {
	attempt := 0
	for {
		attempt++
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		qs, err := dc.getOrDial(dctx, ep, alpn, insecure, streams, qconf)
		cancel()
		if err == nil {
			slog.Info("dial ok", "endpoint", ep, "attempt", attempt)
			return qs, nil
		}
		slog.Warn("dial retry", "endpoint", ep, "attempt", attempt, "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
}

func (dc *dialCache) drop(endpoint string) {
	dc.mu.Lock()
	qs, ok := dc.m[endpoint]
	if ok {
		delete(dc.m, endpoint)
	}
	dc.mu.Unlock()
	if !ok {
		return
	}
	qs.dead.Store(true)
	for i := range qs.ss {
		_ = qs.ss[i].s.Close()
	}
	_ = qs.conn.CloseWithError(0, "drop")
}

func (dc *dialCache) close() {
	dc.closing.Store(true)
	dc.mu.Lock()
	pc := dc.pc
	dc.pc = nil
	m := dc.m
	dc.m = make(map[string]*quicState)
	dc.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
	for _, qs := range m {
		qs.dead.Store(true)
		for i := range qs.ss {
			_ = qs.ss[i].s.Close()
		}
		_ = qs.conn.CloseWithError(0, "shutdown")
	}
}

// ============================ TLS/QUIC cfg ============================

func generateServerTLS(alpn string) (*tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "go-l3-overlay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}, nil
}

func quicConfig(idle, keepalive time.Duration) *quic.Config {
	cfg := &quic.Config{
		MaxIdleTimeout:                 idle,
		InitialStreamReceiveWindow:     32 << 20,
		InitialConnectionReceiveWindow: 128 << 20,
	}
	if keepalive > 0 {
		cfg.KeepAlivePeriod = keepalive
	}
	return cfg
}

// ======================== обработка conn (rx→TUN) =====================

func serveQUICConn(conn *quic.Conn, tun *tunDevice, mtu int) {
	remote := conn.RemoteAddr().String()
	slog.Info("serve conn", "remote", remote)
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			if !errors.Is(err, io.EOF) {
				slog.Warn("accept stream", "remote", remote, "err", err)
			}
			return
		}
		go func(s *quic.Stream) {
			defer s.Close()
			buf := make([]byte, mtu)
			for {
				ln, err := readFrame(s, buf)
				if err != nil {
					if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
						slog.Warn("read frame", "remote", remote, "err", err)
					}
					return
				}
				if ln <= 0 {
					continue
				}
				if _, err := tun.Write(buf[:ln]); err != nil {
					slog.Warn("tun write", "err", err)
					return
				}
			}
		}(str)
	}
}

// =============================== main ================================

var cfgPath = flag.String("config", "overlay.toml", "путь к конфигу TOML")

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(0)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("config load", "err", err)
		os.Exit(1)
	}

	// для throughput-замеров держим INFO
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.Log.Level)})
	slog.SetDefault(slog.New(h))
	slog.Info("start",
		"listen", cfg.Transport.Listen, "alpn", cfg.Transport.ALPN, "streams", cfg.Transport.Streams,
		"udp_rbuf", cfg.Transport.UDPRcv, "udp_wbuf", cfg.Transport.UDPSnd,
		"mtu", cfg.Tun.MTU, "batch_bytes", cfg.Batch.Bytes, "batch_flush", cfg.Batch.Flush,
		"tun", cfg.Tun.Name, "insecure", cfg.Transport.Insecure,
	)

	// Пулы
	var batchPool sync.Pool
	batchPool.New = func() any { return make([]byte, 0, cfg.Batch.Bytes) }
	var rbufPool sync.Pool
	rbufPool.New = func() any { return make([]byte, cfg.Tun.MTU) }

	// Маппинг
	pm := newPeerMap()
	if err := pm.loadFromTOML(cfg.Map.Path); err != nil {
		slog.Error("map load", "err", err)
		os.Exit(1)
	}

	// TUN
	tun, err := openTUN(cfg.Tun.Name)
	if err != nil {
		slog.Error("tun open", "err", err)
		os.Exit(1)
	}
	defer tun.Close()
	if err := configureTUN(cfg.Tun.Name, cfg.Tun.Addr, cfg.Tun.LinkMTU, cfg.Tun.AddRoute); err != nil {
		slog.Error("tun configure", "err", err)
		os.Exit(1)
	}
	if err := addGrayRoutes(cfg.Tun.Name, cfg.Tun.GrayRoutes); err != nil {
		slog.Error("routes add", "err", err)
		os.Exit(1)
	}

	// UDP
	laddr, err := net.ResolveUDPAddr("udp", cfg.Transport.Listen)
	if err != nil {
		slog.Error("resolve listen", "err", err)
		os.Exit(1)
	}
	udpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		slog.Error("udp listen", "err", err)
		os.Exit(1)
	}
	defer udpConn.Close()
	_ = udpConn.SetReadBuffer(cfg.Transport.UDPRcv)
	_ = udpConn.SetWriteBuffer(cfg.Transport.UDPSnd)

	// QUIC
	srvTLS, err := generateServerTLS(cfg.Transport.ALPN)
	if err != nil {
		slog.Error("tls", "err", err)
		os.Exit(1)
	}
	qconf := quicConfig(cfg.Transport.Idle, cfg.Transport.KeepAlive)
	listener, err := quic.Listen(udpConn, srvTLS, qconf)
	if err != nil {
		slog.Error("quic listen", "err", err)
		os.Exit(1)
	}
	defer listener.Close()

	dc := newDialCache(cfg.Transport.UDPRcv, cfg.Transport.UDPSnd)
	defer dc.close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = listener.Close(); _ = tun.Close(); dc.close() }()

	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.Warn("accept", "err", err)
				continue
			}
			ep := conn.RemoteAddr().String()
			slog.Info("accept ok", "remote", ep)
			qs := dc.registerIncomingConn(ep, conn, cfg.Transport.Streams)
			qs.once.Do(func() { go serveQUICConn(qs.conn, tun, cfg.Tun.MTU) })
		}
	}()

	for _, ep := range pm.endpoints() {
		ep := ep
		go func() {
			for {
				if ctx.Err() != nil {
					return
				}
				qs, err := dialWithRetry(ctx, dc, ep, cfg.Transport.ALPN, cfg.Transport.Insecure, cfg.Transport.Streams, qconf)
				if err != nil {
					return
				}
				qs.once.Do(func() { go serveQUICConn(qs.conn, tun, cfg.Tun.MTU) })
				select {
				case <-ctx.Done():
					return
				case <-qs.conn.Context().Done():
					slog.Warn("conn closed", "endpoint", ep)
					dc.drop(ep)
					time.Sleep(1 * time.Second)
				}
			}
		}()
	}

	pktCap := clamp((cfg.Batch.Bytes/cfg.Tun.MTU)*4, 64, 4096)
	pktCh := make(chan []byte, pktCap)
	slog.Info("pkt channel", "cap", pktCap)

	flushTicker := time.NewTicker(cfg.Batch.Flush)
	defer flushTicker.Stop()

	// RX TUN → канал
	go func() {
		defer close(pktCh)
		for {
			b := rbufPool.Get().([]byte)
			if cap(b) < cfg.Tun.MTU {
				b = make([]byte, cfg.Tun.MTU)
			}
			n, err := tun.Read(b[:cfg.Tun.MTU])
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, syscall.EINTR) {
					slog.Error("tun read", "err", err)
				}
				return
			}
			pktCh <- b[:n]
		}
	}()

	var cur batchAgg

	// запись батча; при ошибке — мягкий recovery на новом стриме
	writeBatch := func(buf []byte) {
		// попытка записи
		if _, err := cur.st.s.Write(buf); err != nil {
			// если conn жив, пробуем новый стрим и однократный повтор
			if cur.qs != nil && cur.qs.conn.Context().Err() == nil {
				if ns, e2 := cur.qs.conn.OpenStreamSync(context.Background()); e2 == nil {
					cur.st = &streamState{s: ns}
					if _, e3 := cur.st.s.Write(buf); e3 == nil {
						return
					}
				}
			}
			// conn мёртв — дропаем
			slog.Warn("batch send", "endpoint", cur.ep, "err", err)
			dc.drop(cur.ep)
			cur = batchAgg{}
		}
	}

	flushCur := func() {
		if len(cur.b) == 0 || cur.st == nil {
			return
		}
		buf := cur.b
		cur.b = batchPool.Get().([]byte)[:0]
		writeBatch(buf)
		batchPool.Put(buf[:0])
		if cur.qs != nil && cur.st != nil {
			cur.st = cur.qs.pick()
		}
	}

	sendPkt := func(pkt []byte) {
		dst, ok := ipv4Dst(pkt)
		if !ok {
			return
		}
		ep, ok := pm.lookup(dst)
		if !ok {
			return
		}

		if cur.ep != "" && cur.ep != ep {
			flushCur()
			cur = batchAgg{}
		}
		if cur.ep == "" {
			qs, err := dialWithRetry(ctx, dc, ep, cfg.Transport.ALPN, cfg.Transport.Insecure, cfg.Transport.Streams, qconf)
			if err != nil {
				return
			}
			qs.once.Do(func() { go serveQUICConn(qs.conn, tun, cfg.Tun.MTU) })
			cur.ep, cur.qs, cur.st = ep, qs, qs.pick()
			cur.b = batchPool.Get().([]byte)[:0]
		}
		need := 2 + len(pkt)
		if len(cur.b)+need > cfg.Batch.Bytes {
			flushCur()
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(pkt)))
		cur.b = append(cur.b, hdr[:]...)
		cur.b = append(cur.b, pkt...)
		// маленькие кадры — отправлять сразу для снижения задержек и ретраев
		if len(pkt) <= 256 {
			flushCur()
		}
	}

	for {
		select {
		case <-ctx.Done():
			flushCur()
			slog.Info("shutdown by signal")
			return
		case <-flushTicker.C:
			flushCur()
		case pkt, ok := <-pktCh:
			if !ok {
				flushCur()
				slog.Info("shutdown on tun close")
				return
			}
			sendPkt(pkt)
			rbufPool.Put(pkt[:0])
		}
	}
}
