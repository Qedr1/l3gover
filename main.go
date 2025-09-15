//go:build linux

// L3-оверлей через TUN и UDP. IPv4-only. Без шифрования.
// Батчи через ipv4.PacketConn ReadBatch/WriteBatch.
// Батч ограничен таймером и целевым числом пакетов (≈128 KiB / MTU).
// Эффективный MTU = min(cfg.Tun.MTU, link MTU интерфейса).
// Корректный выход по Ctrl+C: TUN в non-blocking + poll(), UDP с короткими ReadDeadline.

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/BurntSushi/toml"
	netlink "github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// ======================= конфиг и типы =======================

type Config struct { // настройки сервиса
	Tun struct {
		Name       string   `toml:"name"`        // имя интерфейса
		Addr       string   `toml:"addr"`        // IPv4 CIDR для TUN
		LinkMTU    int      `toml:"link_mtu"`    // MTU интерфейса (>0 применить)
		AddRoute   bool     `toml:"add_route"`   // добавить маршрут подсети Addr
		GrayRoutes []string `toml:"gray_routes"` // доп. подсети → TUN
		MTU        int      `toml:"mtu"`         // целевой MTU TUN I/O
	} `toml:"tun"`
	Transport struct {
		Listen string `toml:"listen"`   // UDP адрес ip:port
		UDPRcv int    `toml:"udp_rbuf"` // RX буфер сокета
		UDPSnd int    `toml:"udp_wbuf"` // TX буфер сокета
	} `toml:"transport"`
	Map struct {
		Path string `toml:"path"` // путь к TOML мэппингу
	} `toml:"map"`
	Batch struct {
		Hold   time.Duration `toml:"hold"`   // макс. удержание батча
		Warmup time.Duration `toml:"warmup"` // тёплый старт: флаш каждого пакета
	} `toml:"batch"`
	Log struct {
		Level string `toml:"level"` // debug|info|warn|error
	} `toml:"log"`
}

type peersTOML struct {
	Peers map[string]string `toml:"peers"`
} // "серый IPv4" = "белый host:port"

type tunDevice struct { // один писатель в процессе
	fd int
}

type peerMap struct { // IPv4(BE u32)→"ip:port"
	mu sync.RWMutex
	m  map[uint32]string
}

type udpState struct { // UDP сокет + PacketConn + кэш адресов
	conn *net.UDPConn
	pc   *ipv4.PacketConn
	mu   sync.RWMutex
	r4   map[string]*net.UDPAddr
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
	if cfg.Transport.UDPRcv == 0 {
		cfg.Transport.UDPRcv = 32 << 20
	}
	if cfg.Transport.UDPSnd == 0 {
		cfg.Transport.UDPSnd = 32 << 20
	}
	if cfg.Map.Path == "" {
		cfg.Map.Path = "peers.toml"
	}
	if cfg.Batch.Hold == 0 {
		cfg.Batch.Hold = 200 * time.Microsecond
	}
	if cfg.Batch.Warmup == 0 {
		cfg.Batch.Warmup = 2 * time.Second
	}
	return cfg, nil
}

func rip4(ip net.IP) uint32 {
	b := ip.To4()
	if b == nil {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// ============================= TUN I/O ================================

func openTUN(name string) (*tunDevice, error) { // открыть TUN и сделать non-blocking
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
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return &tunDevice{fd: fd}, nil
}

func (t *tunDevice) ReadNB(p []byte) (int, error) { // неблокирующее чтение
	n, err := syscall.Read(t.fd, p)
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		return 0, nil
	}
	return n, err
}

func (t *tunDevice) Write(p []byte) (int, error) { return syscall.Write(t.fd, p) }
func (t *tunDevice) Close() error                { return syscall.Close(t.fd) }

func configureTUN(name, cidr string, linkMTU int, addRoute bool) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, errors.New("link not found: " + err.Error())
	}
	if linkMTU > 0 {
		if err := netlink.LinkSetMTU(link, linkMTU); err != nil {
			return 0, errors.New("set mtu: " + err.Error())
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return 0, errors.New("link up: " + err.Error())
	}
	if cidr != "" {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return 0, errors.New("addr parse: " + err.Error())
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return 0, errors.New("IPv4 only")
		}
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip4, Mask: ipnet.Mask}}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return 0, errors.New("addr set: " + err.Error())
		}
		if addRoute {
			dst := &net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: ipnet.Mask}
			rt := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
			if err := netlink.RouteReplace(rt); err != nil {
				return 0, errors.New("route add: " + err.Error())
			}
		}
	}
	link, _ = netlink.LinkByName(name)
	return link.Attrs().MTU, nil
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
		host, port, err := net.SplitHostPort(strings.TrimSpace(white))
		if err != nil {
			return errors.New("map: host:port invalid for " + gray)
		}
		rip, err := net.ResolveIPAddr("ip", host)
		if err != nil || rip == nil || rip.IP == nil || rip.IP.To4() == nil {
			return errors.New("map: host invalid for " + gray)
		}
		tmp[rip4(ip)] = net.JoinHostPort(rip.IP.String(), port)
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
	key := uint32(dstIPv4[0])<<24 | uint32(dstIPv4[1])<<16 | uint32(dstIPv4[2])<<8 | uint32(dstIPv4[3])
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

// ============================= IPv4 utils ============================

func ipv4Dst(pkt []byte) ([]byte, bool) {
	if len(pkt) < 20 {
		return nil, false
	}
	if pkt[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, false
	}
	return pkt[16:20], true
}

// =============================== UDP ================================

func newUDP(listen string, rcv, snd int) (*udpState, error) {
	laddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	_ = c.SetReadBuffer(rcv)
	_ = c.SetWriteBuffer(snd)
	return &udpState{conn: c, pc: ipv4.NewPacketConn(c), r4: make(map[string]*net.UDPAddr)}, nil
}

func (u *udpState) close() { _ = u.pc.Close(); _ = u.conn.Close() }

func (u *udpState) raddr(ep string) (*net.UDPAddr, error) {
	u.mu.RLock()
	if a, ok := u.r4[ep]; ok {
		u.mu.RUnlock()
		return a, nil
	}
	u.mu.RUnlock()
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return nil, err
	}
	rip, err := net.ResolveIPAddr("ip", host)
	if err != nil || rip == nil || rip.IP == nil || rip.IP.To4() == nil {
		return nil, errors.New("resolve: " + ep)
	}
	port, _ := strconv.Atoi(portStr)
	addr := &net.UDPAddr{IP: rip.IP, Port: port}
	u.mu.Lock()
	if old, ok := u.r4[ep]; ok {
		u.mu.Unlock()
		return old, nil
	}
	u.r4[ep] = addr
	u.mu.Unlock()
	return addr, nil
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
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.Log.Level)})
	slog.SetDefault(slog.New(h))

	pm := newPeerMap()
	if err := pm.loadFromTOML(cfg.Map.Path); err != nil {
		slog.Error("map load", "err", err)
		os.Exit(1)
	}

	tun, err := openTUN(cfg.Tun.Name)
	if err != nil {
		slog.Error("tun open", "err", err)
		os.Exit(1)
	}
	defer tun.Close()
	linkMTU, err := configureTUN(cfg.Tun.Name, cfg.Tun.Addr, cfg.Tun.LinkMTU, cfg.Tun.AddRoute)
	if err != nil {
		slog.Error("tun configure", "err", err)
		os.Exit(1)
	}
	if err := addGrayRoutes(cfg.Tun.Name, cfg.Tun.GrayRoutes); err != nil {
		slog.Error("routes add", "err", err)
		os.Exit(1)
	}

	effMTU := cfg.Tun.MTU
	if linkMTU > 0 && linkMTU < effMTU {
		effMTU = linkMTU
	}
	if effMTU < 576 {
		effMTU = 576
	}

	udp, err := newUDP(cfg.Transport.Listen, cfg.Transport.UDPRcv, cfg.Transport.UDPSnd)
	if err != nil {
		slog.Error("udp listen", "err", err)
		os.Exit(1)
	}
	defer udp.close()

	slog.Info("start",
		"listen", cfg.Transport.Listen,
		"udp_rbuf", cfg.Transport.UDPRcv, "udp_wbuf", cfg.Transport.UDPSnd,
		"cfg_mtu", cfg.Tun.MTU, "link_mtu", linkMTU, "eff_mtu", effMTU,
		"hold", cfg.Batch.Hold, "warmup", cfg.Batch.Warmup,
		"tun", cfg.Tun.Name,
	)

	// Завершение по сигналу
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Прогрев: предразрешение адресов и мини-датаграммы
	prewarmEndpoints(udp, pm)

	// Лимиты батча
	const targetBatchBytes = 128 << 10
	pktLimit := targetBatchBytes / effMTU
	if pktLimit < 1 {
		pktLimit = 1
	}
	if pktLimit > 256 {
		pktLimit = 256
	}

	// ================= RX: UDP → TUN =================
	go func() {
		N := clamp(pktLimit*2, 64, 512)
		msgs := make([]ipv4.Message, N)
		bufs := make([][]byte, N)
		for i := 0; i < N; i++ {
			bufs[i] = make([]byte, effMTU)
			msgs[i].Buffers = [][]byte{bufs[i]}
		}

		for {
			_ = udp.pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) // короткий таймаут
			n, err := udp.pc.ReadBatch(msgs, 0)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				time.Sleep(200 * time.Microsecond)
				continue
			}
			for i := 0; i < n; i++ {
				ln := msgs[i].N
				if ln <= 0 || ln > effMTU {
					continue
				}
				if _, err := tun.Write(bufs[i][:ln]); err != nil {
					if ctx.Err() != nil {
						return
					}
				}
			}
		}
	}()

	// ================= TX: TUN → UDP =================
	{
		N := clamp(pktLimit*2, 64, 512)
		msgs := make([]ipv4.Message, N)
		bufs := make([][]byte, N)
		for i := 0; i < N; i++ {
			bufs[i] = make([]byte, effMTU)
		}

		flush := func(k int) {
			if k > 0 {
				_, _ = udp.pc.WriteBatch(msgs[:k], 0)
			}
		}

		warmUntil := time.Now().Add(cfg.Batch.Warmup)
		maxHold := cfg.Batch.Hold
		k := 0
		batchStart := time.Now()

		pfd := []unix.PollFd{{Fd: int32(tun.fd), Events: unix.POLLIN}}
		for {
			// ожидаем данные на TUN с таймаутом, чтобы проверять ctx
			_, _ = unix.Poll(pfd, 200) // мс
			if ctx.Err() != nil {
				flush(k)
				return
			}

			for k < N {
				n, err := tun.ReadNB(bufs[k][:effMTU])
				if err != nil {
					flush(k)
					return
				}
				if n == 0 { // нет данных сейчас
					break
				}
				if n > effMTU {
					continue
				}
				dst, ok := ipv4Dst(bufs[k][:n])
				if !ok {
					continue
				}
				ep, ok := pm.lookup(dst)
				if !ok {
					continue
				}
				addr, err := udp.raddr(ep)
				if err != nil {
					continue
				}

				msgs[k].Buffers = [][]byte{bufs[k][:n]}
				msgs[k].Addr = addr
				k++

				if time.Now().Before(warmUntil) || k >= pktLimit || time.Since(batchStart) > maxHold {
					break
				}
			}
			flush(k)
			k = 0
			batchStart = time.Now()
		}
	}
}

// ============================ вспомогательные =========================

func clamp(x, lo, hi int) int {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func prewarmEndpoints(udp *udpState, pm *peerMap) {
	eps := pm.endpoints()
	if len(eps) == 0 {
		return
	}
	const shots = 4
	msgs := make([]ipv4.Message, 0, len(eps)*shots)
	for _, ep := range eps {
		addr, err := udp.raddr(ep)
		if err != nil {
			continue
		}
		for i := 0; i < shots; i++ {
			msgs = append(msgs, ipv4.Message{Buffers: [][]byte{{0}}, Addr: addr})
		}
	}
	for off := 0; off < len(msgs); {
		n, _ := udp.pc.WriteBatch(msgs[off:], 0)
		if n <= 0 {
			break
		}
		off += n
	}
}
