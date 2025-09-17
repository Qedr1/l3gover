//go:build linux

// L3-оверлей через TUN и UDP. IPv4-only. Без шифрования.
// Основной путь: ipv4.PacketConn ReadBatch/WriteBatch.
// Опция: SO_ZEROCOPY (SendmsgN + error-queue).
// TUN в non-blocking + poll() → корректный выход по Ctrl+C.
// Батч: лимит по времени и числу пакетов (~512 KiB / MTU), тёплый старт.

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

//
// ======================= Конфиг и типы =======================
//

// Config — общие настройки сервиса.
// Вход: TOML. Выход: заполненная структура с дефолтами.
type Config struct {
	Tun struct {
		Name       string   `toml:"name"`        // имя TUN
		Addr       string   `toml:"addr"`        // IPv4 CIDR адрес на TUN
		LinkMTU    int      `toml:"link_mtu"`    // MTU интерфейса (>0 применить)
		AddRoute   bool     `toml:"add_route"`   // добавить маршрут своей подсети
		GrayRoutes []string `toml:"gray_routes"` // дополнительные подсети → TUN
		MTU        int      `toml:"mtu"`         // целевой MTU обработки
	} `toml:"tun"`
	Transport struct {
		Listen   string `toml:"listen"`   // UDP ip:port
		UDPRcv   int    `toml:"udp_rbuf"` // размер RX буфера сокета
		UDPSnd   int    `toml:"udp_wbuf"` // размер TX буфера сокета
		ZeroCopy bool   `toml:"zerocopy"` // включить SO_ZEROCOPY
	} `toml:"transport"`
	Map struct {
		Path string `toml:"path"` // путь к мэппингу серый_IP→endpoint
	} `toml:"map"`
	Batch struct {
		Hold   time.Duration `toml:"hold"`   // макс удержание батча
		Warmup time.Duration `toml:"warmup"` // период тёплого старта
	} `toml:"batch"`
	Log struct {
		Level string `toml:"level"` // уровень логов
	} `toml:"log"`
}

// peersTOML — формат TOML-мэппинга: [peers] "серыйIPv4"="белый ip:port".
type peersTOML struct {
	Peers map[string]string `toml:"peers"`
}

// tunDevice — TUN-дескриптор (один писатель внутри процесса).
// Потокобезопасность: запись выполняет одна горутина → без мьютекса.
type tunDevice struct{ fd int }

// peerMap — потокобезопасный серый_IP→endpoint.
// Потокобезопасность: RWMutex защищает карту от гонок.
type peerMap struct {
	mu sync.RWMutex
	m  map[uint32]string // IPv4 (BE u32) → "ip:port"
}

// peerStatus — короткий статус пира по сигналам из error-queue.
type peerStatus struct {
	LastErr string    // текстовый маркер причины
	When    time.Time // момент фиксации
}

// udpState — UDP-сокет и кэш адресов. Поддержка SO_ZEROCOPY.
// Потокобезопасность: адресные карты под RWMutex, TX делает одна горутина.
type udpState struct {
	conn   *net.UDPConn
	pc     *ipv4.PacketConn
	mu     sync.RWMutex
	r4     map[string]*net.UDPAddr        // endpoint → *UDPAddr (fallback)
	rs4    map[string]*unix.SockaddrInet4 // endpoint → *SockaddrInet4 (zerocopy)
	fd     int
	zerocp bool

	// Индекс и статусы для прогрева/диагностики.
	ip2eps map[string][]string   // "A.B.C.D" → список endpoint с таким dst IP
	pstat  map[string]peerStatus // endpoint → статус
}

//
// ======================= Системные константы TUN =======================
//

const (
	iffTUN    = 0x0001
	iffNO_PI  = 0x1000
	TUNSETIFF = 0x400454ca
	IFNAMSIZ  = 16
)

// ifreq — аргумент ioctl(TUNSETIFF).
// Назначение: задать имя/флаги при создании TUN.
type ifreq struct {
	Name  [IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

//
// ============================== Утилиты ===============================
//

// parseLevel — парсинг уровня логов.
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

// loadConfig — загрузка TOML и дефолтизация.
func loadConfig(path string) (Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Tun.Name == "" {
		cfg.Tun.Name = "tun0"
	}
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 9000
	}
	if cfg.Tun.MTU < 576 || cfg.Tun.MTU > 65535 {
		return cfg, errors.New("mtu вне диапазона")
	}
	if cfg.Transport.Listen == "" {
		cfg.Transport.Listen = "0.0.0.0:5555"
	}
	if cfg.Transport.UDPRcv == 0 {
		cfg.Transport.UDPRcv = 33554432
	}
	if cfg.Transport.UDPSnd == 0 {
		cfg.Transport.UDPSnd = 33554432
	}
	if cfg.Map.Path == "" {
		cfg.Map.Path = "conf/peers.toml"
	}
	if cfg.Batch.Hold == 0 {
		cfg.Batch.Hold = 5 * time.Millisecond
	}
	if cfg.Batch.Warmup == 0 {
		cfg.Batch.Warmup = 2 * time.Second
	}
	return cfg, nil
}

// clamp — ограничение значения диапазоном.
func clamp(x, lo, hi int) int {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// rip4 — IPv4 → big-endian u32.
func rip4(ip net.IP) uint32 {
	b := ip.To4()
	if b == nil {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

//
// ============================= TUN I/O ================================
//

// openTUN — открыть /dev/net/tун, привязать имя, включить non-blocking.
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
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return &tunDevice{fd: fd}, nil
}

// ReadNB — неблокирующее чтение IP-пакета из TUN.
func (t *tunDevice) ReadNB(p []byte) (int, error) {
	n, err := syscall.Read(t.fd, p)
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		return 0, nil
	}
	return n, err
}

// Write — запись IP-пакета в TUN.
func (t *tunDevice) Write(p []byte) (int, error) { return syscall.Write(t.fd, p) }

// Close — закрытие TUN.
func (t *tunDevice) Close() error { return syscall.Close(t.fd) }

// configureTUN — поднять линк, адрес/MTU, при необходимости маршрут.
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

// addGrayRoutes — добавить маршруты доп. подсетей в TUN.
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

//
// ======================== Мэппинг адресов ========================
//

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

// lookup — быстрый поиск endpoint по dst IPv4.
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

// endpoints — уникальные endpoints для прогрева.
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

//
// ============================= IPv4 utils ============================
//

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

//
// =============================== UDP ================================
//

// newUDP — создать UDP сокет, включить IP_RECVERR и опционально SO_ZEROCOPY.
func newUDP(listen string, rcv, snd int, zerocopy bool) (*udpState, error) {
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
	pc := ipv4.NewPacketConn(c)

	// сырой fd
	var fd int
	if sc, err := c.SyscallConn(); err == nil {
		_ = sc.Control(func(f uintptr) { fd = int(f) })
	}

	u := &udpState{
		conn: c, pc: pc, fd: fd, zerocp: false,
		r4:     make(map[string]*net.UDPAddr),
		rs4:    make(map[string]*unix.SockaddrInet4),
		ip2eps: make(map[string][]string),
		pstat:  make(map[string]peerStatus),
	}

	// Включаем IP_RECVERR для приёма ICMP ошибок в error-queue.
	if fd > 0 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
			slog.Warn("ip_recverr off", "err", err)
		}
	} else {
		slog.Warn("ip_recverr off", "err", "no fd")
	}

	// SO_ZEROCOPY по запросу.
	if zerocopy && fd > 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1); err == nil {
			u.zerocp = true
			slog.Info("zerocopy on")
		} else {
			slog.Warn("zerocopy off", "err", err)
		}
	} else if zerocopy {
		slog.Warn("zerocopy off", "err", "no fd")
	}

	// Монитор очереди ошибок: ICMP unreachable/route/port → помечаем пиры.
	// Один воркер достаточно, завершится при закрытии fd.
	go drainErrQueueAndMark(context.Background(), u)

	return u, nil
}

// close — корректно закрыть UDP.
func (u *udpState) close() { _ = u.pc.Close(); _ = u.conn.Close() }

// raddr — разрешить endpoint и закешировать адреса.
func (u *udpState) raddr(ep string) (*net.UDPAddr, *unix.SockaddrInet4, error) {
	u.mu.RLock()
	if a, ok := u.r4[ep]; ok {
		if rs, ok2 := u.rs4[ep]; ok2 {
			u.mu.RUnlock()
			return a, rs, nil
		}
		u.mu.RUnlock()
		return a, nil, nil
	}
	u.mu.RUnlock()

	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return nil, nil, err
	}
	rip, err := net.ResolveIPAddr("ip", host)
	if err != nil || rip == nil || rip.IP == nil || rip.IP.To4() == nil {
		return nil, nil, errors.New("resolve: " + ep)
	}
	port, _ := strconv.Atoi(portStr)
	na := &net.UDPAddr{IP: rip.IP, Port: port}
	sa := &unix.SockaddrInet4{Port: port}
	copy(sa.Addr[:], rip.IP.To4())

	u.mu.Lock()
	// прямой кэш
	if old, ok := u.r4[ep]; ok {
		if rs2, ok2 := u.rs4[ep]; ok2 {
			u.mu.Unlock()
			return old, rs2, nil
		}
		u.rs4[ep] = sa
		u.mu.Unlock()
		return old, sa, nil
	}
	u.r4[ep] = na
	u.rs4[ep] = sa
	u.mu.Unlock()
	return na, sa, nil
}

// indexEndpointIP — сохранить соответствие dst IP → endpoint для быстрых пометок.
func (u *udpState) indexEndpointIP(ep, ip string) {
	u.mu.Lock()
	u.ip2eps[ip] = append(u.ip2eps[ip], ep)
	u.mu.Unlock()
}

// GetPeerStatus — отдать статус пира.
func (u *udpState) GetPeerStatus(ep string) (peerStatus, bool) {
	u.mu.RLock()
	ps, ok := u.pstat[ep]
	u.mu.RUnlock()
	return ps, ok
}

// DownPeers — список пиров, помеченных как down за период d.
func (u *udpState) DownPeers(d time.Duration) []string {
	cut := time.Now().Add(-d)
	u.mu.RLock()
	defer u.mu.RUnlock()
	out := make([]string, 0, len(u.pstat))
	for ep, st := range u.pstat {
		if st.When.After(cut) {
			out = append(out, ep)
		}
	}
	return out
}

//
// ======================= MSG_ERRQUEUE монитор =======================
//

// drainErrQueueAndMark — читает error-queue и помечает endpoint'ы по IP источника ошибки.
// Примечание: для ICMP Unreachable адресом from обычно будет удалённый хост или промежуточный роутер.
func drainErrQueueAndMark(ctx context.Context, u *udpState) {
	if u.fd <= 0 {
		return
	}
	oob := make([]byte, 1024)
	dummy := make([]byte, 1)
	pfd := []unix.PollFd{{Fd: int32(u.fd), Events: unix.POLLERR}}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, _ = unix.Poll(pfd, 1000) // мс
		for {
			n, oobn, _, from, err := unix.Recvmsg(u.fd, dummy, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				break
			}
			if err != nil {
				// fd закрыт или другая критика — выходим.
				return
			}
			if n == 0 && oobn == 0 && from == nil {
				break
			}

			// Определяем IP источника ошибки.
			var ipStr string
			switch a := from.(type) {
			case *unix.SockaddrInet4:
				ipStr = net.IP(a.Addr[:]).String()
			default:
				ipStr = ""
			}
			if ipStr == "" {
				continue
			}

			// Помечаем все endpoint'ы с таким dst IP.
			u.mu.Lock()
			eps := u.ip2eps[ipStr]
			now := time.Now()
			for _, ep := range eps {
				u.pstat[ep] = peerStatus{LastErr: "icmp_errqueue", When: now}
				slog.Error("peer down", "endpoint", ep, "ip", ipStr, "reason", "icmp_errqueue")
			}
			u.mu.Unlock()
		}
	}
}

//
// =============================== main ================================
//

// флаг пути к конфигу
var cfgPath = flag.String("config", "overlay.toml", "путь к конфигу TOML")

// main — инициализация и два конвейера: UDP→TUN и TUN→UDP.
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

	// Если link_mtu не задан, применяем mtu как link MTU.
	reqLinkMTU := cfg.Tun.LinkMTU
	if reqLinkMTU == 0 && cfg.Tun.MTU > 0 {
		reqLinkMTU = cfg.Tun.MTU
	}

	linkMTU, err := configureTUN(cfg.Tun.Name, cfg.Tun.Addr, reqLinkMTU, cfg.Tun.AddRoute)
	if err != nil {
		slog.Error("tun configure", "err", err)
		os.Exit(1)
	}
	if err := addGrayRoutes(cfg.Tun.Name, cfg.Tun.GrayRoutes); err != nil {
		slog.Error("routes add", "err", err)
		os.Exit(1)
	}

	// Правило безфрагментационной инкапсуляции (IPv4+UDP = 28 байт):
	const outerOverhead = 28
	maxInner := linkMTU - outerOverhead
	if maxInner < 576 {
		maxInner = 576
	}
	effMTU := cfg.Tun.MTU
	if effMTU > maxInner {
		slog.Warn("eff_mtu clamped by link_mtu-28",
			"requested_mtu", cfg.Tun.MTU, "link_mtu", linkMTU, "outer_overhead", outerOverhead, "new_eff_mtu", maxInner)
		effMTU = maxInner
	}
	if effMTU < 576 {
		effMTU = 576
	}

	udp, err := newUDP(cfg.Transport.Listen, cfg.Transport.UDPRcv, cfg.Transport.UDPSnd, cfg.Transport.ZeroCopy)
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
		"zerocopy", cfg.Transport.ZeroCopy,
		"tun", cfg.Tun.Name,
	)

	// Контекст завершения.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Прогрев: резолв, индексация IP→endpoint и мини-датаграммы для ARP/NAT/кэшей.
	prewarmEndpoints(udp, pm)

	// Цель: крупный батч для снижения системных вызовов.
	const targetBatchBytes = 512 << 10 // 512 KiB
	pktLimit := targetBatchBytes / effMTU
	if pktLimit < 1 {
		pktLimit = 1
	}
	if pktLimit > 512 {
		pktLimit = 512
	}

	//
	// ================= RX: UDP → TUN =================
	//
	go func() {
		N := clamp(pktLimit*2, 128, 1024)
		msgs := make([]ipv4.Message, N)
		bufs := make([][]byte, N)
		for i := 0; i < N; i++ {
			bufs[i] = make([]byte, effMTU)
			msgs[i].Buffers = [][]byte{bufs[i]}
		}
		for {
			_ = udp.pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := udp.pc.ReadBatch(msgs, 0)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
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
					if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
						continue
					}
					if ctx.Err() != nil {
						return
					}
				}
			}
		}
	}()

	//
	// ================= TX: TUN → UDP =================
	//
	{
		N := clamp(pktLimit*2, 128, 1024)

		// Общие буферы пакетов
		bufs := make([][]byte, N)
		for i := 0; i < N; i++ {
			bufs[i] = make([]byte, effMTU)
		}

		// Fallback batched через WriteBatch
		msgs := make([]ipv4.Message, N)
		sendBatchIPv4 := func(k int) {
			if k > 0 {
				_, _ = udp.pc.WriteBatch(msgs[:k], 0)
			}
		}

		warmUntil := time.Now().Add(cfg.Batch.Warmup)
		maxHold := cfg.Batch.Hold
		k := 0
		batchStart := time.Now()

		// poll TUN для неблокирующего чтения
		pfd := []unix.PollFd{{Fd: int32(tun.fd), Events: unix.POLLIN}}

		for {
			_, _ = unix.Poll(pfd, 200) // мс
			if ctx.Err() != nil {
				if k > 0 && !udp.zerocp {
					sendBatchIPv4(k)
				}
				return
			}

			for k < N {
				n, err := tun.ReadNB(bufs[k][:effMTU])
				if err != nil {
					if k > 0 && !udp.zerocp {
						sendBatchIPv4(k)
					}
					return
				}
				if n == 0 {
					break
				}
				if n > effMTU {
					continue
				}
				pkt := bufs[k][:n]

				dst, ok := ipv4Dst(pkt)
				if !ok {
					continue
				}
				ep, ok := pm.lookup(dst)
				if !ok {
					continue
				}
				na, rsa, err := udp.raddr(ep)
				if err != nil {
					continue
				}

				// Отправка
				if udp.zerocp {
					_, _ = unix.SendmsgN(udp.fd, pkt, nil, rsa, unix.MSG_ZEROCOPY)
				} else {
					msgs[k].Buffers = [][]byte{pkt}
					msgs[k].Addr = na
				}
				k++

				// Тёплый старт: флашим чаще; иначе — по размерам/таймеру.
				if time.Now().Before(warmUntil) || k >= pktLimit || time.Since(batchStart) > maxHold {
					break
				}
			}

			if k > 0 && !udp.zerocp {
				sendBatchIPv4(k)
			}
			k = 0
			batchStart = time.Now()
		}
	}
}

//
// ============================ Вспомогательные =========================
//

// prewarmEndpoints — быстрый прогрев пиров (адресация/ARP/NAT) и построение индекса IP→endpoint.
// Во время прогрева error-queue помечает недоступные пиры.
func prewarmEndpoints(udp *udpState, pm *peerMap) {
	eps := pm.endpoints()
	if len(eps) == 0 {
		return
	}
	const shots = 4
	msgs := make([]ipv4.Message, 0, len(eps)*shots)
	for _, ep := range eps {
		na, _, err := udp.raddr(ep)
		if err != nil {
			continue
		}
		// Индексация dst IP → endpoint для последующей корреляции в error-queue.
		udp.indexEndpointIP(ep, na.IP.String())

		for i := 0; i < shots; i++ {
			msgs = append(msgs, ipv4.Message{
				Buffers: [][]byte{{0}},
				Addr:    na,
			})
		}
	}
	for off := 0; off < len(msgs); {
		n, _ := udp.pc.WriteBatch(msgs[off:], 0)
		if n <= 0 {
			break
		}
		off += n
	}

	// Можно вывести краткий отчёт по down-пирам за окно прогрева.
	down := udp.DownPeers(30 * time.Second)
	if len(down) > 0 {
		slog.Warn("prewarm: peers unreachable", "count", len(down), "peers", strings.Join(down, ","))
	}
}
