//go:build linux

// L3-оверлей через TUN и UDP. IPv4-only. Без шифрования.
//
// Производительность:
// - TUN с IFF_VNET_HDR + TUNSETOFFLOAD (CSUM/TSO4/TSO6). Мы читаем/пишем virtio-net hdr.
// - RX: ipv4.PacketConn.ReadBatch → запись в TUN (с vnet hdr), дедлайны от batch.hold.
// - TX: чтение из TUN (vnet hdr) → UDP: копирующий батч WriteBatch или zerocopy SendmsgN.
// - UDP_SEGMENT: ВКЛЮЧАЕТСЯ ТОЛЬКО ЕСЛИ Transport.udpgso_mss>0 И aggregate_inner=true.
//   Иначе не используем (иначе сломает семантику «1 inner → 1 outer UDP»).
//
// Внешние offload’ы: после запуска пробуем `ethtool -K tunX gro/gso/tso on`. Ошибки не критичны.
//
// Логи недоступности пира: warmup и tx, с троттлингом 5с/peer.

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/exec"
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
	netlink "github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

//
// ======================= Конфиг и типы =======================
//

// Config — конфигурация сервиса.
// Вход: TOML. Выход: валидированная структура с дефолтами.
type Config struct {
	Tun struct {
		Name       string   `toml:"name"`         // имя TUN; "" → "tun0"
		Addr       string   `toml:"addr"`         // IPv4 CIDR для TUN, напр. "10.10.0.1/24"
		LinkMTU    int      `toml:"link_mtu"`     // MTU интерфейса; 0 → не менять (или взять из mtu)
		AddRoute   bool     `toml:"add_route"`    // добавить маршрут своей подсети на TUN
		GrayRoutes []string `toml:"gray_routes"`  // доп. IPv4 CIDR, направлять в TUN
		MTU        int      `toml:"mtu"`          // целевой MTU inner; 0 → 9000
		VNetHdr    bool     `toml:"vnet_hdr"`     // включить IFF_VNET_HDR (virtio-net header) для offload’ов TUN
		Offloads   bool     `toml:"tun_offloads"` // выставить TUNSETOFFLOAD: CSUM/TSO4/TSO6
	} `toml:"tun"`
	Transport struct {
		Listen       string `toml:"listen"`          // UDP bind "ip:port"; "" → "0.0.0.0:5555"
		UDPRcv       int    `toml:"udp_rbuf"`        // RX-буфер сокета; 0 → 32MiB
		UDPSnd       int    `toml:"udp_wbuf"`        // TX-буфер сокета; 0 → 32MiB
		ZeroCopy     bool   `toml:"zerocopy"`        // SO_ZEROCOPY
		ZCMinBytes   int    `toml:"zc_min_bytes"`    // порог для zerocopy; 0 → 8192
		UDPGSOMSS    int    `toml:"udpgso_mss"`      // MSS для UDP_SEGMENT; 0 → выкл (без агрегации использовать нельзя)
		AggregateInn bool   `toml:"aggregate_inner"` // агрегировать несколько inner в один outer UDP (эксперимент, по умолчанию false)
	} `toml:"transport"`
	Map struct {
		Path string `toml:"path"` // путь к мэппингу серый_IP → "белый ip:port"; "" → "conf/peers.toml"
	} `toml:"map"`
	Batch struct {
		Hold   time.Duration `toml:"hold"`   // макс удержание TX-батча и шаг опроса; 0 → 5ms
		Warmup time.Duration `toml:"warmup"` // длительность прогрева; 0 → 2s
	} `toml:"batch"`
	Log struct {
		Level string `toml:"level"` // уровень логов: debug|info|warn|error; "" → info
	} `toml:"log"`
}

// peersTOML — формат TOML файла мэппинга пиров.
type peersTOML struct {
	Peers map[string]string `toml:"peers"`
}

// virtioNetHdr — заголовок virtio-net для vnet_hdr (минимальный).
// Используем «без mergeable buffers»; num_buffers=0.
type virtioNetHdr struct {
	Flags     uint8  // VIRTIO_NET_HDR_F_*
	GSOType   uint8  // VIRTIO_NET_HDR_GSO_*
	HdrLen    uint16 // длина L2/L3/L4 hdr (для GSO)
	GSOSize   uint16 // размер MSS для GSO
	CSumStart uint16 // смещение начала псевдозаголовка
	CSumOff   uint16 // смещение чек-суммы
}

// virtio-net константы (минимальный набор).
const (
	VIRTIO_NET_HDR_F_NEEDS_CSUM = 1
	VIRTIO_NET_HDR_GSO_TCPV4    = 1
	VIRTIO_NET_HDR_GSO_TCPV6    = 4
)

// tunDevice — дескриптор TUN + режим vnet_hdr.
// Потокобезопасность: запись делает одна горутина.
type tunDevice struct {
	fd         int
	vnet       bool // если true — ожидаем/пишем virtio-net hdr
	vnetHdrLen int  // длина virtio hdr (мы используем 10 байт, выровняем до 12)
}

// peerMap — неизменяемая карта серый_IP→endpoint под atomic.Value.
type peerMap struct {
	v atomic.Value // map[uint32]string
}

// udpState — UDP-сокет и кэш адресов.
type udpState struct {
	conn   *net.UDPConn
	pc     *ipv4.PacketConn
	fd     int
	zerocp bool
	zcMin  int

	udpgsoMSS int  // MSS для UDP_SEGMENT (если >0)
	aggInner  bool // агрегировать inner (в противном случае UDP_SEGMENT не используется)

	mu  sync.RWMutex
	r4  map[string]*net.UDPAddr
	rs4 map[string]*unix.SockaddrInet4

	lastLog     map[string]time.Time
	logCool     time.Duration
	warmupUntil time.Time
}

//
// ============================== Утилиты ===============================
//

// parseLevel — строка уровня → slog.Level.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// loadConfig — загрузка TOML и дефолты.
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
		return cfg, errors.New("mtu вне диапазона 576..65535")
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
	if cfg.Transport.ZCMinBytes <= 0 {
		cfg.Transport.ZCMinBytes = 8192
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

// clamp — ограничение x в [lo,hi].
func clamp(x, lo, hi int) int {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// rip4 — IPv4 → BE u32 ключ.
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

// ioctl константы для TUN (отсутствующие в x/sys).
const (
	// базовые
	iffTUN    = 0x0001
	iffNO_PI  = 0x1000
	iffVNET   = 0x4000 // IFF_VNET_HDR
	IFNAMSIZ  = 16
	TUNSETIFF = 0x400454ca

	// offload
	TUNSETOFFLOAD = 0x400454d0

	// флаги TUNSETOFFLOAD
	TUN_F_CSUM    = 0x01
	TUN_F_TSO4    = 0x02
	TUN_F_TSO6    = 0x04
	TUN_F_TSO_ECN = 0x08
)

// ifreq — аргумент ioctl(TUNSETIFF).
type ifreq struct {
	Name  [IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

// openTUN — открыть /dev/net/tun, создать TUN, включить non-blocking и vnet_hdr.
// Вход: name, vnetHdr(bool), setOffloads(bool). Выход: *tunDevice.
func openTUN(name string, vnetHdr, setOffloads bool) (*tunDevice, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("open /dev/net/tun: " + err.Error())
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTUN | iffNO_PI
	if vnetHdr {
		req.Flags |= iffVNET
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, errors.New("ioctl TUNSETIFF")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}

	td := &tunDevice{fd: fd, vnet: vnetHdr, vnetHdrLen: 10}
	// выровняем до 12 байт (общая практика для совместимости)
	if td.vnetHdrLen%2 != 0 {
		td.vnetHdrLen++
	}
	if setOffloads && vnetHdr {
		// запросить offload’ы: CSUM + TSO4 + TSO6
		flags := TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN
		_, _, e2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETOFFLOAD), uintptr(unsafe.Pointer(&flags)))
		if e2 != 0 {
			slog.Warn("TUNSETOFFLOAD failed", "errno", e2)
		} else {
			slog.Info("TUNSETOFFLOAD on", "flags", flags)
		}
	}
	return td, nil
}

// ReadNB — неблокирующее чтение кадра из TUN.
// Возвращает длину полезной L3-части; если vnet_hdr включён — пропускаем virtio hdr.
func (t *tunDevice) ReadNB(p []byte) (int, error) {
	n, err := syscall.Read(t.fd, p)
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		return 0, nil
	}
	if err != nil {
		return n, err
	}
	if !t.vnet {
		return n, nil
	}
	if n < t.vnetHdrLen {
		return 0, nil
	}
	// пропускаем virtio hdr
	copy(p, p[t.vnetHdrLen:n])
	return n - t.vnetHdrLen, nil
}

// WriteL3 — запись L3-пакета в TUN.
// Если vnet_hdr включён — предваряем virtio hdr нулями.
func (t *tunDevice) WriteL3(pkt []byte) (int, error) {
	if !t.vnet {
		return syscall.Write(t.fd, pkt)
	}
	// формируем [virtio_hdr | pkt] без аллокаций: используем временный стековый буфер для hdr
	var hdr [12]byte
	// все поля 0 → без GSO/CSUM подсказок для ядра (минимальная совместимость)
	// пишем сразу два iov: hdr и pkt.
	iov := []syscall.Iovec{
		{Base: &hdr[0], Len: uint64(t.vnetHdrLen)},
		{Base: &pkt[0], Len: uint64(len(pkt))},
	}
	n, _, errno := syscall.Syscall(syscall.SYS_WRITEV, uintptr(t.fd), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)))
	if errno != 0 {
		return int(n), errno
	}
	// возвращаем длину L3 части
	return int(n) - t.vnetHdrLen, nil
}

// Close — закрытие TUN.
func (t *tunDevice) Close() error { return syscall.Close(t.fd) }

// configureTUN — поднять интерфейс, адрес/MTU, при необходимости маршрут.
// Выход: фактический MTU линка.
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

// newPeerMap — пустая атомарная карта.
func newPeerMap() *peerMap {
	pm := &peerMap{}
	pm.v.Store(make(map[uint32]string))
	return pm
}

// loadFromTOML — загрузить мэппинг и атомарно заменить карту.
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
	pm.v.Store(tmp)
	return nil
}

// lookup — быстрый поиск endpoint по dst IPv4 без блокировок.
func (pm *peerMap) lookup(dstIPv4 []byte) (string, bool) {
	if len(dstIPv4) != 4 {
		return "", false
	}
	key := uint32(dstIPv4[0])<<24 | uint32(dstIPv4[1])<<16 | uint32(dstIPv4[2])<<8 | uint32(dstIPv4[3])
	m := pm.v.Load().(map[uint32]string)
	ep, ok := m[key]
	return ep, ok
}

// endpoints — уникальные endpoints для прогрева.
func (pm *peerMap) endpoints() []string {
	m := pm.v.Load().(map[uint32]string)
	seen := make(map[string]struct{}, len(m))
	out := make([]string, 0, len(m))
	for _, ep := range m {
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

// ipv4Dst — извлечь dst IPv4 из заголовка IPv4-пакета.
func ipv4Dst(pkt []byte) ([]byte, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
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

// newUDP — создать UDP-сокет, включить опции, подготовить cmsg/zerocopy.
func newUDP(listen string, rcv, snd int, zerocopy bool, zcMin, udpgsoMSS int, aggregate bool) (*udpState, error) {
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
		conn:      c,
		pc:        pc,
		fd:        fd,
		zerocp:    false,
		zcMin:     zcMin,
		udpgsoMSS: udpgsoMSS,
		aggInner:  aggregate,
		r4:        make(map[string]*net.UDPAddr),
		rs4:       make(map[string]*unix.SockaddrInet4),
		lastLog:   make(map[string]time.Time),
		logCool:   5 * time.Second,
	}

	// IP_RECVERR для логов ICMP.
	if fd > 0 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
			slog.Warn("IP_RECVERR off", "err", err)
		}
	} else {
		slog.Warn("IP_RECVERR off", "err", "no fd")
	}

	// SO_ZEROCOPY.
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
	return u, nil
}

// close — закрыть UDP.
func (u *udpState) close() { _ = u.pc.Close(); _ = u.conn.Close() }

// raddr — разрешить endpoint и закешировать sockaddr.
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
	u.r4[ep] = na
	u.rs4[ep] = sa
	u.mu.Unlock()
	return na, sa, nil
}

// setWarmupUntil — установить дедлайн прогрева.
func (u *udpState) setWarmupUntil(t time.Time) {
	u.mu.Lock()
	u.warmupUntil = t
	u.mu.Unlock()
}

// phase — текущая фаза: warmup/tx.
func (u *udpState) phase() string {
	u.mu.RLock()
	t := u.warmupUntil
	u.mu.RUnlock()
	if time.Now().Before(t) {
		return "warmup"
	}
	return "tx"
}

// notePeerUnavailable — троттлинг сообщений об ошибках доставки.
func (u *udpState) notePeerUnavailable(ep, phase, reason string, err error) {
	now := time.Now()
	u.mu.Lock()
	last := u.lastLog[ep]
	if now.Sub(last) < u.logCool {
		u.mu.Unlock()
		return
	}
	u.lastLog[ep] = now
	u.mu.Unlock()
	slog.Error("peer unavailable", "peer", ep, "phase", phase, "reason", reason, "err", err)
}

// isTempSendErr — временные ошибки TX.
func isTempSendErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.ENOBUFS) {
		return true
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return true
		}
		return isTempSendErr(ne.Err)
	}
	return false
}

// startErrMonitor — дренаж error-queue для логов ICMP.
func (u *udpState) startErrMonitor(ctx context.Context, tick time.Duration) {
	if u.fd <= 0 {
		return
	}
	if tick <= 0 {
		tick = 10 * time.Millisecond
	}
	if tick > 200*time.Millisecond {
		tick = 200 * time.Millisecond
	}
	go func() {
		oob := make([]byte, 512)
		buf := make([]byte, 512)
		pfd := []unix.PollFd{{Fd: int32(u.fd), Events: unix.POLLERR}}
		timeoutMS := int(tick / time.Millisecond)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, _ = unix.Poll(pfd, timeoutMS)
			for {
				n, oobn, _, _, err := unix.Recvmsg(u.fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					break
				}
				if err != nil {
					return
				}
				_ = oobn
				if ep, ok := parseUDPEndpointFromICMPPayload(buf[:n]); ok {
					u.notePeerUnavailable(ep, u.phase(), "icmp_unreachable", nil)
				}
			}
		}
	}()
}

// parseUDPEndpointFromICMPPayload — извлечь "dstIP:dstPort" из вложенного IPv4+UDP.
func parseUDPEndpointFromICMPPayload(buf []byte) (string, bool) {
	if len(buf) < 28 || buf[0]>>4 != 4 {
		return "", false
	}
	ihl := int(buf[0]&0x0F) * 4
	if ihl < 20 || len(buf) < ihl+4 {
		return "", false
	}
	dstIP := net.IPv4(buf[16], buf[17], buf[18], buf[19]).String()
	udpOff := ihl
	if len(buf) < udpOff+4 {
		return "", false
	}
	dstPort := int(binary.BigEndian.Uint16(buf[udpOff+2 : udpOff+4]))
	return net.JoinHostPort(dstIP, strconv.Itoa(dstPort)), true
}

//
// =============================== UDP_SEGMENT ==========================
//

// buildUDPSegmentCMSG — построить cmsg UDP_SEGMENT на MSS байт.
// Используется ТОЛЬКО при агрегации нескольких inner в один UDP.
func buildUDPSegmentCMSG(mss uint16) []byte {
	// struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; ... }
	// За cmsghdr следует u16 gso_size (native-endian), затем padding.
	hlen := unix.CmsgSpace(2) // 2 байта данных
	buf := make([]byte, hlen)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	data := buf[unix.CmsgLen(0):unix.CmsgLen(2)]
	// native endian; Linux на x86 — LE.
	binary.LittleEndian.PutUint16(data[:2], mss)
	return buf
}

//
// =============================== main ================================
//

var cfgPath = flag.String("config", "overlay.toml", "путь к конфигу TOML")

// main — инициализация, прогрев, запуск конвейеров.
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

	// Открываем TUN c IFF_VNET_HDR и включаем TUNSETOFFLOAD при запросе.
	tun, err := openTUN(cfg.Tun.Name, cfg.Tun.VNetHdr, cfg.Tun.Offloads)
	if err != nil {
		slog.Error("tun open", "err", err)
		os.Exit(1)
	}
	defer tun.Close()

	// Контекст завершения.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Настраиваем линк/адрес/маршруты.
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

	// Внешние offload’ы для tunX: best-effort системные команды.
	applyTunOffloadSys(cfg.Tun.Name)

	// Эффективный MTU inner = min(cfg.MTU, link_mtu-28), clamp [576..].
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
	// Понизим link MTU до effMTU (исключить несогласованность).
	if linkMTU > effMTU {
		if link, err := netlink.LinkByName(cfg.Tun.Name); err == nil {
			if err := netlink.LinkSetMTU(link, effMTU); err != nil {
				slog.Warn("lower link_mtu failed", "want", effMTU, "err", err)
			} else {
				slog.Info("lower link_mtu to eff_mtu", "old", linkMTU, "new", effMTU)
				linkMTU = effMTU
			}
		}
	}

	udp, err := newUDP(cfg.Transport.Listen, cfg.Transport.UDPRcv, cfg.Transport.UDPSnd,
		cfg.Transport.ZeroCopy, cfg.Transport.ZCMinBytes, cfg.Transport.UDPGSOMSS, cfg.Transport.AggregateInn)
	if err != nil {
		slog.Error("udp listen", "err", err)
		os.Exit(1)
	}
	defer udp.close()
	udp.setWarmupUntil(time.Now().Add(cfg.Batch.Warmup))

	// Период опроса error-queue = min(hold, 20ms).
	errqTick := cfg.Batch.Hold
	if errqTick <= 0 || errqTick > 20*time.Millisecond {
		errqTick = 20 * time.Millisecond
	}
	udp.startErrMonitor(ctx, errqTick)

	slog.Info("start",
		"listen", cfg.Transport.Listen,
		"udp_rbuf", cfg.Transport.UDPRcv, "udp_wbuf", cfg.Transport.UDPSnd,
		"cfg_mtu", cfg.Tun.MTU, "link_mtu", linkMTU, "eff_mtu", effMTU,
		"hold", cfg.Batch.Hold, "warmup", cfg.Batch.Warmup,
		"zerocopy", cfg.Transport.ZeroCopy, "zc_min_bytes", cfg.Transport.ZCMinBytes,
		"udpgso_mss", cfg.Transport.UDPGSOMSS, "aggregate_inner", cfg.Transport.AggregateInn,
		"vnet_hdr", cfg.Tun.VNetHdr, "tun_offloads", cfg.Tun.Offloads,
		"tun", cfg.Tun.Name,
	)

	// Прогрев пиров.
	prewarmEndpoints(udp, pm)

	// Размер батча.
	const targetBatchBytes = 512 << 10 // 512 KiB
	pktLimit := clamp(targetBatchBytes/effMTU, 1, 512)

	// RX: UDP → TUN (пишем vnet_hdr при необходимости).
	go rxLoop(ctx, udp, tun, effMTU, pktLimit, cfg.Batch.Hold)

	// TX: TUN → UDP (читаем vnet_hdr, отправляем UDP).
	txLoop(ctx, udp, pm, tun, linkMTU, effMTU, pktLimit, cfg.Batch.Hold, cfg.Batch.Warmup)
}

//
// ============================ Конвейеры ===============================
//

// rxLoop — приём UDP батчами и запись в TUN (включая virtio hdr при необходимости).
func rxLoop(ctx context.Context, udp *udpState, tun *tunDevice, effMTU, pktLimit int, hold time.Duration) {
	N := clamp(pktLimit*2, 128, 1024)
	msgs := make([]ipv4.Message, N)
	bufs := make([][]byte, N)
	for i := 0; i < N; i++ {
		bufs[i] = make([]byte, effMTU)
		msgs[i].Buffers = [][]byte{bufs[i]}
	}
	if hold <= 0 {
		hold = 5 * time.Millisecond
	}
	for {
		_ = udp.pc.SetReadDeadline(time.Now().Add(hold))
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
			// запишем L3 в TUN (функция сама добавит vnet_hdr при его включении)
			if _, err := tun.WriteL3(bufs[i][:ln]); err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					continue
				}
				if ctx.Err() != nil {
					return
				}
			}
		}
	}
}

// txLoop — чтение из TUN и отправка UDP.
// Если zerocopy=true и размер ≥ порога — SendmsgN(MSG_ZEROCOPY).
// Копирующий путь — батч через WriteBatch без аллокаций на горячем пути.
// UDP_SEGMENT включается ТОЛЬКО при aggregate_inner=true и udpgso_mss>0.
func txLoop(ctx context.Context, udp *udpState, pm *peerMap, tun *tunDevice, linkMTU, effMTU, pktLimit int, maxHold, warm time.Duration) {
	N := clamp(pktLimit*2, 128, 1024)

	// Буферы чтения из TUN: N штук по linkMTU (+ место под vnet hdr в ReadNB не требуется — он срезается).
	readBufs := make([][]byte, N)
	for i := 0; i < N; i++ {
		readBufs[i] = make([]byte, linkMTU)
	}

	// Копирующий путь: заранее 1 слот в Buffers.
	msgs := make([]ipv4.Message, N)
	for i := 0; i < N; i++ {
		msgs[i].Buffers = make([][]byte, 1)
	}

	warmUntil := time.Now().Add(warm)
	k := 0
	batchStart := time.Now()

	if maxHold <= 0 {
		maxHold = 5 * time.Millisecond
	}
	timeoutMS := clamp(int(maxHold/time.Millisecond), 1, 200)
	pfd := []unix.PollFd{{Fd: int32(tun.fd), Events: unix.POLLIN}}

	flushCopy := func() {
		if k > 0 {
			_, _ = udp.pc.WriteBatch(msgs[:k], 0)
			k = 0
			batchStart = time.Now()
		}
	}

	for {
		_, _ = unix.Poll(pfd, timeoutMS)
		if ctx.Err() != nil {
			flushCopy()
			return
		}

		for k < N {
			// чтение из TUN (внутри ReadNB virtio hdr уже срезан при vnet_hdr=true)
			n, err := tun.ReadNB(readBufs[k][:linkMTU])
			if err != nil {
				flushCopy()
				return
			}
			if n == 0 {
				break
			}
			if n > effMTU {
				slog.Warn("drop oversized inner packet", "len", n, "eff_mtu", effMTU, "link_mtu", linkMTU)
				continue
			}
			pkt := readBufs[k][:n]

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
				udp.notePeerUnavailable(ep, udp.phase(), "resolve_error", err)
				continue
			}

			// Zerocopy или копирующий путь.
			useZC := udp.zerocp && len(pkt) >= udp.zcMin

			// UDP_SEGMENT: используем ТОЛЬКО при агрегации нескольких inner в один outer.
			var oob []byte
			if udp.aggInner && udp.udpgsoMSS > 0 && len(pkt) > udp.udpgsoMSS {
				oob = buildUDPSegmentCMSG(uint16(udp.udpgsoMSS))
			}

			if useZC {
				_, err := unix.SendmsgN(udp.fd, pkt, oob, rsa, unix.MSG_ZEROCOPY)
				if err != nil {
					if isTempSendErr(err) {
						_, _ = udp.conn.WriteToUDP(pkt, na)
					} else {
						udp.notePeerUnavailable(ep, udp.phase(), "send_error", err)
					}
				}
				continue
			}

			// копирующий путь (батч)
			msgs[k].Buffers[0] = pkt
			msgs[k].Addr = na
			k++

			if time.Now().Before(warmUntil) || k >= pktLimit || time.Since(batchStart) > maxHold {
				break
			}
		}

		flushCopy()
	}
}

//
// ============================ Вспомогательные =========================
//

// prewarmEndpoints — прогрев пиров + явная проверка недоступности.
func prewarmEndpoints(udp *udpState, pm *peerMap) {
	eps := pm.endpoints()
	if len(eps) == 0 {
		return
	}
	const shots = 2
	msgs := make([]ipv4.Message, 0, len(eps)*shots)

	for _, ep := range eps {
		na, _, err := udp.raddr(ep)
		if err != nil {
			udp.notePeerUnavailable(ep, "warmup", "resolve_error", err)
			continue
		}
		// пассивный прогрев (ARP/NAT/cache)
		for i := 0; i < shots; i++ {
			msgs = append(msgs, ipv4.Message{Buffers: [][]byte{{0}}, Addr: na})
		}
		// активная проверка ICMP Port Unreachable
		func() {
			c, err := net.DialUDP("udp", nil, na)
			if err != nil {
				udp.notePeerUnavailable(ep, "warmup", "dial_error", err)
				return
			}
			defer c.Close()
			_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			if _, werr := c.Write([]byte{0}); werr != nil {
				udp.notePeerUnavailable(ep, "warmup", "send_error", werr)
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			var b [1]byte
			if _, rerr := c.Read(b[:]); isConnRefused(rerr) {
				udp.notePeerUnavailable(ep, "warmup", "icmp_port_unreachable", rerr)
			}
		}()
	}
	for off := 0; off < len(msgs); {
		n, _ := udp.pc.WriteBatch(msgs[off:], 0)
		if n <= 0 {
			break
		}
		off += n
	}
}

// isConnRefused — true, если ошибка соответствует ECONNREFUSED.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	var se syscall.Errno
	if errors.As(err, &se) && se == syscall.ECONNREFUSED {
		return true
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		return isConnRefused(ne.Err)
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// applyTunOffloadSys — best-effort включение gro/gso/tso на tunX через ethtool.
// Выполняется после поднятия интерфейса. Ошибки некритичны.
func applyTunOffloadSys(tunName string) {
	// ethtool -K tunX gro on gso on tso on
	cmd := exec.Command("ethtool", "-K", tunName, "gro", "on", "gso", "on", "tso", "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("ethtool tun offload", "err", err, "out", string(out))
	}
}
