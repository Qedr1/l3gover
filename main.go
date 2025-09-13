// go-l3-overlay: L3 оверлей через TUN и QUIC (UDP)
// Цель: ~1 Гбит/с. Ленивая установка соединений. Разрыв по простою.
// Linux-only. IPv4-only. QUIC всегда с TLS 1.3.

package main

import (
	"bufio"
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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/quic-go/quic-go"
	"github.com/vishvananda/netlink"
)

// ---- Константы и флаги ----

const (
	iffTUN    = 0x0001
	iffNO_PI  = 0x1000
	TUNSETIFF = 0x400454ca
	IFNAMSIZ  = 16
)

var (
	flagTun       = flag.String("tun", "tun0", "имя TUN-интерфейса")
	flagListen    = flag.String("listen", "0.0.0.0:5555", "адрес:порт для входящих QUIC")
	flagMap       = flag.String("map", "peers.map", "путь к файлу соответствий серый_IP=белый_host:порт")
	flagMTU       = flag.Int("mtu", 1500, "MTU для буфера IP-кадра")
	flagALPN      = flag.String("alpn", "go-l3-overlay", "идентификатор протокола QUIC (ALPN)")
	flagInsecure  = flag.Bool("insecure", true, "клиент: не проверять сертификат сервера")
	flagStreams   = flag.Int("streams", 4, "число параллельных QUIC-стримов на peer")
	flagUDPRcv    = flag.Int("udp-rbuf", 16<<20, "сервер: размер UDP RX буфера")
	flagUDPSnd    = flag.Int("udp-wbuf", 16<<20, "сервер: размер UDP TX буфера")
	flagAddr      = flag.String("addr", "", "адрес/префикс на TUN (CIDR)")
	flagLinkMTU   = flag.Int("link-mtu", 0, "установить MTU интерфейса TUN")
	flagAddRoute  = flag.Bool("add-route", true, "добавить маршрут подсети addr через TUN")
	flagIdle      = flag.Duration("idle", 10*time.Minute, "таймаут простоя QUIC")
	flagKeepAlive = flag.Duration("keepalive", 0, "период QUIC keepalive")
)

// ---- Структуры данных ----

type ifreq struct {
	Name  [IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

type tunDevice struct{ fd int }

func (t *tunDevice) Read(p []byte) (int, error)  { return syscall.Read(t.fd, p) }
func (t *tunDevice) Write(p []byte) (int, error) { return syscall.Write(t.fd, p) }
func (t *tunDevice) Close() error                { return syscall.Close(t.fd) }

type peerMap struct {
	mu sync.RWMutex
	m  map[uint32]string
}

type streamState struct {
	s  *quic.Stream
	mu sync.Mutex
}

type quicState struct {
	conn *quic.Conn
	ss   []streamState
	rr   uint64
}

type dialCache struct {
	mu      sync.Mutex
	m       map[string]*quicState
	pc      net.PacketConn
	closing atomic.Bool
}

// ---- Вспомогательные функции ----

func openTUN(name string) (*tunDevice, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTUN | iffNO_PI

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF: %v", errno)
	}
	return &tunDevice{fd: fd}, nil
}

func configureTUN(name, cidr string, linkMTU int, addRoute bool) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}

	if linkMTU > 0 {
		if err := netlink.LinkSetMTU(link, linkMTU); err != nil {
			return fmt.Errorf("set mtu %d: %w", linkMTU, err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}

	if cidr != "" {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("addr parse %q: %w", cidr, err)
		}
		if ip = ip.To4(); ip == nil {
			return fmt.Errorf("IPv4 only: %q", cidr)
		}
		ipnet.IP = ip
		addr := &netlink.Addr{IPNet: ipnet}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("addr set %s: %w", ipnet.String(), err)
		}

		if addRoute {
			rt := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       ipnet,
			}
			if err := netlink.RouteReplace(rt); err != nil {
				return fmt.Errorf("route add %s: %w", ipnet.String(), err)
			}
		}
	}
	return nil
}

func newPeerMap() *peerMap {
	return &peerMap{m: make(map[uint32]string)}
}

func (pm *peerMap) loadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	tmp := make(map[uint32]string)
	scanner := bufio.NewScanner(f)
	line := 0

	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("%s:%d: ожидается '<серый>=<белый>:<порт>'", path, line)
		}

		g := strings.TrimSpace(parts[0])
		w := strings.TrimSpace(parts[1])

		ip := net.ParseIP(g)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("%s:%d: только IPv4: %q", path, line, g)
		}

		if _, _, err := net.SplitHostPort(w); err != nil {
			return fmt.Errorf("%s:%d: host:port: %q (%v)", path, line, w, err)
		}

		key := binary.BigEndian.Uint32(ip.To4())
		tmp[key] = w
	}

	if err := scanner.Err(); err != nil {
		return err
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
	defer pm.mu.RUnlock()
	return pm.m[key], true
}

func writeFrame(dst *quic.Stream, payload []byte) error {
	if len(payload) > 0xFFFF {
		return errors.New("frame too large")
	}

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := (*dst).Write(hdr[:]); err != nil {
		return err
	}
	_, err := (*dst).Write(payload)
	return err
}

func readFrame(src *quic.Stream, buf []byte) (int, error) {
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

func (qs *quicState) pick() *streamState {
	i := atomic.AddUint64(&qs.rr, 1)
	return &qs.ss[i%uint64(len(qs.ss))]
}

func newDialCache() *dialCache {
	return &dialCache{m: make(map[string]*quicState)}
}

func (dc *dialCache) ensureClientPC() error {
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
		_ = uc.SetReadBuffer(16 << 20)
		_ = uc.SetWriteBuffer(16 << 20)
	}
	dc.pc = c
	return nil
}

func (dc *dialCache) getOrDial(ctx context.Context, endpoint, alpn string, insecure bool, streamCount int, qconf *quic.Config) (*quicState, error) {
	dc.mu.Lock()
	if qs, ok := dc.m[endpoint]; ok {
		dc.mu.Unlock()
		return qs, nil
	}
	dc.mu.Unlock()

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

	tlsConf := &tls.Config{
		NextProtos:         []string{alpn},
		InsecureSkipVerify: insecure,
		ServerName:         host,
	}

	raddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, err
	}

	// Используем новый API quic.Dial вместо quic.DialContext :cite[2]:cite[3]
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
	defer dc.mu.Unlock()
	if existing, ok := dc.m[endpoint]; ok {
		_ = conn.CloseWithError(0, "duplicate connection")
		return existing, nil
	}
	dc.m[endpoint] = qs
	return qs, nil
}

func (dc *dialCache) drop(endpoint string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if qs, ok := dc.m[endpoint]; ok {
		for i := range qs.ss {
			_ = (*qs.ss[i].s).Close()
		}
		_ = qs.conn.CloseWithError(0, "drop")
		delete(dc.m, endpoint)
	}
}

func (dc *dialCache) close() {
	dc.closing.Store(true)
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.pc != nil {
		_ = dc.pc.Close()
	}

	for _, qs := range dc.m {
		for i := range qs.ss {
			_ = (*qs.ss[i].s).Close()
		}
		_ = qs.conn.CloseWithError(0, "shutdown")
	}
	dc.m = nil
}

func generateServerTLS(alpn string) (*tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "go-l3-overlay"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func quicConfig(idle, keepalive time.Duration) *quic.Config {
	cfg := &quic.Config{
		MaxIdleTimeout:                 idle,
		InitialStreamReceiveWindow:     8 << 20,
		InitialConnectionReceiveWindow: 32 << 20,
	}
	if keepalive > 0 {
		cfg.KeepAlivePeriod = keepalive
	}
	return cfg
}

func handleQUICConn(conn *quic.Conn, tun *tunDevice, mtu int) {
	remote := conn.RemoteAddr().String()
	log.Printf("входящее QUIC от %s", remote)

	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("stream accept: %v", err)
			}
			_ = conn.CloseWithError(0, "eof")
			return
		}

		go func(s quic.Stream) {
			buf := make([]byte, mtu)
			defer s.Close()

			for {
				ln, err := readFrame(&s, buf)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						log.Printf("in %s: %v", remote, err)
					}
					return
				}
				if ln == 0 {
					continue
				}

				if _, err := tun.Write(buf[:ln]); err != nil {
					log.Printf("tun write: %v", err)
					return
				}
			}
		}(*str)
	}
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	runtime.GOMAXPROCS(0)

	if *flagMTU < 576 || *flagMTU > 65535 {
		log.Fatalf("-mtu вне диапазона: %d", *flagMTU)
	}
	if *flagALPN == "" {
		log.Fatalf("-alpn пуст")
	}
	if *flagStreams < 1 {
		*flagStreams = 1
	}

	pm := newPeerMap()
	if err := pm.loadFromFile(*flagMap); err != nil {
		log.Fatalf("загрузка карты: %v", err)
	}

	tun, err := openTUN(*flagTun)
	if err != nil {
		log.Fatalf("TUN: %v", err)
	}
	defer tun.Close()

	if err := configureTUN(*flagTun, *flagAddr, *flagLinkMTU, *flagAddRoute); err != nil {
		log.Fatalf("настройка TUN: %v", err)
	}

	laddr, err := net.ResolveUDPAddr("udp", *flagListen)
	if err != nil {
		log.Fatalf("resolve %s: %v", *flagListen, err)
	}

	udpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("listen udp %s: %v", *flagListen, err)
	}
	defer udpConn.Close()

	_ = udpConn.SetReadBuffer(*flagUDPRcv)
	_ = udpConn.SetWriteBuffer(*flagUDPSnd)

	srvTLS, err := generateServerTLS(*flagALPN)
	if err != nil {
		log.Fatalf("TLS: %v", err)
	}

	qconf := quicConfig(*flagIdle, *flagKeepAlive)

	// Используем новый API quic.Listen :cite[2]
	listener, err := quic.Listen(udpConn, srvTLS, qconf)
	if err != nil {
		log.Fatalf("quic listen: %v", err)
	}
	defer listener.Close()

	dc := newDialCache()
	defer dc.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		log.Printf("получен сигнал завершения")
		cancel()
	}()

	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("accept: %v", err)
				continue
			}
			go handleQUICConn(conn, tun, *flagMTU)
		}
	}()

	buf := make([]byte, *flagMTU)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := tun.Read(buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			log.Fatalf("tun read: %v", err)
		}

		pkt := buf[:n]
		dst, ok := ipv4Dst(pkt)
		if !ok {
			continue
		}

		endpoint, ok := pm.lookup(dst)
		if !ok {
			continue
		}

		dialCtx, cancelDial := context.WithTimeout(ctx, 5*time.Second)
		qs, err := dc.getOrDial(dialCtx, endpoint, *flagALPN, *flagInsecure, *flagStreams, qconf)
		cancelDial()

		if err != nil {
			log.Printf("dial %s: %v", endpoint, err)
			dc.drop(endpoint)
			continue
		}

		st := qs.pick()
		st.mu.Lock()
		err = writeFrame(st.s, pkt)
		st.mu.Unlock()

		if err != nil {
			log.Printf("send %s: %v (drop)", endpoint, err)
			dc.drop(endpoint)
		}
	}
}
