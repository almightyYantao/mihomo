package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/iwan"

	"golang.org/x/sync/semaphore"
)

// Iwan is a layer-3 iWAN (Panabit SD-WAN / Tunnova iwansd) tunnel terminated
// in a userspace IP stack, the same shape as the OpenVPN outbound.
type Iwan struct {
	*Base
	option *IwanOption
	config iwan.Config
	ports  []int // destination port per link

	tunDevice ipStack
	client    *iwan.Client
	resolver  resolver.Resolver
	dns       []dns.NameServer

	runCtx    context.Context
	runCancel context.CancelFunc
	runLock   *semaphore.Weighted
	running   bool
}

type IwanOption struct {
	BasicOption
	Name     string `proxy:"name"`
	Server   string `proxy:"server"`
	Port     int    `proxy:"port"`
	Ports    string `proxy:"ports,omitempty"` // "8000-8099": link i dials port start + i%span
	Username string `proxy:"username"`
	Password string `proxy:"password"`
	MTU      int    `proxy:"mtu,omitempty"`
	XOR      bool   `proxy:"xor,omitempty"`

	Crypto   bool `proxy:"crypto,omitempty"`
	Compress bool `proxy:"compress,omitempty"`
	Links    int  `proxy:"links,omitempty"`
	FEC      int  `proxy:"fec,omitempty"`

	Pipe       string `proxy:"pipe,omitempty"` // "id[:dir]"
	SRLabels   []int  `proxy:"sr-labels,omitempty"`
	SREncrypt  int    `proxy:"sr-encrypt,omitempty"`
	SRPassword string `proxy:"sr-password,omitempty"`

	Timeout          int  `proxy:"timeout,omitempty"`
	HandshakeTimeout int  `proxy:"handshake-timeout,omitempty"`
	UDP              bool `proxy:"udp,omitempty"`

	IPStack IPStackOption `proxy:"ip-stack,omitempty"`

	RemoteDnsResolve bool     `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string `proxy:"dns,omitempty"`
}

func parseIwanPipe(s string) (uint16, error) {
	if s == "" {
		return 0, nil
	}
	idStr, dirStr, hasDir := strings.Cut(s, ":")
	id, err := strconv.Atoi(idStr)
	if err != nil || id < 1 || id > 32767 {
		return 0, fmt.Errorf("iwan pipe id must be 1..32767, got %q", idStr)
	}
	dir := 0
	if hasDir {
		if dir, err = strconv.Atoi(dirStr); err != nil || (dir != 0 && dir != 1) {
			return 0, fmt.Errorf("iwan pipe direction must be 0 or 1, got %q", dirStr)
		}
	}
	return uint16(dir<<15 | id), nil
}

func iwanLinkPorts(port int, portRange string, links int) ([]int, error) {
	lo, hi := port, port
	if portRange != "" {
		a, b, ok := strings.Cut(portRange, "-")
		var err1, err2 error
		lo, err1 = strconv.Atoi(strings.TrimSpace(a))
		hi = lo
		if ok {
			hi, err2 = strconv.Atoi(strings.TrimSpace(b))
		}
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("invalid iwan ports %q", portRange)
		}
	}
	if lo < 1 || hi > 65535 || hi < lo {
		return nil, fmt.Errorf("invalid iwan port range %d-%d", lo, hi)
	}
	span := hi - lo + 1
	ports := make([]int, links)
	for i := range ports {
		ports[i] = lo + i%span
	}
	return ports, nil
}

func NewIwan(option IwanOption) (*Iwan, error) {
	option.IPStack.normalize()
	if err := option.IPStack.validate(); err != nil {
		return nil, err
	}
	if option.Username == "" {
		return nil, errors.New("iwan username is required")
	}
	if option.Links == 0 {
		option.Links = 1
	}
	if option.Links < 1 || option.Links > 100 {
		return nil, errors.New("iwan links must be 1..100")
	}
	if option.HandshakeTimeout < 0 || option.Timeout < 0 {
		return nil, errors.New("iwan timeouts must be non-negative")
	}
	if option.HandshakeTimeout == 0 {
		option.HandshakeTimeout = 10
	}
	ports, err := iwanLinkPorts(option.Port, option.Ports, option.Links)
	if err != nil {
		return nil, err
	}
	pipe, err := parseIwanPipe(option.Pipe)
	if err != nil {
		return nil, err
	}
	if len(option.SRLabels) > 6 {
		return nil, errors.New("iwan sr-labels takes at most 6 labels")
	}
	labels := make([]uint32, len(option.SRLabels))
	for i, l := range option.SRLabels {
		if l <= 0 || int64(l) > 0xffffffff {
			return nil, fmt.Errorf("invalid iwan sr label %d", l)
		}
		labels[i] = uint32(l)
	}
	if option.SREncrypt != 0 && (option.SREncrypt != 1 || len(labels) == 0) {
		return nil, errors.New("iwan sr-encrypt only supports 1 (AES-128) and needs sr-labels")
	}
	if len(option.SRPassword) > 32 {
		return nil, errors.New("iwan sr-password is at most 32 bytes")
	}

	cfg := iwan.Config{
		Username:   option.Username,
		Password:   option.Password,
		MTU:        option.MTU,
		XOR:        option.XOR,
		Crypto:     option.Crypto,
		Compress:   option.Compress,
		FEC:        option.FEC,
		Pipe:       pipe,
		SRLabels:   labels,
		SRAlgo:     option.SREncrypt,
		SRPassword: option.SRPassword,
		Timeout:    time.Duration(option.Timeout) * time.Second,
	}
	// Validate the protocol settings now rather than on the first dial.
	if err := cfg.Check(); err != nil {
		return nil, err
	}

	outbound := &Iwan{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(ports[0])),
			Type:         C.Iwan,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:  &option,
		config:  cfg,
		ports:   ports,
		runLock: semaphore.NewWeighted(1),
	}
	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		nss, err := dns.ParseNameServer(option.Dns)
		if err != nil {
			return nil, err
		}
		outbound.dns = nss
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.runCtx, outbound.runCancel = context.WithCancel(context.Background())
	return outbound, nil
}

func (o *Iwan) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	tunDevice, r, err := o.run(ctx)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	if !metadata.Resolved() || r != nil {
		if r == nil {
			r = resolver.DefaultResolver
		}
		options := o.DialOptions()
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(ipStackNetDialer{stack: tunDevice}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = tunDevice.DialTCP(ctx, "tcp", netip.AddrPort{}, metadata.AddrPort())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, o), nil
}

func (o *Iwan) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	tunDevice, r, err := o.run(ctx)
	if err != nil {
		return nil, err
	}
	if err = o.resolveUDP(ctx, metadata, r); err != nil {
		return nil, err
	}
	pc, err := tunDevice.ListenUDP(ctx, "udp", netip.AddrPort{})
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(pc, o), nil
}

func (o *Iwan) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	_, r, err := o.run(ctx)
	if err != nil {
		return err
	}
	return o.resolveUDP(ctx, metadata, r)
}

func (o *Iwan) resolveUDP(ctx context.Context, metadata *C.Metadata, r resolver.Resolver) error {
	if (!metadata.Resolved() || r != nil) && metadata.Host != "" {
		if r == nil {
			r = resolver.DefaultResolver
		}
		// The tunnel only carries IPv4.
		ip, err := resolveIPWithResolver(ctx, metadata.Host, C.IPv4Only, r)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (o *Iwan) ProxyInfo() C.ProxyInfo {
	info := o.Base.ProxyInfo()
	info.DialerProxy = o.option.DialerProxy
	return info
}

func (o *Iwan) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (o *Iwan) Close() error {
	if o.runCancel != nil {
		o.runCancel()
	}
	_ = o.runLock.Acquire(context.Background(), 1)
	client := o.client
	tunDevice := o.tunDevice
	o.client = nil
	o.tunDevice = nil
	o.running = false
	o.runLock.Release(1)

	if client != nil {
		_ = client.Close()
	}
	if tunDevice != nil {
		return tunDevice.Close()
	}
	return nil
}

func (o *Iwan) run(ctx context.Context) (ipStack, resolver.Resolver, error) {
	runCtx, cancel := context.WithCancel(ctx)
	stop := contextutils.AfterFunc(o.runCtx, cancel)
	defer func() {
		stop()
		cancel()
	}()

	if err := o.runLock.Acquire(runCtx, 1); err != nil {
		return nil, nil, err
	}
	releaseRunLock := true
	defer func() {
		if releaseRunLock {
			o.runLock.Release(1)
		}
	}()

	if o.running {
		if o.tunDevice == nil {
			return nil, nil, net.ErrClosed
		}
		return o.tunDevice, o.resolver, nil
	}
	if o.runCtx.Err() != nil {
		return nil, nil, o.runCtx.Err()
	}

	// The handshake runs detached from the caller so a cancelled dial does not
	// abort a session other dials are about to share.
	type runResult struct {
		tunDevice ipStack
		resolver  resolver.Resolver
		err       error
	}
	releaseRunLock = false
	resultCh := make(chan runResult, 1)
	go func() {
		defer o.runLock.Release(1)
		handshakeCtx, handshakeCancel := context.WithTimeout(o.runCtx, time.Duration(o.option.HandshakeTimeout)*time.Second)
		defer handshakeCancel()
		tunDevice, r, err := o.startLocked(handshakeCtx)
		resultCh <- runResult{tunDevice: tunDevice, resolver: r, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.tunDevice, result.resolver, result.err
	case <-runCtx.Done():
		return nil, nil, runCtx.Err()
	}
}

func (o *Iwan) startLocked(handshakeCtx context.Context) (ipStack, resolver.Resolver, error) {
	conns := make([]net.Conn, 0, len(o.ports))
	for _, port := range o.ports {
		conn, err := o.dialer.DialContext(handshakeCtx, "udp", net.JoinHostPort(o.option.Server, strconv.Itoa(port)))
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, nil, fmt.Errorf("connect iwan server: %w", err)
		}
		conns = append(conns, conn)
	}
	client, err := iwan.NewClient(o.config, conns)
	if err != nil {
		for _, c := range conns {
			_ = c.Close()
		}
		return nil, nil, err
	}
	sess, err := client.Handshake(handshakeCtx)
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("iwan handshake: %w", err)
	}
	log.Infoln("[iWAN](%s) connected: ip=%s gw=%s mtu=%d caps=%#x links=%d xor=%t",
		o.name, sess.IP, sess.Gateway, sess.MTU, sess.Caps, sess.Links, sess.XOR)

	tunDevice, err := newIPStack(o.option.IPStack, []netip.Prefix{netip.PrefixFrom(sess.IP, 32)}, uint32(sess.MTU))
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("create iwan stack device: %w", err)
	}
	if err := tunDevice.Start(); err != nil {
		_ = client.Close()
		_ = tunDevice.Close()
		return nil, nil, err
	}
	o.client = client
	o.tunDevice = tunDevice
	o.running = true
	if o.option.RemoteDnsResolve && o.resolver == nil {
		nss := append([]dns.NameServer(nil), o.dns...)
		if len(nss) == 0 {
			// No dns: given — use the resolvers the server pushed in OPENACK.
			for _, a := range sess.DNS {
				nss = append(nss, dns.NameServer{Net: "udp", Addr: net.JoinHostPort(a.String(), "53")})
			}
		}
		if len(nss) > 0 {
			for i := range nss {
				nss[i].ProxyAdapter = o
			}
			o.resolver = dns.NewResolver(dns.Config{Main: nss})
		}
	}
	o.startPacketLoops()
	return o.tunDevice, o.resolver, nil
}

func (o *Iwan) startPacketLoops() {
	runCtx, runCancel := context.WithCancel(o.runCtx)
	client := o.client
	tunDevice := o.tunDevice
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			runCancel()
			_ = client.Close()
			_ = tunDevice.Close()
			st := client.Stats()
			log.Infoln("[iWAN](%s) session closed: rx=%d tx=%d fec-recovered=%d duplicates=%d dropped=%d",
				o.name, st.RxPackets, st.TxPackets, st.FECRecovered, st.Duplicates, st.Dropped)
			_ = o.runLock.Acquire(context.Background(), 1)
			if o.client == client {
				// Drop the session; the next dial builds a fresh one.
				o.client = nil
				o.tunDevice = nil
				o.running = false
			}
			o.runLock.Release(1)
		})
	}
	go func() {
		defer stop()
		buf := make([]byte, 64*1024)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for runCtx.Err() == nil {
			_, err := tunDevice.Read(bufs, sizes, 0)
			if err != nil {
				if runCtx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
					log.Errorln("[iWAN](%s) error reading from stack device: %v", o.name, err)
				}
				return
			}
			if err := client.WriteIPPacket(buf[:sizes[0]]); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Warnln("[iWAN](%s) link down: %v", o.name, err)
				}
				return
			}
		}
	}()
	go func() {
		defer stop()
		for runCtx.Err() == nil {
			packet, err := client.ReadIPPacket(runCtx)
			if err != nil {
				if runCtx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					log.Warnln("[iWAN](%s) link down: %v", o.name, err)
				}
				return
			}
			if _, err := tunDevice.Write([][]byte{packet}, 0); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Errorln("[iWAN](%s) error writing to stack device: %v", o.name, err)
				}
				return
			}
		}
	}()
}
