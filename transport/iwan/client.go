package iwan

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrAuthRejected   = errors.New("iwan: authentication rejected by server")
	ErrAddressChanged = errors.New("iwan: server reassigned the tunnel address")
)

type Config struct {
	Username string
	Password string
	MTU      int  // default 1400, 576..1500
	XOR      bool // ask for PA 0x18 obfuscation

	// Tunnova extensions; a PA server ignores the request and the session
	// falls back to plain PA.
	Crypto   bool
	Compress bool
	FEC      int // parity every k packets, 2..16; 0 = off

	Pipe       uint16 // dir<<15 | id; 0 = none
	SRLabels   []uint32
	SRAlgo     int
	SRPassword string

	Timeout time.Duration // no packet from the server for this long → re-OPEN; default 90s
}

// Check fills in defaults and rejects values the protocol can't carry.
func (cfg *Config) Check() error {
	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}
	if cfg.MTU < 576 || cfg.MTU > 1500 {
		return errors.New("iwan: mtu must be 576..1500")
	}
	if cfg.FEC != 0 && (cfg.FEC < 2 || cfg.FEC > 16) {
		return errors.New("iwan: fec must be 2..16")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 90 * time.Second
	}
	if cfg.Timeout < 10*time.Second {
		return errors.New("iwan: timeout must be at least 10s")
	}
	return nil
}

// Session is what OPENACK assigned.
type Session struct {
	IP      netip.Addr
	Gateway netip.Addr
	DNS     []netip.Addr
	MTU     int    // min(local, peer)
	Caps    uint16 // negotiated Tunnova capabilities
	Links   int    // links actually used for sending
	XOR     bool
}

// state is replaced wholesale on every OPENACK so the data path can read it
// without locks. The FEC accumulators hang off it and reset with it.
type state struct {
	id    sessionID
	caps  uint16
	xor   bool
	nuse  int
	salt  [8]byte
	c2s   cipher.AEAD
	s2c   cipher.AEAD
	key8  [8]byte
	fecK  int
	sess  Session
	txMu  sync.Mutex
	fecTx *fecTx
	rxMu  sync.Mutex
	fecRx *fecRx
}

type Client struct {
	cfg   Config
	conns []net.Conn // conns[0] carries control traffic
	csalt [8]byte
	cid   [8]byte
	mycap uint16
	sr    *srState
	epoch time.Time

	st      atomic.Pointer[state]
	up      atomic.Bool
	sticky  atomic.Bool // the server once asked for XOR; keep it for later sessions
	seqTx   atomic.Uint32
	lastRx  atomic.Int64 // unix nanos
	lastOp  atomic.Int64
	lastEch atomic.Int64
	rtt     struct{ cur, min, max atomic.Uint32 } // µs
	stats   struct{ rx, tx, fecRecovered, duplicates, dropped atomic.Uint64 }

	firstUp  chan struct{}
	upOnce   sync.Once
	rejected chan struct{}
	rejOnce  sync.Once
	inbound  chan []byte

	ctx    context.Context
	cancel context.CancelCauseFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// NewClient takes one connected UDP conn per link (multi-port when len > 1).
// It owns the conns from here on.
func NewClient(cfg Config, conns []net.Conn) (*Client, error) {
	if len(conns) == 0 {
		return nil, errors.New("iwan: no link")
	}
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	c := &Client{
		cfg:      cfg,
		conns:    conns,
		epoch:    time.Now(),
		firstUp:  make(chan struct{}),
		rejected: make(chan struct{}),
		inbound:  make(chan []byte, 1024),
	}
	if len(cfg.SRLabels) > 0 {
		c.sr = newSRState(cfg.SRLabels, cfg.SRAlgo, cfg.SRPassword)
	} else {
		c.sr = newSRState(nil, 0, "")
	}
	if cfg.Crypto {
		c.mycap |= CapCrypto
	}
	if cfg.Compress {
		c.mycap |= CapCompress
	}
	if len(conns) > 1 {
		c.mycap |= CapMultiport
	}
	if cfg.FEC > 0 {
		c.mycap |= CapFEC
	}
	_, _ = rand.Read(c.csalt[:])
	_, _ = rand.Read(c.cid[:]) // same id on every re-OPEN: the server sees a reconnect
	c.sticky.Store(cfg.XOR)
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	return c, nil
}

// Handshake starts the link readers and the keepalive loop, then waits for
// the first OPENACK. OPEN is resent every 2 seconds until one arrives.
func (c *Client) Handshake(ctx context.Context) (Session, error) {
	for _, conn := range c.conns {
		c.wg.Add(1)
		go c.readLoop(conn)
	}
	c.wg.Add(1)
	go c.keepalive()
	select {
	case <-c.firstUp:
		return c.st.Load().sess, nil
	case <-c.rejected:
		c.Close()
		return Session{}, ErrAuthRejected
	case <-c.ctx.Done():
		return Session{}, context.Cause(c.ctx)
	case <-ctx.Done():
		c.Close()
		return Session{}, ctx.Err()
	}
}

type Stats struct {
	RxPackets, TxPackets uint64
	FECRecovered         uint64 // packets rebuilt from parity
	Duplicates           uint64 // late originals of rebuilt packets, dropped
	Dropped              uint64 // inbound packets dropped because the reader fell behind
}

func (c *Client) Stats() Stats {
	return Stats{
		RxPackets:    c.stats.rx.Load(),
		TxPackets:    c.stats.tx.Load(),
		FECRecovered: c.stats.fecRecovered.Load(),
		Duplicates:   c.stats.duplicates.Load(),
		Dropped:      c.stats.dropped.Load(),
	}
}

// Done is closed when the client stops; Err says why.
func (c *Client) Done() <-chan struct{} { return c.ctx.Done() }
func (c *Client) Err() error            { return context.Cause(c.ctx) }

func (c *Client) Close() error {
	c.once.Do(func() {
		if c.up.Load() {
			if st := c.st.Load(); st != nil {
				b := make([]byte, hdrLen+sigLen)
				putHdr(b, tClose, 0, st.id)
				sign(b)
				_, _ = c.conns[0].Write(b)
			}
		}
		c.cancel(net.ErrClosed)
		for _, conn := range c.conns {
			_ = conn.Close()
		}
	})
	c.wg.Wait()
	return nil
}

func (c *Client) fail(err error) {
	c.cancel(err)
	for _, conn := range c.conns {
		_ = conn.Close()
	}
}

func (c *Client) now() int64 { return time.Now().UnixNano() }

func (c *Client) keepalive() {
	defer c.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		now := c.now()
		switch {
		case !c.up.Load():
			if now-c.lastOp.Load() >= int64(2*time.Second) {
				c.sendOpen()
			}
		case now-c.lastRx.Load() > int64(c.cfg.Timeout):
			c.up.Store(false)
			c.sendOpen()
		case now-c.lastEch.Load() >= int64(10*time.Second):
			c.sendEcho()
		}
		select {
		case <-t.C:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) sendOpen() {
	b := make([]byte, hdrLen+sigLen, 256)
	putHdr(b, tOpen, 0, sessionID{})
	sign(b)
	pw := passwordBlock(c.cfg.Username, c.cfg.Password)
	b = appendTLV(b, tlvUser, []byte(c.cfg.Username)...)
	b = appendTLV(b, tlvPass, pw[:]...)
	b = appendTLV(b, tlvMTU, byte(c.cfg.MTU>>8), byte(c.cfg.MTU))
	if c.sticky.Load() {
		b = appendTLV(b, tlvEnc, 1)
	}
	if c.cfg.Pipe != 0 {
		b = appendTLV(b, tlvPipeSR, byte(c.cfg.Pipe>>8), byte(c.cfg.Pipe))
	}
	if len(c.cfg.SRLabels) > 0 {
		b = appendTLV(b, tlvPipeSR, binary.BigEndian.AppendUint32(nil, c.cfg.SRLabels[0])...)
	}
	if c.mycap != 0 {
		b = appendTLV(b, tlvCap, byte(c.mycap), byte(c.mycap>>8))
		b = appendTLV(b, tlvSalt, c.csalt[:]...)
		if c.mycap&CapFEC != 0 {
			b = appendTLV(b, tlvFEC, byte(c.cfg.FEC))
		}
	}
	b = appendTLV(b, tlvCID, c.cid[:]...)
	_, _ = c.conns[0].Write(b)
	c.lastOp.Store(c.now())
}

func (c *Client) sendEcho() {
	st := c.st.Load()
	b := make([]byte, hdrLen+sigLen+echoLen)
	putHdr(b, tEchoReq, 0, st.id)
	sign(b)
	// Same layout as the Panabit client: send time (µs, LE u64), then current /
	// min / max RTT (µs, LE u32). The server shows the current RTT as the
	// link's latency.
	e := b[hdrLen+sigLen:]
	binary.LittleEndian.PutUint64(e[0:], c.monoUS())
	binary.LittleEndian.PutUint32(e[8:], c.rtt.cur.Load())
	binary.LittleEndian.PutUint32(e[12:], c.rtt.min.Load())
	binary.LittleEndian.PutUint32(e[16:], c.rtt.max.Load())
	_, _ = c.conns[0].Write(b)
	c.lastEch.Store(c.now())
}

func (c *Client) monoUS() uint64 { return uint64(time.Since(c.epoch).Microseconds()) + 1 }

func (c *Client) readLoop(conn net.Conn) {
	defer c.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if c.ctx.Err() == nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				c.fail(err)
			}
			return
		}
		if n >= hdrLen {
			c.handle(buf[:n])
		}
	}
}

func (c *Client) deliver(ip []byte) {
	if !isIPv4(ip) {
		return
	}
	pkt := append([]byte(nil), ip...)
	select {
	case c.inbound <- pkt:
		c.stats.rx.Add(1)
	default: // reader is behind: drop, as a congested link would
		c.stats.dropped.Add(1)
	}
}

func (c *Client) touch() { c.lastRx.Store(c.now()) }

func (c *Client) handle(b []byte) {
	st := c.st.Load()
	switch b[0] {
	case tOpenAck:
		c.onOpenAck(b)
	case tOpenRej:
		if verify(b) {
			c.up.Store(false)
			c.rejOnce.Do(func() { close(c.rejected) })
		}
	case tEchoResp:
		if st == nil || !hdrMatch(b, st.id) || len(b) < hdrLen+sigLen+echoLen {
			return
		}
		c.touch()
		t := binary.LittleEndian.Uint64(b[hdrLen+sigLen:])
		if d := c.monoUS() - t; t != 0 && d < 60_000_000 {
			c.rtt.cur.Store(uint32(d))
			if m := c.rtt.min.Load(); m == 0 || uint32(d) < m {
				c.rtt.min.Store(uint32(d))
			}
			if uint32(d) > c.rtt.max.Load() {
				c.rtt.max.Store(uint32(d))
			}
		}
	case tClose:
		if st != nil && hdrMatch(b, st.id) && verify(b) {
			c.up.Store(false)
		}
	case tData, tDataEnc:
		if st == nil || !hdrMatch(b, st.id) {
			return
		}
		c.touch()
		body := b[hdrLen:]
		if b[0] == tDataEnc {
			xor8(st.key8, body)
		}
		c.deliver(body)
	case tDataExt:
		if st == nil || !hdrMatch(b, st.id) || len(b) < hdrLen+extLen {
			return
		}
		c.touch()
		ip := b[hdrLen+extLen:]
		if b[hdrLen]&xfCrypto != 0 {
			if st.caps&CapCrypto == 0 || len(b) < hdrLen+extLen+tagLen {
				return
			}
			pt, err := st.s2c.Open(nil, mkIV(st.salt, extSeq(b)), ip, b[:hdrLen+extLen])
			if err != nil {
				return
			}
			ip = pt
		}
		if b[hdrLen]&xfComp != 0 {
			dc := make([]byte, bufSize)
			n := lzDecompress(ip, dc)
			if n < 0 {
				return
			}
			ip = dc[:n]
		}
		if st.fecK > 0 && len(ip) >= 20 {
			st.rxMu.Lock()
			fresh := st.fecRx.data(extSeq(b), ip)
			st.rxMu.Unlock()
			if !fresh {
				c.stats.duplicates.Add(1)
				return
			}
		}
		c.deliver(ip)
	case tFEC:
		if st == nil || !hdrMatch(b, st.id) || st.fecK <= 0 || len(b) < hdrLen+extLen+fecHdrLen {
			return
		}
		c.touch()
		group := binary.BigEndian.Uint32(b[hdrLen+extLen:])
		k := int(b[hdrLen+extLen+4])
		aad := b[:hdrLen+extLen+fecHdrLen]
		xd := b[hdrLen+extLen+fecHdrLen:]
		if b[hdrLen]&xfCrypto != 0 {
			if st.caps&CapCrypto == 0 || len(xd) < tagLen {
				return
			}
			pt, err := st.s2c.Open(nil, mkIV(st.salt, extSeq(b)), xd, aad)
			if err != nil {
				return
			}
			xd = pt
		}
		if k != st.fecK {
			return
		}
		st.rxMu.Lock()
		rec := st.fecRx.parity(group, xd)
		st.rxMu.Unlock()
		if rec != nil {
			c.stats.fecRecovered.Add(1)
			c.deliver(rec)
		}
	case tSegRT, tIPFrag, tIPFrag2:
		// The SR header sits where sid/token would be, so these are matched
		// only by the connected server address.
		if !c.up.Load() || st == nil {
			return
		}
		c.touch()
		var ip []byte
		if b[0] == tSegRT {
			ip = c.sr.segrt(b, st.key8, time.Now())
		} else {
			ip = c.sr.frag(b, nil, time.Now())
		}
		if ip != nil {
			c.deliver(ip)
		}
	}
}

func (c *Client) onOpenAck(p []byte) {
	if !verify(p) {
		return
	}
	var (
		ip, gw  netip.Addr
		dns     []netip.Addr
		peerMTU int
		encReq  bool
		negCaps uint16
		ssalt   []byte
		negFEC  int
		links   int
		id      sessionID
	)
	copy(id[:], p[2:hdrLen])
	for i := hdrLen + sigLen; i+2 <= len(p); {
		t, nn := p[i], int(p[i+1])
		if nn < 2 || i+nn > len(p) {
			break
		}
		v := p[i+2 : i+nn]
		switch {
		case t == tlvMTU && len(v) == 2:
			peerMTU = int(v[0])<<8 | int(v[1])
		case t == tlvIP && len(v) == 4:
			ip = netip.AddrFrom4([4]byte(v))
		case t == tlvGW && len(v) == 4:
			gw = netip.AddrFrom4([4]byte(v))
		case t == tlvDNS && len(v) == 8:
			for _, a := range []netip.Addr{netip.AddrFrom4([4]byte(v[0:4])), netip.AddrFrom4([4]byte(v[4:8]))} {
				if !a.IsUnspecified() {
					dns = append(dns, a)
				}
			}
		case t == tlvEnc && len(v) == 1:
			encReq = v[0] != 0
		case t == tlvCap && len(v) == 2:
			negCaps = uint16(v[0]) | uint16(v[1])<<8
		case t == tlvSalt && len(v) == 8:
			ssalt = v
		case t == tlvFEC && len(v) == 1:
			negFEC = int(v[0])
		case t == tlvLinks && len(v) == 1:
			links = int(v[0])
		}
		i += nn
	}
	if !ip.IsValid() || ip.IsUnspecified() {
		return
	}
	if old := c.st.Load(); old != nil && old.sess.IP != ip {
		// The netstack is bound to the first address; a new one means the
		// whole stack has to be rebuilt by the caller.
		c.fail(ErrAddressChanged)
		return
	}
	if encReq {
		c.sticky.Store(true)
	}
	st := &state{id: id, caps: negCaps, xor: c.sticky.Load(), nuse: len(c.conns)}
	if links > 0 && links < len(c.conns) {
		st.nuse = links
	}
	if st.caps&CapCrypto != 0 {
		if ssalt != nil {
			copy(st.salt[:], ssalt)
			kc2s, ks2c := deriveKeys(c.cfg.Username, c.cfg.Password, c.csalt, st.salt)
			st.c2s, st.s2c = newGCM(kc2s), newGCM(ks2c)
		} else {
			st.caps &^= CapCrypto // asked for crypto without a salt: downgrade
		}
	}
	if st.caps&CapFEC != 0 && negFEC >= 2 && negFEC <= 16 {
		st.fecK = negFEC
		st.fecTx = &fecTx{k: negFEC}
		st.fecRx = &fecRx{k: negFEC}
	} else {
		st.caps &^= CapFEC
	}
	st.key8 = xorKey(c.cfg.Username, c.cfg.Password)
	mtu := c.cfg.MTU
	if peerMTU > 0 && peerMTU < mtu {
		mtu = peerMTU
	}
	st.sess = Session{IP: ip, Gateway: gw, DNS: dns, MTU: mtu, Caps: st.caps, Links: st.nuse, XOR: st.xor}
	if st.caps != 0 {
		c.seqTx.Store(0) // fresh server salt each OPENACK, so restarting seq is safe
	}
	c.st.Store(st)
	c.touch()
	c.up.Store(true)
	c.upOnce.Do(func() { close(c.firstUp) })
}

// ReadIPPacket returns the next IPv4 packet from the server.
func (c *Client) ReadIPPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-c.inbound:
		return p, nil
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// WriteIPPacket sends one IPv4 packet. Packets are dropped while the session
// is re-establishing, like the C client drains its TUN.
func (c *Client) WriteIPPacket(ip []byte) error {
	if err := c.ctx.Err(); err != nil {
		return context.Cause(c.ctx)
	}
	if !isIPv4(ip) || len(ip) > bufSize-hdrLen {
		return nil
	}
	st := c.st.Load()
	if st == nil || !c.up.Load() {
		return nil
	}
	mp := st.caps&CapMultiport != 0 && st.nuse > 1
	ext := st.caps&(CapCrypto|CapCompress) != 0 || mp || st.fecK > 0
	var seq uint32
	if ext {
		seq = c.seqTx.Add(1) - 1
	}
	var ch byte
	conn := c.conns[0]
	if mp {
		ch = byte(flowHash(ip) % uint32(st.nuse))
		conn = c.conns[ch]
	}

	var pkt []byte
	switch {
	case ext:
		payload, flags := ip, byte(0)
		if st.caps&CapCompress != 0 {
			dst := make([]byte, len(ip))
			if n := lzCompress(ip, dst, len(ip)-1); n > 0 {
				payload, flags = dst[:n], xfComp
			}
		}
		head := make([]byte, hdrLen+extLen, hdrLen+extLen+len(payload)+tagLen)
		if st.caps&CapCrypto != 0 {
			putExt(head, tDataExt, flags|xfCrypto, ch, st.id, seq)
			pkt = st.c2s.Seal(head, mkIV(st.salt, seq), payload, head)
		} else {
			putExt(head, tDataExt, flags, ch, st.id, seq)
			pkt = append(head, payload...)
		}
	case st.xor:
		pkt = make([]byte, hdrLen+len(ip))
		putHdr(pkt, tDataEnc, 1, st.id)
		copy(pkt[hdrLen:], ip)
		xor8(st.key8, pkt[hdrLen:])
	default:
		pkt = make([]byte, hdrLen+len(ip))
		putHdr(pkt, tData, 0, st.id)
		copy(pkt[hdrLen:], ip)
	}
	if len(pkt) > bufSize {
		return nil
	}

	// FEC accumulates the plaintext before compression/encryption. A group's
	// parity goes out right after the data packet that completed it.
	var parity []byte
	var group uint32
	var full bool
	if st.fecK > 0 {
		st.txMu.Lock()
		parity, group, full = st.fecTx.add(seq, ip)
		st.txMu.Unlock()
	}
	_, err := conn.Write(pkt)
	c.stats.tx.Add(1)
	if full {
		_, _ = c.conns[0].Write(buildFEC(st, group, parity))
	}
	if err != nil && c.ctx.Err() != nil {
		return context.Cause(c.ctx)
	}
	return nil
}

// buildFEC: extension header (seq = FEC bit | group) + FEC header + XOR data,
// sealed when crypto is on. Parity always rides link 0.
func buildFEC(st *state, group uint32, xd []byte) []byte {
	fseq := fecSeqBit | group
	head := make([]byte, hdrLen+extLen+fecHdrLen, hdrLen+extLen+fecHdrLen+len(xd)+tagLen)
	var flags byte
	if st.caps&CapCrypto != 0 {
		flags = xfCrypto
	}
	putExt(head, tFEC, flags, 0, st.id, fseq)
	binary.BigEndian.PutUint32(head[hdrLen+extLen:], group)
	head[hdrLen+extLen+4] = byte(st.fecK)
	binary.BigEndian.PutUint16(head[hdrLen+extLen+5:], uint16(len(xd)))
	if flags != 0 {
		return st.c2s.Seal(head, mkIV(st.salt, fseq), xd, head)
	}
	return append(head, xd...)
}
