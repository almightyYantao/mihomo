package iwan

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"sync"
	"time"
)

// Receive-only PA "standard interconnect" downlink: 0x28 SEGRT (SR header,
// optionally AES-128-ECB encrypted) and 0x22/0x24 two-piece IP fragments. The
// client never sends either.

// jhashOld is the pre-2.6.37 Linux jhash (Bob Jenkins lookup2), which the
// vendor client uses to derive the SR key from the labels.
func jhashOld(k []byte, initval uint32) uint32 {
	a, b, c := uint32(0x9e3779b9), uint32(0x9e3779b9), initval
	mix := func() {
		a -= b
		a -= c
		a ^= c >> 13
		b -= c
		b -= a
		b ^= a << 8
		c -= a
		c -= b
		c ^= b >> 13
		a -= b
		a -= c
		a ^= c >> 12
		b -= c
		b -= a
		b ^= a << 16
		c -= a
		c -= b
		c ^= b >> 5
		a -= b
		a -= c
		a ^= c >> 3
		b -= c
		b -= a
		b ^= a << 10
		c -= a
		c -= b
		c ^= b >> 15
	}
	length := uint32(len(k))
	for len(k) >= 12 {
		a += binary.LittleEndian.Uint32(k[0:])
		b += binary.LittleEndian.Uint32(k[4:])
		c += binary.LittleEndian.Uint32(k[8:])
		mix()
		k = k[12:]
	}
	c += length
	switch len(k) {
	case 11:
		c += uint32(k[10]) << 24
		fallthrough
	case 10:
		c += uint32(k[9]) << 16
		fallthrough
	case 9:
		c += uint32(k[8]) << 8
		fallthrough
	case 8:
		b += uint32(k[7]) << 24
		fallthrough
	case 7:
		b += uint32(k[6]) << 16
		fallthrough
	case 6:
		b += uint32(k[5]) << 8
		fallthrough
	case 5:
		b += uint32(k[4])
		fallthrough
	case 4:
		a += uint32(k[3]) << 24
		fallthrough
	case 3:
		a += uint32(k[2]) << 16
		fallthrough
	case 2:
		a += uint32(k[1]) << 8
		fallthrough
	case 1:
		a += uint32(k[0])
	}
	mix()
	return c
}

// srKey is the password followed by h (LE) repeated to 32 bytes, where
// h = jhash(labels BE, in order) + jhash(labels BE, reversed). AES-128 uses the
// first 16 bytes.
func srKey(labels []uint32, pass string) [32]byte {
	var key [32]byte
	n := len(labels)
	fw := make([]byte, 4*n)
	rv := make([]byte, 4*n)
	for i, l := range labels {
		binary.BigEndian.PutUint32(fw[4*i:], l)
		binary.BigEndian.PutUint32(rv[4*(n-1-i):], l)
	}
	var h uint32
	if n > 0 {
		h = jhashOld(fw, 0) + jhashOld(rv, 0)
	}
	if len(pass) > 32 {
		pass = pass[:32]
	}
	l := copy(key[:], pass)
	for l <= 28 {
		binary.LittleEndian.PutUint32(key[l:], h)
		l += 4
	}
	for x := h; l <= 31; x >>= 8 {
		key[l] = byte(x)
		l++
	}
	return key
}

const (
	fragSlots   = 10
	fragTimeout = 10 * time.Second
)

type fragSlot struct {
	id  uint32
	off int
	t   time.Time
	d   []byte
}

type srState struct {
	algo int          // 0 = plain, 1 = AES-128-ECB
	dec  cipher.Block // nil when algo == 0

	mu    sync.Mutex
	slots [fragSlots]fragSlot
}

func newSRState(labels []uint32, algo int, pass string) *srState {
	s := &srState{algo: algo}
	if algo != 0 {
		key := srKey(labels, pass)
		s.dec, _ = aes.NewCipher(key[:16])
	}
	return s
}

func (s *srState) decrypt(p []byte) bool {
	if len(p)%16 != 0 {
		return false
	}
	for i := 0; i < len(p); i += 16 {
		s.dec.Decrypt(p[i:i+16], p[i:i+16])
	}
	return true
}

// frag handles one 0x22/0x24 piece. It returns the reassembled IP packet once
// both pieces are in, nil otherwise. srh is the enclosing SR header (nil for a
// bare fragment); its algo/pad apply to the whole reassembled payload.
func (s *srState) frag(b []byte, srh []byte, now time.Time) []byte {
	if len(b) < 16 {
		return nil
	}
	w := binary.LittleEndian.Uint32(b[12:16])
	flen, foff, eop := int(w>>15&0x7ff), int(w>>2&0x1fff), w&1 == 1
	id := binary.LittleEndian.Uint32(b[8:12]) // opaque, compared as raw bytes
	if id == 0 || len(b) != 16+flen {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.slots {
		sl := &s.slots[i]
		if sl.id != id {
			continue
		}
		sl.id = 0
		if now.Sub(sl.t) >= fragTimeout {
			return nil
		}
		// The end-of-packet piece goes at its own offset and the stored one at
		// 0; otherwise the stored piece is the tail.
		o1, o2 := sl.off, 0
		if eop {
			o1, o2 = 0, foff
		}
		if o1+len(sl.d) > 4096 || o2+flen > 4096 {
			return nil
		}
		out := make([]byte, 4096)
		copy(out[o1:], sl.d)
		copy(out[o2:], b[16:])
		n := flen + len(sl.d)
		out = out[:n]
		if srh != nil && s.algo != 0 {
			pad := int(srh[3] >> 3)
			if int(srh[3]&7) != s.algo || !s.decrypt(out) || pad > n {
				return nil
			}
			out = out[:n-pad]
		}
		return out
	}
	for i := range s.slots {
		sl := &s.slots[i]
		if sl.id != 0 && now.Sub(sl.t) < fragTimeout {
			continue
		}
		*sl = fragSlot{id: id, off: foff, t: now, d: append([]byte(nil), b[16:]...)}
		return nil
	}
	return nil // all slots busy
}

// segrt unwraps a 0x28 packet: SR header (type nextid linkcnt algo|pad<<3,
// then 4*linkcnt label bytes) around an inner DATA packet or fragment. The
// inner packet is decrypted in place.
func (s *srState) segrt(b []byte, key8 [8]byte, now time.Time) []byte {
	if len(b) < 4 {
		return nil
	}
	hl, algo, pad := 4+4*int(b[2]), int(b[3]&7), int(b[3]>>3)
	if hl >= len(b) {
		return nil
	}
	in := b[hl:]
	if in[0] == tIPFrag || in[0] == tIPFrag2 {
		return s.frag(in, b, now)
	}
	if len(in) < hdrLen {
		return nil
	}
	body := in[hdrLen:]
	if s.algo != 0 {
		if algo != s.algo || !s.decrypt(body) || pad > len(body) {
			return nil
		}
		body = body[:len(body)-pad]
	} else if algo != 0 {
		// Encrypted on the wire but no SR key configured: it would only be
		// garbage, so drop it (the vendor client does the same).
		return nil
	}
	if in[0] == tDataEnc {
		xor8(key8, body) // sender XORs first, then AES
	}
	return body
}
