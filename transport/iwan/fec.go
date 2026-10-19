package iwan

// XOR row FEC: one parity packet per k data packets recovers any single loss
// in the group. It works on plaintext IP packets (a GCM tag can't be XORed).
// Records are [len(BE 2) || ip], XORed into an accumulator with zero padding.

const fecGroups = 4 // receive-side ring of groups

func fecXor(acc []byte, acclen *int, ip []byte) {
	if rec := 2 + len(ip); rec > *acclen {
		*acclen = rec
	}
	acc[0] ^= byte(len(ip) >> 8)
	acc[1] ^= byte(len(ip))
	for i, b := range ip {
		acc[2+i] ^= b
	}
}

type fecTx struct {
	k      int
	group  uint32
	cnt    int
	acclen int
	acc    [bufSize]byte
}

func (f *fecTx) reset() {
	f.cnt, f.acclen = 0, 0
	f.acc = [bufSize]byte{}
}

// add folds a packet into its group. When the group is full it returns the
// parity bytes and group number; a skipped group is abandoned, which only
// lowers coverage.
func (f *fecTx) add(seq uint32, ip []byte) (parity []byte, group uint32, ok bool) {
	g := seq / uint32(f.k)
	if g != f.group {
		f.group = g
		f.reset()
	}
	fecXor(f.acc[:], &f.acclen, ip)
	f.cnt++
	if f.cnt < f.k {
		return nil, 0, false
	}
	parity = append([]byte(nil), f.acc[:f.acclen]...)
	f.group = g + 1
	f.reset()
	return parity, g, true
}

type fecSlot struct {
	group  uint32
	used   bool
	acclen int
	cnt    int
	mask   uint16
	acc    [bufSize]byte
}

type fecRx struct {
	k     int
	slots [fecGroups]fecSlot
}

// slot finds the group's slot, recycling the lowest group when none matches.
func (f *fecRx) slot(g uint32) *fecSlot {
	o := 0
	for i := range f.slots {
		s := &f.slots[i]
		if s.used && s.group == g {
			return s
		}
		if !s.used {
			o = i
		} else if f.slots[o].used && s.group < f.slots[o].group {
			o = i
		}
	}
	s := &f.slots[o]
	*s = fecSlot{used: true, group: g}
	return s
}

// data records a received packet and reports whether it is new. A packet
// whose slot bit is already set was either delivered before or rebuilt from
// parity that overtook it on another link, so the caller drops it. (iwansd's C
// client delivers it a second time; deduping here doesn't touch the wire.)
func (f *fecRx) data(seq uint32, ip []byte) bool {
	g, idx := seq/uint32(f.k), seq%uint32(f.k)
	s := f.slot(g)
	if s.mask&(1<<idx) != 0 {
		return false
	}
	fecXor(s.acc[:], &s.acclen, ip)
	s.mask |= 1 << idx
	s.cnt++
	return true
}

// parity recovers the one missing packet of group g, if exactly one is missing.
func (f *fecRx) parity(g uint32, chk []byte) []byte {
	var s *fecSlot
	for i := range f.slots {
		if f.slots[i].used && f.slots[i].group == g {
			s = &f.slots[i]
		}
	}
	if s == nil || s.cnt != f.k-1 {
		return nil
	}
	mlen := len(chk)
	if s.acclen > mlen {
		mlen = s.acclen
	}
	tmp := make([]byte, mlen)
	for i := range tmp {
		var a, b byte
		if i < len(chk) {
			a = chk[i]
		}
		if i < s.acclen {
			b = s.acc[i]
		}
		tmp[i] = a ^ b
	}
	l := int(tmp[0])<<8 | int(tmp[1])
	if l < 20 || l+2 > mlen {
		return nil
	}
	s.cnt = f.k // complete: never recover the same packet twice
	for i := 0; i < f.k; i++ {
		if s.mask&(1<<i) == 0 {
			s.mask |= 1 << i // the original may still arrive late; see data()
			break
		}
	}
	return tmp[2 : 2+l]
}
