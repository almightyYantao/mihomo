package iwan

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// Vectors below are the ones iwansd's own self-test (-T) checks, so a pass
// here means byte-for-byte agreement with the C implementation.

func TestGCMNISTCase4(t *testing.T) {
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	iv, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	pt, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	ct, _ := hex.DecodeString("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
	tag, _ := hex.DecodeString("5bc94fbc3221a5db94fae95ae7121a47")
	var k [16]byte
	copy(k[:], key)
	out := newGCM(k).Seal(nil, iv, pt, aad)
	if !bytes.Equal(out, append(ct, tag...)) {
		t.Fatalf("seal mismatch")
	}
}

func TestPasswordBlock(t *testing.T) {
	// Reference: AES-128-ECB(MD5("mw"||user), zero-padded password).
	user, pass := "alice", "0123456789abcdefTRUNCATED"
	key := md5Of([]byte("mw"), []byte(user))
	block, _ := aes.NewCipher(key[:])
	want := make([]byte, 16)
	block.Encrypt(want, []byte("0123456789abcdef"))
	got := passwordBlock(user, pass)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("password block mismatch")
	}
}

func TestFEC(t *testing.T) {
	pl := []int{20, 35, 28}
	pk := make([][]byte, 3)
	for i := range pk {
		pk[i] = make([]byte, pl[i])
		for j := range pk[i] {
			pk[i][j] = byte(i*50 + j)
		}
	}
	tx := &fecTx{k: 3}
	var chk []byte
	var g uint32
	var full bool
	for i := 0; i < 3; i++ {
		chk, g, full = tx.add(uint32(i), pk[i])
	}
	if !full {
		t.Fatal("group not completed")
	}
	rx := &fecRx{k: 3}
	if !rx.data(1, pk[1]) || !rx.data(2, pk[2]) {
		t.Fatal("fresh packets flagged as duplicates")
	}
	rec := rx.parity(g, chk)
	if !bytes.Equal(rec, pk[0]) {
		t.Fatalf("recovered %x, want %x", rec, pk[0])
	}
	if rx.parity(g, chk) != nil {
		t.Fatal("recovered the same packet twice")
	}
	if rx.data(0, pk[0]) {
		t.Fatal("late original of a recovered packet was not flagged as duplicate")
	}
}

func TestLZ(t *testing.T) {
	raw := make([]byte, 1000)
	for i := range raw {
		raw[i] = "ABCDEFGH"[i&7]
	}
	comp := make([]byte, 1000)
	cn := lzCompress(raw, comp, 1000)
	if cn <= 0 || cn >= 1000 {
		t.Fatalf("compressed size %d", cn)
	}
	dec := make([]byte, 1100)
	if dn := lzDecompress(comp[:cn], dec); dn != 1000 || !bytes.Equal(dec[:dn], raw) {
		t.Fatalf("round trip failed (%d)", dn)
	}

	for i := range raw {
		raw[i] = byte((i*37 + (i >> 2)) & 0xff)
	}
	comp = make([]byte, 1100)
	if cn = lzCompress(raw, comp, 1100); cn > 0 {
		if dn := lzDecompress(comp[:cn], dec); dn != 1000 || !bytes.Equal(dec[:dn], raw) {
			t.Fatal("mixed round trip failed")
		}
	}
}

func TestJhash(t *testing.T) {
	if h := jhashOld([]byte{0, 0, 0, 0x64}, 0); h != 0x32311574 {
		t.Fatalf("jhash = %#x", h)
	}
}

func TestSRKey(t *testing.T) {
	cases := []struct {
		labels []uint32
		pass   string
		key    string
	}{
		{[]uint32{100}, "123456", "313233343536e82a6264e82a6264e82a"},
		{[]uint32{100}, "", "e82a6264e82a6264e82a6264e82a6264"},
		{[]uint32{1, 2, 7}, "SR@Auth789", "5352404175746837383910f972ef10f9"},
		{[]uint32{1}, "0123456789abcdef", hex.EncodeToString([]byte("0123456789abcdef"))},
	}
	for _, c := range cases {
		k := srKey(c.labels, c.pass)
		if got := hex.EncodeToString(k[:16]); got != c.key {
			t.Errorf("srKey(%v,%q) = %s, want %s", c.labels, c.pass, got, c.key)
		}
	}
}

func TestSegRTEncrypted(t *testing.T) {
	ipk := make([]byte, 45)
	for i := range ipk {
		ipk[i] = byte(0x45 + i)
	}
	key8 := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	sr := newSRState([]uint32{100}, 1, "123456")
	key := srKey([]uint32{100}, "123456")
	enc, _ := aes.NewCipher(key[:16])

	pad := 16 - 45%16
	b := []byte{tSegRT, 0, 1, byte(1 | pad<<3)}
	b = binary.BigEndian.AppendUint32(b, 100)
	inner := make([]byte, hdrLen)
	putHdr(inner, tDataEnc, 1, sessionID{})
	body := append(append([]byte(nil), ipk...), make([]byte, pad)...)
	xor8(key8, body[:45])
	for i := 0; i < len(body); i += 16 {
		enc.Encrypt(body[i:i+16], body[i:i+16])
	}
	b = append(append(b, inner...), body...)

	if got := sr.segrt(b, key8, time.Now()); !bytes.Equal(got, ipk) {
		t.Fatalf("segrt = %x", got)
	}
}

func TestFragOutOfOrder(t *testing.T) {
	ipk := make([]byte, 45)
	for i := range ipk {
		ipk[i] = byte(0x45 + i)
	}
	mk := func(w uint32, data []byte) []byte {
		f := make([]byte, 16, 16+len(data))
		putHdr(f, tIPFrag, 0, sessionID{})
		binary.LittleEndian.PutUint32(f[8:], 7)
		binary.LittleEndian.PutUint32(f[12:], w)
		return append(f, data...)
	}
	f1 := mk(0<<2|30<<15, ipk[:30])
	f2 := mk(1|30<<2|15<<15, ipk[30:])
	sr := newSRState(nil, 0, "")
	now := time.Now()
	if got := sr.frag(f2, nil, now); got != nil {
		t.Fatal("completed on first piece")
	}
	if got := sr.frag(f1, nil, now); !bytes.Equal(got, ipk) {
		t.Fatalf("reassembled %x", got)
	}
}

func TestFlowHashSymmetric(t *testing.T) {
	ip := make([]byte, 40)
	ip[0], ip[9] = 0x45, 6
	copy(ip[12:], []byte{10, 0, 0, 1, 8, 8, 8, 8})
	binary.BigEndian.PutUint16(ip[20:], 51000)
	binary.BigEndian.PutUint16(ip[22:], 443)
	rev := append([]byte(nil), ip...)
	copy(rev[12:], []byte{8, 8, 8, 8, 10, 0, 0, 1})
	binary.BigEndian.PutUint16(rev[20:], 443)
	binary.BigEndian.PutUint16(rev[22:], 51000)
	if flowHash(ip) != flowHash(rev) {
		t.Fatal("flow hash not symmetric")
	}
}
