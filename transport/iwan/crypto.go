package iwan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
)

func md5Of(parts ...[]byte) [16]byte {
	h := md5.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [16]byte
	h.Sum(out[:0])
	return out
}

// passwordBlock is the OPEN password TLV value:
// AES-128-ECB(key = MD5("mw" || user), zero-padded password). Passwords past
// 16 bytes are silently truncated by the protocol.
func passwordBlock(user, pass string) [16]byte {
	key := md5Of([]byte("mw"), []byte(user))
	var pt, ct [16]byte
	copy(pt[:], pass)
	block, _ := aes.NewCipher(key[:])
	block.Encrypt(ct[:], pt[:])
	return ct
}

// xorKey is the PA "encryption" key for 0x18 packets. It is obfuscation only.
func xorKey(user, pass string) [8]byte {
	d := md5Of([]byte(user), []byte(pass))
	var k [8]byte
	copy(k[:], d[:8])
	return k
}

func xor8(k [8]byte, p []byte) {
	for i := range p {
		p[i] ^= k[i&7]
	}
}

// deriveKeys gives one key per direction so the shared salt never repeats a
// (key, IV) pair: base = MD5(user||pass||csalt||ssalt).
func deriveKeys(user, pass string, csalt, ssalt [8]byte) (c2s, s2c [16]byte) {
	base := md5Of([]byte(user), []byte(pass), csalt[:], ssalt[:])
	c2s = md5Of(base[:], []byte("c2s"))
	s2c = md5Of(base[:], []byte("s2c"))
	return
}

func newGCM(key [16]byte) cipher.AEAD {
	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)
	return aead
}

// mkIV is salt(8) || seq(BE 4). Both directions use the server's salt; the
// per-direction keys keep the nonces apart.
func mkIV(salt [8]byte, seq uint32) []byte {
	iv := make([]byte, 12)
	copy(iv, salt[:])
	binary.BigEndian.PutUint32(iv[8:], seq)
	return iv
}
