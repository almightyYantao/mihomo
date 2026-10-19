// Package iwan implements the client side of the iWAN (Panabit SD-WAN) UDP
// tunnel, plus the Tunnova extensions negotiated with iwansd (AES-GCM,
// multi-port, FEC, LZSS compression).
//
// The wire format follows iwansd.c (v1.9, mywrt commit a60e62a), not
// PROTOCOL.md: the two disagree on the echo payload, the OPEN TLV order and
// how multi-port links are chosen, and the C code is what servers run.
package iwan

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
)

const (
	tOpenRej  = 0x11
	tOpenAck  = 0x12
	tOpen     = 0x13
	tData     = 0x14
	tEchoReq  = 0x15
	tEchoResp = 0x16
	tClose    = 0x17
	tDataEnc  = 0x18 // XOR-obfuscated data
	tIPFrag   = 0x22
	tIPFrag2  = 0x24
	tSegRT    = 0x28
	tDataExt  = 0x30 // Tunnova: extension header + payload
	tFEC      = 0x31 // Tunnova: FEC parity
)

const (
	hdrLen    = 8
	sigLen    = 16
	extLen    = 6 // flags(1) chan(1) seq(4, LE)
	tagLen    = 16
	fecHdrLen = 7 // group(4, BE) k(1) xdlen(2, BE)
	bufSize   = 2048
	echoLen   = 24
)

// Capability bits negotiated through TLV 20. A PA server never echoes the TLV
// back, so the negotiated set is 0 and the session falls back to plain PA.
const (
	CapMultiport uint16 = 0x01
	CapFEC       uint16 = 0x02
	CapCompress  uint16 = 0x04
	CapCrypto    uint16 = 0x08
)

const (
	tlvUser   = 1
	tlvPass   = 2
	tlvMTU    = 3
	tlvIP     = 4
	tlvDNS    = 5
	tlvGW     = 6
	tlvEnc    = 8
	tlvPipeSR = 10 // pipe (len 4) and SR label (len 6) share the type
	tlvCap    = 20
	tlvSalt   = 22
	tlvFEC    = 23
	tlvCID    = 24
	tlvLinks  = 25
)

const (
	xfComp   = 0x01
	xfCrypto = 0x04

	fecSeqBit = 0x80000000 // parity IVs live in a separate seq space
)

// sessionID is header bytes 2..7 (sid + token). The server hands it out in
// OPENACK and the client echoes it back byte for byte, never interpreting it.
type sessionID [6]byte

func putHdr(p []byte, typ, enc byte, id sessionID) {
	p[0] = typ
	p[1] = enc
	copy(p[2:hdrLen], id[:])
}

func hdrMatch(p []byte, id sessionID) bool {
	return len(p) >= hdrLen && bytes.Equal(p[2:hdrLen], id[:])
}

// sign writes MD5(header || "mw") right after the header. Only control packets
// are signed, and only the header is covered.
func sign(p []byte) {
	h := md5.New()
	h.Write(p[:hdrLen])
	h.Write([]byte("mw"))
	h.Sum(p[hdrLen:hdrLen])
}

func verify(p []byte) bool {
	if len(p) < hdrLen+sigLen {
		return false
	}
	h := md5.New()
	h.Write(p[:hdrLen])
	h.Write([]byte("mw"))
	return bytes.Equal(h.Sum(nil), p[hdrLen:hdrLen+sigLen])
}

func putExt(p []byte, typ, flags, ch byte, id sessionID, seq uint32) {
	putHdr(p, typ, 0, id)
	p[hdrLen] = flags
	p[hdrLen+1] = ch
	binary.LittleEndian.PutUint32(p[hdrLen+2:], seq)
}

func extSeq(p []byte) uint32 { return binary.LittleEndian.Uint32(p[hdrLen+2:]) }

func appendTLV(b []byte, t byte, v ...byte) []byte {
	b = append(b, t, byte(2+len(v)))
	return append(b, v...)
}

// isIPv4 is the last check before a packet reaches the stack, same as the C
// client's guard in front of every TUN write.
func isIPv4(p []byte) bool { return len(p) >= 20 && p[0]>>4 == 4 }

// flowHash is symmetric in src/dst so a connection maps to the same link in
// both directions; ports are mixed in unless the packet is a later fragment.
func flowHash(ip []byte) uint32 {
	a := binary.BigEndian.Uint32(ip[12:16])
	b := binary.BigEndian.Uint32(ip[16:20])
	h := (a^b)*2654435761 ^ uint32(ip[9])
	ihl := int(ip[0]&15) * 4
	if (ip[9] == 6 || ip[9] == 17) && len(ip) >= ihl+4 && ip[6]&0x1f == 0 && ip[7] == 0 {
		sp := uint32(ip[ihl])<<8 | uint32(ip[ihl+1])
		dp := uint32(ip[ihl+2])<<8 | uint32(ip[ihl+3])
		h ^= (sp ^ dp) * 40503
	}
	return (h ^ h>>16) & 1023
}
