package iwan

// LZSS as implemented by iwansd (lz_compress / lz_decompress). A flag byte
// precedes every 8 tokens (bit set = match); a match is 2 bytes BE:
// (offset-1)<<4 | (length-3), offset 1..4096, length 3..18.

// lzCompress returns the compressed length, or 0 when the output would not be
// smaller than the input (or would exceed dcap) so the caller sends the raw
// packet instead.
func lzCompress(s []byte, d []byte, dcap int) int {
	var ht [4096]int
	for i := range ht {
		ht[i] = -1
	}
	n := len(s)
	si, di := 0, 0
	for si < n {
		if di >= dcap {
			return 0
		}
		fp := di
		di++
		var flag byte
		for b := 0; b < 8 && si < n; b++ {
			blen, boff := 0, 0
			if si+4 <= n {
				h := (uint32(s[si])<<16 | uint32(s[si+1])<<8 | uint32(s[si+2])) * 2654435761 >> 20 & 4095
				c := ht[h]
				ht[h] = si
				if c >= 0 && si-c <= 4095 {
					l := 0
					for si+l < n && l < 18 && s[c+l] == s[si+l] {
						l++
					}
					if l >= 3 {
						blen, boff = l, si-c
					}
				}
			}
			if blen >= 3 {
				if di+2 > dcap {
					return 0
				}
				e := (boff-1)<<4 | (blen - 3)
				d[di] = byte(e >> 8)
				d[di+1] = byte(e)
				di += 2
				flag |= 1 << b
				si += blen
			} else {
				if di >= dcap {
					return 0
				}
				d[di] = s[si]
				di++
				si++
			}
		}
		d[fp] = flag
	}
	if di < n {
		return di
	}
	return 0
}

// lzDecompress returns the decompressed length, or -1 on malformed input.
func lzDecompress(s []byte, d []byte) int {
	n, dcap := len(s), len(d)
	si, di := 0, 0
	for si < n {
		flag := s[si]
		si++
		for b := 0; b < 8 && si < n; b++ {
			if flag&(1<<b) != 0 {
				if si+1 >= n {
					return -1
				}
				e := int(s[si])<<8 | int(s[si+1])
				si += 2
				off, l := (e>>4)+1, (e&15)+3
				if off > di || di+l > dcap {
					return -1
				}
				for i := 0; i < l; i++ {
					d[di] = d[di-off]
					di++
				}
			} else {
				if di >= dcap {
					return -1
				}
				d[di] = s[si]
				di++
				si++
			}
		}
	}
	return di
}
