package dpapi

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"unicode/utf16"
)

const (
	CALG_3DES    = 0x6603
	CALG_AES_128 = 0x660e
	CALG_AES_192 = 0x660f
	CALG_AES_256 = 0x6610
	CALG_SHA1    = 0x8004
	CALG_HMAC    = 0x8009
	CALG_SHA_256 = 0x800c
	CALG_SHA_384 = 0x800d
	CALG_SHA_512 = 0x800e
)

func DeriveKeyDPAPI(passphrase, salt []byte, keyLen, count int, newHash func() hash.Hash) []byte {
	var keyMaterial []byte
	i := uint32(1)
	for len(keyMaterial) < keyLen {
		U := make([]byte, len(salt)+4)
		copy(U, salt)
		binary.BigEndian.PutUint32(U[len(salt):], i)
		i++

		h := hmac.New(newHash, passphrase)
		h.Write(U)
		derived := h.Sum(nil)

		for r := 0; r < count-1; r++ {
			h = hmac.New(newHash, passphrase)
			h.Write(derived)
			actual := h.Sum(nil)
			for b := range derived {
				derived[b] ^= actual[b]
			}
		}
		keyMaterial = append(keyMaterial, derived...)
	}
	return keyMaterial[:keyLen]
}

func FormatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func NormalizeGUID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	return strings.ToLower(s)
}

func DecodeUTF16LE(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return strings.TrimRight(string(utf16.Decode(u16)), "\x00")
}
