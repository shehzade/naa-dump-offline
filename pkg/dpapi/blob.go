package dpapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

type DPAPIBlob struct {
	Version          uint32
	GuidCredential   string
	MasterKeyVersion uint32
	GuidMasterKey    string
	Flags            uint32
	Description      string
	CryptAlgo        uint32
	CryptAlgoLen     uint32
	Salt             []byte
	HMacKey          []byte
	HashAlgo         uint32
	HashAlgoLen      uint32
	HMac             []byte
	Data             []byte
	Sign             []byte
	RawData          []byte
}

func ParseDPAPIBlob(raw []byte) (*DPAPIBlob, error) {
	if len(raw) < 44 {
		return nil, fmt.Errorf("DPAPI blob too short (%d bytes)", len(raw))
	}

	blob := &DPAPIBlob{
		RawData:          raw,
		Version:          binary.LittleEndian.Uint32(raw[0:4]),
		GuidCredential:   FormatGUID(raw[4:20]),
		MasterKeyVersion: binary.LittleEndian.Uint32(raw[20:24]),
		GuidMasterKey:    FormatGUID(raw[24:40]),
		Flags:            binary.LittleEndian.Uint32(raw[40:44]),
	}

	offset := 44
	if offset+4 > len(raw) {
		return nil, fmt.Errorf("invalid blob at description len")
	}
	descLen := binary.LittleEndian.Uint32(raw[offset : offset+4])
	offset += 4
	if offset+int(descLen) > len(raw) {
		return nil, fmt.Errorf("invalid blob description length")
	}
	blob.Description = DecodeUTF16LE(raw[offset : offset+int(descLen)])
	offset += int(descLen)

	if offset+8 > len(raw) {
		return nil, fmt.Errorf("invalid blob at CryptAlgo")
	}
	blob.CryptAlgo = binary.LittleEndian.Uint32(raw[offset : offset+4])
	blob.CryptAlgoLen = binary.LittleEndian.Uint32(raw[offset+4 : offset+8])
	offset += 8

	if offset+4 > len(raw) {
		return nil, fmt.Errorf("invalid blob at SaltLen")
	}
	saltLen := binary.LittleEndian.Uint32(raw[offset : offset+4])
	offset += 4
	if offset+int(saltLen) > len(raw) {
		return nil, fmt.Errorf("invalid blob salt length")
	}
	blob.Salt = raw[offset : offset+int(saltLen)]
	offset += int(saltLen)

	if offset+4 > len(raw) {
		return nil, fmt.Errorf("invalid blob at HMacKeyLen")
	}
	hmacKeyLen := binary.LittleEndian.Uint32(raw[offset : offset+4])
	offset += 4
	if offset+int(hmacKeyLen) > len(raw) {
		return nil, fmt.Errorf("invalid blob hmac key length")
	}
	blob.HMacKey = raw[offset : offset+int(hmacKeyLen)]
	offset += int(hmacKeyLen)

	if offset+8 > len(raw) {
		return nil, fmt.Errorf("invalid blob at HashAlgo")
	}
	blob.HashAlgo = binary.LittleEndian.Uint32(raw[offset : offset+4])
	blob.HashAlgoLen = binary.LittleEndian.Uint32(raw[offset+4 : offset+8])
	offset += 8

	if offset+4 > len(raw) {
		return nil, fmt.Errorf("invalid blob at HMacLen")
	}
	hmacLen := binary.LittleEndian.Uint32(raw[offset : offset+4])
	offset += 4
	if offset+int(hmacLen) > len(raw) {
		return nil, fmt.Errorf("invalid blob hmac length")
	}
	blob.HMac = raw[offset : offset+int(hmacLen)]
	offset += int(hmacLen)

	if offset+4 > len(raw) {
		return nil, fmt.Errorf("invalid blob at DataLen")
	}
	dataLen := binary.LittleEndian.Uint32(raw[offset : offset+4])
	offset += 4
	if offset+int(dataLen) > len(raw) {
		return nil, fmt.Errorf("invalid blob data length")
	}
	blob.Data = raw[offset : offset+int(dataLen)]
	offset += int(dataLen)

	if offset+4 <= len(raw) {
		signLen := binary.LittleEndian.Uint32(raw[offset : offset+4])
		offset += 4
		if offset+int(signLen) <= len(raw) {
			blob.Sign = raw[offset : offset+int(signLen)]
		}
	}

	return blob, nil
}

func (blob *DPAPIBlob) Decrypt(masterKey []byte) ([]byte, error) {
	h := sha1.New()
	h.Write(masterKey)
	keyHash := h.Sum(nil)

	var hashFunc func() hash.Hash
	var hashBlockSize int
	switch blob.HashAlgo {
	case CALG_SHA1, CALG_HMAC:
		hashFunc = sha1.New
		hashBlockSize = 64
	case CALG_SHA_512:
		hashFunc = sha512.New
		hashBlockSize = 128
	default:
		return nil, fmt.Errorf("unsupported blob hash algo: 0x%x", blob.HashAlgo)
	}

	var cryptKeyLen, ivLen int
	switch blob.CryptAlgo {
	case CALG_AES_256:
		cryptKeyLen = 32
		ivLen = 16
	case CALG_AES_128:
		cryptKeyLen = 16
		ivLen = 16
	case CALG_3DES:
		cryptKeyLen = 24
		ivLen = 8
	default:
		return nil, fmt.Errorf("unsupported blob crypt algo: 0x%x", blob.CryptAlgo)
	}

	h2 := hmac.New(hashFunc, keyHash)
	h2.Write(blob.Salt)
	sessionKey := h2.Sum(nil)

	derivedKey := sessionKey
	if len(derivedKey) > hashBlockSize {
		h3 := hmac.New(hashFunc, sessionKey)
		derivedKey = h3.Sum(nil)
	}

	if len(derivedKey) < cryptKeyLen {
		padLen := hashBlockSize
		padded := make([]byte, len(derivedKey)+padLen)
		copy(padded, derivedKey)
		ipad := make([]byte, padLen)
		opad := make([]byte, padLen)
		for i := 0; i < padLen; i++ {
			ipad[i] = padded[i] ^ 0x36
			opad[i] = padded[i] ^ 0x5c
		}

		hi := hashFunc()
		hi.Write(ipad)
		ho := hashFunc()
		ho.Write(opad)

		derivedKey = append(hi.Sum(nil), ho.Sum(nil)...)
	}

	cryptKey := derivedKey[:cryptKeyLen]
	iv := make([]byte, ivLen)

	var cleartext []byte
	switch blob.CryptAlgo {
	case CALG_AES_256, CALG_AES_128:
		block, err := aes.NewCipher(cryptKey)
		if err != nil {
			return nil, err
		}
		if len(blob.Data)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("ciphertext length not multiple of AES block size")
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		cleartext = make([]byte, len(blob.Data))
		mode.CryptBlocks(cleartext, blob.Data)
	case CALG_3DES:
		block, err := des.NewTripleDESCipher(cryptKey)
		if err != nil {
			return nil, err
		}
		if len(blob.Data)%des.BlockSize != 0 {
			return nil, fmt.Errorf("ciphertext length not multiple of 3DES block size")
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		cleartext = make([]byte, len(blob.Data))
		mode.CryptBlocks(cleartext, blob.Data)
	}

	if len(cleartext) == 0 {
		return nil, fmt.Errorf("decrypted cleartext empty")
	}

	padding := int(cleartext[len(cleartext)-1])
	if padding > 0 && padding <= len(cleartext) {
		valid := true
		for i := len(cleartext) - padding; i < len(cleartext); i++ {
			if cleartext[i] != byte(padding) {
				valid = false
				break
			}
		}
		if valid {
			return cleartext[:len(cleartext)-padding], nil
		}
	}

	return cleartext, nil
}
