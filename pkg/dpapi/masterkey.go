package dpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"github.com/shehzade/naa-dump-offline/pkg/registry"
)

type MasterKeyFile struct {
	Version      uint32
	Unk1         uint32
	Unk2         uint32
	Guid         string
	Unknown      uint32
	Policy       uint32
	Flags        uint32
	MasterKeyLen uint64
	BackupKeyLen uint64
	CredHistLen  uint64
	DomainKeyLen uint64
	MasterKey    *MasterKey
	BackupKey    *MasterKey
}

type MasterKey struct {
	Version      uint32
	Salt         []byte
	Rounds       uint32
	HashAlgo     uint32
	CryptAlgo    uint32
	Data         []byte
	DecryptedKey []byte
}

func ParseMasterKeyFile(raw []byte) (*MasterKeyFile, error) {
	if len(raw) < 128 {
		return nil, fmt.Errorf("master key file too short (%d bytes)", len(raw))
	}

	mkf := &MasterKeyFile{
		Version:      binary.LittleEndian.Uint32(raw[0:4]),
		Unk1:         binary.LittleEndian.Uint32(raw[4:8]),
		Unk2:         binary.LittleEndian.Uint32(raw[8:12]),
		Guid:         NormalizeGUID(DecodeUTF16LE(raw[12:84])),
		Unknown:      binary.LittleEndian.Uint32(raw[84:88]),
		Policy:       binary.LittleEndian.Uint32(raw[88:92]),
		Flags:        binary.LittleEndian.Uint32(raw[92:96]),
		MasterKeyLen: binary.LittleEndian.Uint64(raw[96:104]),
		BackupKeyLen: binary.LittleEndian.Uint64(raw[104:112]),
		CredHistLen:  binary.LittleEndian.Uint64(raw[112:120]),
		DomainKeyLen: binary.LittleEndian.Uint64(raw[120:128]),
	}

	offset := 128
	if mkf.MasterKeyLen > 0 && offset+int(mkf.MasterKeyLen) <= len(raw) {
		mkData := raw[offset : offset+int(mkf.MasterKeyLen)]
		mkf.MasterKey = parseMasterKey(mkData)
		offset += int(mkf.MasterKeyLen)
	}

	if mkf.BackupKeyLen > 0 && offset+int(mkf.BackupKeyLen) <= len(raw) {
		bkmkData := raw[offset : offset+int(mkf.BackupKeyLen)]
		mkf.BackupKey = parseMasterKey(bkmkData)
	}

	return mkf, nil
}

func parseMasterKey(raw []byte) *MasterKey {
	if len(raw) < 32 {
		return nil
	}
	return &MasterKey{
		Version:   binary.LittleEndian.Uint32(raw[0:4]),
		Salt:      raw[4:20],
		Rounds:    binary.LittleEndian.Uint32(raw[20:24]),
		HashAlgo:  binary.LittleEndian.Uint32(raw[24:28]),
		CryptAlgo: binary.LittleEndian.Uint32(raw[28:32]),
		Data:      raw[32:],
	}
}

func (mk *MasterKey) Decrypt(key []byte) ([]byte, error) {
	if mk == nil {
		return nil, fmt.Errorf("nil master key")
	}

	var hashFunc func() hash.Hash
	var hashKeyLen int
	switch mk.HashAlgo {
	case CALG_HMAC, CALG_SHA1:
		hashFunc = sha1.New
		hashKeyLen = 20
	case CALG_SHA_512:
		hashFunc = sha512.New
		hashKeyLen = 64
	default:
		return nil, fmt.Errorf("unsupported hash algo: 0x%x", mk.HashAlgo)
	}

	var cryptKeyLen, ivLen int
	switch mk.CryptAlgo {
	case CALG_AES_256:
		cryptKeyLen = 32
		ivLen = 16
	case CALG_3DES:
		cryptKeyLen = 24
		ivLen = 8
	default:
		return nil, fmt.Errorf("unsupported crypt algo: 0x%x", mk.CryptAlgo)
	}

	derivedBlob := DeriveKeyDPAPI(key, mk.Salt, cryptKeyLen+ivLen, int(mk.Rounds), hashFunc)
	cryptKey := derivedBlob[:cryptKeyLen]
	iv := derivedBlob[cryptKeyLen : cryptKeyLen+ivLen]

	var cleartext []byte
	switch mk.CryptAlgo {
	case CALG_AES_256:
		block, err := aes.NewCipher(cryptKey)
		if err != nil {
			return nil, err
		}
		if len(mk.Data)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("ciphertext length not multiple of AES block size")
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		cleartext = make([]byte, len(mk.Data))
		mode.CryptBlocks(cleartext, mk.Data)
	case CALG_3DES:
		block, err := des.NewTripleDESCipher(cryptKey)
		if err != nil {
			return nil, err
		}
		if len(mk.Data)%des.BlockSize != 0 {
			return nil, fmt.Errorf("ciphertext length not multiple of 3DES block size")
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		cleartext = make([]byte, len(mk.Data))
		mode.CryptBlocks(cleartext, mk.Data)
	}

	if len(cleartext) < 16+hashKeyLen+64 {
		return nil, fmt.Errorf("cleartext too short (%d)", len(cleartext))
	}

	decryptedKey := cleartext[len(cleartext)-64:]
	hmacSalt := cleartext[:16]
	hmacExpected := cleartext[16 : 16+hashKeyLen]

	h1 := hmac.New(hashFunc, key)
	h1.Write(hmacSalt)
	hmacKey := h1.Sum(nil)

	h2 := hmac.New(hashFunc, hmacKey)
	h2.Write(decryptedKey)
	hmacCalculated := h2.Sum(nil)

	if !bytes.Equal(hmacCalculated[:hashKeyLen], hmacExpected) {
		return nil, fmt.Errorf("HMAC verification failed")
	}

	mk.DecryptedKey = decryptedKey
	return decryptedKey, nil
}

func (mkf *MasterKeyFile) DecryptWithSystemKeys(keys *registry.DPAPISystemKeys) ([]byte, string, error) {
	if mkf.MasterKey != nil && len(keys.UserKey) > 0 {
		if dec, err := mkf.MasterKey.Decrypt(keys.UserKey); err == nil {
			return dec, "UserKey", nil
		}
	}

	if mkf.MasterKey != nil && len(keys.MachineKey) > 0 {
		if dec, err := mkf.MasterKey.Decrypt(keys.MachineKey); err == nil {
			return dec, "MachineKey", nil
		}
	}

	if mkf.BackupKey != nil && len(keys.UserKey) > 0 {
		if dec, err := mkf.BackupKey.Decrypt(keys.UserKey); err == nil {
			return dec, "BackupKey (UserKey)", nil
		}
	}

	if mkf.BackupKey != nil && len(keys.MachineKey) > 0 {
		if dec, err := mkf.BackupKey.Decrypt(keys.MachineKey); err == nil {
			return dec, "BackupKey (MachineKey)", nil
		}
	}

	return nil, "", fmt.Errorf("failed to decrypt master key with UserKey or MachineKey")
}

func LoadAndDecryptMasterKey(pathOrDir string, targetGUID string, keys *registry.DPAPISystemKeys) ([]byte, string, error) {
	info, err := os.Stat(pathOrDir)
	if err != nil {
		return nil, "", fmt.Errorf("cannot access master key path: %w", err)
	}

	targetGUID = NormalizeGUID(targetGUID)

	if !info.IsDir() {
		data, err := os.ReadFile(pathOrDir)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read master key file: %w", err)
		}
		mkf, err := ParseMasterKeyFile(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse master key file: %w", err)
		}
		decKey, keyType, err := mkf.DecryptWithSystemKeys(keys)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decrypt master key %s: %w", pathOrDir, err)
		}
		return decKey, fmt.Sprintf("%s (%s)", pathOrDir, keyType), nil
	}

	entries, err := os.ReadDir(pathOrDir)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read master key directory: %w", err)
	}

	var filesToTry []string
	for _, e := range entries {
		if !e.IsDir() {
			filesToTry = append(filesToTry, filepath.Join(pathOrDir, e.Name()))
		}
	}

	for _, filePath := range filesToTry {
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		mkf, err := ParseMasterKeyFile(data)
		if err != nil {
			continue
		}

		fileBase := NormalizeGUID(filepath.Base(filePath))
		if targetGUID != "" && mkf.Guid != targetGUID && fileBase != targetGUID {
			continue
		}

		decKey, keyType, err := mkf.DecryptWithSystemKeys(keys)
		if err == nil {
			return decKey, fmt.Sprintf("%s (%s)", filePath, keyType), nil
		}
	}

	return nil, "", fmt.Errorf("could not find or decrypt valid master key for GUID %s in %s", targetGUID, pathOrDir)
}
