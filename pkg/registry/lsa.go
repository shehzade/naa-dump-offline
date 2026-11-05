package registry

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"

	"www.velocidex.com/golang/regparser"
)

type DPAPISystemKeys struct {
	BootKey    []byte
	LSAKey     []byte
	MachineKey []byte
	UserKey    []byte
}

func sha256Key(key, value []byte) []byte {
	h := sha256.New()
	h.Write(key)
	for i := 0; i < 1000; i++ {
		h.Write(value)
	}
	return h.Sum(nil)
}

func decryptAES(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	paddedLen := (len(ciphertext) + 15) / 16 * 16
	buf := make([]byte, paddedLen)
	copy(buf, ciphertext)

	out := make([]byte, paddedLen)
	for i := 0; i < len(buf); i += 16 {
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(out[i:i+16], buf[i:i+16])
	}
	return out, nil
}

func ExtractDPAPISystemKeys(securityHivePath string, bootKey []byte) (*DPAPISystemKeys, error) {
	f, err := os.Open(securityHivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SECURITY hive: %w", err)
	}
	defer f.Close()

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SECURITY hive: %w", err)
	}

	polEKKey := reg.OpenKey("Policy\\PolEKList")
	if polEKKey == nil {
		return nil, fmt.Errorf("could not find Policy\\PolEKList key in SECURITY hive")
	}

	var polEKVal []byte
	for _, v := range polEKKey.Values() {
		if v.ValueName() == "" || v.ValueName() == "default" {
			polEKVal = v.ValueData().Data
			break
		}
	}
	if len(polEKVal) < 60 {
		return nil, fmt.Errorf("Policy\\PolEKList value is too short (%d bytes)", len(polEKVal))
	}

	salt := polEKVal[28 : 28+32]
	ciphertext := polEKVal[28+32:]

	tmpKey := sha256Key(bootKey, salt)
	plainText, err := decryptAES(tmpKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PolEKList: %w", err)
	}

	if len(plainText) < 100 {
		return nil, fmt.Errorf("decrypted PolEKList plainText too short (%d bytes)", len(plainText))
	}
	lsaKey := make([]byte, 32)
	copy(lsaKey, plainText[68:100])

	dpapiValKey := reg.OpenKey("Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal")
	if dpapiValKey == nil {
		return nil, fmt.Errorf("could not find Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal key in SECURITY hive")
	}

	var dpapiVal []byte
	for _, v := range dpapiValKey.Values() {
		if v.ValueName() == "" || v.ValueName() == "default" {
			dpapiVal = v.ValueData().Data
			break
		}
	}
	if len(dpapiVal) < 60 {
		return nil, fmt.Errorf("DPAPI_SYSTEM CurrVal is too short (%d bytes)", len(dpapiVal))
	}

	dpapiSalt := dpapiVal[28 : 28+32]
	dpapiCipher := dpapiVal[28+32:]

	dpapiTmpKey := sha256Key(lsaKey, dpapiSalt)
	dpapiPlain, err := decryptAES(dpapiTmpKey, dpapiCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DPAPI_SYSTEM secret: %w", err)
	}

	if len(dpapiPlain) < 16 {
		return nil, fmt.Errorf("decrypted DPAPI_SYSTEM plainText too short (%d bytes)", len(dpapiPlain))
	}

	secretLen := binary.LittleEndian.Uint32(dpapiPlain[:4])
	if int(16+secretLen) > len(dpapiPlain) || secretLen < 44 {
		return nil, fmt.Errorf("invalid secret length in DPAPI_SYSTEM: %d", secretLen)
	}

	dpapiSecret := dpapiPlain[16 : 16+secretLen]
	machineKey := make([]byte, 20)
	userKey := make([]byte, 20)
	copy(machineKey, dpapiSecret[4:24])
	copy(userKey, dpapiSecret[24:44])

	return &DPAPISystemKeys{
		BootKey:    bootKey,
		LSAKey:     lsaKey,
		MachineKey: machineKey,
		UserKey:    userKey,
	}, nil
}
