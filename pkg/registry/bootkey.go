package registry

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"unicode/utf16"

	"www.velocidex.com/golang/regparser"
)

var bootKeyPermutation = []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

func readClassString(r io.ReaderAt, key *regparser.CM_KEY_NODE) (string, error) {
	offset := key.Class()
	length := key.ClassLength()
	if length == 0 {
		return "", fmt.Errorf("empty class")
	}
	buf := make([]byte, length)
	_, err := r.ReadAt(buf, int64(4096+offset+4))
	if err != nil {
		return "", err
	}
	u16 := make([]uint16, length/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(buf[i*2 : (i+1)*2])
	}
	return string(utf16.Decode(u16)), nil
}

func GetBootKey(systemHivePath string) ([]byte, error) {
	f, err := os.Open(systemHivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SYSTEM hive: %w", err)
	}
	defer f.Close()

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SYSTEM hive: %w", err)
	}

	selectKey := reg.OpenKey("Select")
	if selectKey == nil {
		return nil, fmt.Errorf("could not find Select key in SYSTEM hive")
	}

	var currentControlSet string
	for _, val := range selectKey.Values() {
		if val.ValueName() == "Current" {
			currentControlSet = fmt.Sprintf("ControlSet%03d", val.ValueData().Uint64)
			break
		}
	}
	if currentControlSet == "" {
		currentControlSet = "ControlSet001"
	}

	subkeys := []string{"JD", "Skew1", "GBG", "Data"}
	var hexStr string

	for _, sub := range subkeys {
		path := fmt.Sprintf("%s\\Control\\Lsa\\%s", currentControlSet, sub)
		k := reg.OpenKey(path)
		if k == nil {
			return nil, fmt.Errorf("could not find key: %s", path)
		}
		s, err := readClassString(f, k)
		if err != nil {
			return nil, fmt.Errorf("failed to read class for %s: %w", path, err)
		}
		if len(s) > 8 {
			s = s[:8]
		}
		hexStr += s
	}

	rawBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bootkey hex: %w", err)
	}
	if len(rawBytes) != 16 {
		return nil, fmt.Errorf("expected 16 scrambled bytes, got %d", len(rawBytes))
	}

	bootKey := make([]byte, len(rawBytes))
	for i := range bootKey {
		bootKey[i] = rawBytes[bootKeyPermutation[i]]
	}

	return bootKey, nil
}
