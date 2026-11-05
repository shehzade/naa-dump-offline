package wmi

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/shehzade/naa-dump-offline/pkg/dpapi"
)

type NAACredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Source   string `json:"source,omitempty"`
}

type CarvedSecret struct {
	Index          int    `json:"index"`
	Offset         int64  `json:"offset"`
	MasterKeyGUID  string `json:"masterkey_guid"`
	Context        string `json:"context"`
	RawHex         string `json:"-"`
	DecryptedBytes []byte `json:"-"`
	DecryptedText  string `json:"decrypted_text,omitempty"`
	IsEmpty        bool   `json:"is_empty"`
}

var (
	cdataRegex = regexp.MustCompile(`<!\[CDATA\[([0-9A-Fa-f]{100,})\]\]>`)
	xmlHexRe   = regexp.MustCompile(`<!\[CDATA\[([0-9A-Fa-f]+)\]\]>`)
)

func DecompressZlib(hexPayload string) ([]byte, error) {
	data, err := hex.DecodeString(strings.TrimSpace(hexPayload))
	if err != nil {
		return nil, err
	}
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func ParseDecryptedPayload(data []byte) (string, bool) {
	if len(data) == 0 || (len(data) <= 2 && bytes.Equal(data, []byte{0, 0})) {
		return "", true
	}

	text := dpapi.DecodeUTF16LE(data)
	if text == "" {
		text = strings.TrimRight(string(data), "\x00")
	}

	return text, false
}

func ExtractCredentialsFromSecrets(secrets []*CarvedSecret) []NAACredential {
	credentials := []NAACredential{}
	seen := make(map[string]bool)

	var potentialUsers []string
	var potentialPasswords []string

	for _, s := range secrets {
		if s.IsEmpty || s.DecryptedText == "" {
			continue
		}

		if strings.Contains(s.DecryptedText, "CCM_NetworkAccessAccount") {
			extractFromXML(s.DecryptedText, &credentials, seen)
		}

		if strings.Contains(s.DecryptedText, `Compression="zlib"`) {
			matches := xmlHexRe.FindAllStringSubmatch(s.DecryptedText, -1)
			for _, m := range matches {
				decomp, err := DecompressZlib(m[1])
				if err == nil {
					decompText := dpapi.DecodeUTF16LE(decomp)
					if decompText == "" {
						decompText = string(decomp)
					}
					extractFromXML(decompText, &credentials, seen)
				}
			}
		}

		text := strings.TrimSpace(s.DecryptedText)
		if !strings.HasPrefix(text, "<") && !strings.Contains(text, "\n") {
			if strings.Contains(text, "\\") || strings.Contains(text, "@") {
				potentialUsers = append(potentialUsers, text)
			} else if len(text) > 0 && len(text) < 128 {
				potentialPasswords = append(potentialPasswords, text)
			}
		}
	}

	for _, u := range potentialUsers {
		for _, p := range potentialPasswords {
			key := fmt.Sprintf("%s:%s", u, p)
			if !seen[key] {
				seen[key] = true
				credentials = append(credentials, NAACredential{
					Username: u,
					Password: p,
					Source:   "OBJECTS.DATA",
				})
			}
		}
	}

	return credentials
}

func isLikelyHexCiphertext(s string) bool {
	if len(s) < 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func extractFromXML(xmlContent string, creds *[]NAACredential, seen map[string]bool) {
	userRe := regexp.MustCompile(`name="NetworkAccessUsername"[^>]*>[\s\r\n]*<value>[\s\r\n]*<!\[CDATA\[([^\]]+)\]\]>`)
	passRe := regexp.MustCompile(`name="NetworkAccessPassword"[^>]*>[\s\r\n]*<value>[\s\r\n]*<!\[CDATA\[([^\]]+)\]\]>`)

	userMatches := userRe.FindAllStringSubmatch(xmlContent, -1)
	passMatches := passRe.FindAllStringSubmatch(xmlContent, -1)

	minLen := len(userMatches)
	if len(passMatches) < minLen {
		minLen = len(passMatches)
	}

	for i := 0; i < minLen; i++ {
		u := strings.TrimSpace(userMatches[i][1])
		p := strings.TrimSpace(passMatches[i][1])

		if isLikelyHexCiphertext(u) || isLikelyHexCiphertext(p) {
			continue
		}

		key := fmt.Sprintf("%s:%s", u, p)
		if !seen[key] && (u != "" || p != "") {
			seen[key] = true
			*creds = append(*creds, NAACredential{
				Username: u,
				Password: p,
				Source:   "Policy XML",
			})
		}
	}
}
