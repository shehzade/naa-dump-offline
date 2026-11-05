package wmi

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/shehzade/naa-dump-offline/pkg/dpapi"
)

type CarverResult struct {
	TotalBlobs    int
	UniqueBlobs   []*CarvedSecret
	RequiredGUIDs []string
	GUIDCounts    map[string]int
}

var (
	policySecretRe = regexp.MustCompile(`(?s)<PolicySecret[^>]*><!\[CDATA\[([0-9A-Fa-f]{100,})\]\]></PolicySecret>`)
)

func ScanObjectsData(objectsDataPath string) (*CarverResult, error) {
	data, err := os.ReadFile(objectsDataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read OBJECTS.DATA: %w", err)
	}

	result := &CarverResult{
		GUIDCounts: make(map[string]int),
	}

	seenHex := make(map[string]*CarvedSecret)

	matches := policySecretRe.FindAllSubmatchIndex(data, -1)
	result.TotalBlobs = len(matches)

	for i, loc := range matches {
		matchStart := loc[0]
		matchEnd := loc[1]
		subStart := loc[2]
		subEnd := loc[3]

		hexPayload := string(data[subStart:subEnd])

		ctxStart := matchStart - 200
		if ctxStart < 0 {
			ctxStart = 0
		}
		prefixChunk := string(data[ctxStart:matchStart])
		context := "PolicySecret"
		if strings.Contains(prefixChunk, "CCM_NetworkAccessAccount") {
			context = "CCM_NetworkAccessAccount"
		} else if strings.Contains(prefixChunk, "CCM_Policy_Action") {
			context = "CCM_Policy_Action"
		} else if strings.Contains(prefixChunk, "CCM_Policy_Policy5") {
			context = "CCM_Policy_Policy5"
		}

		rawBytes, err := hex.DecodeString(hexPayload)
		if err != nil || len(rawBytes) < 44 {
			continue
		}

		blobBytes := rawBytes
		if len(rawBytes) > 4 {
			blobBytes = rawBytes[4:]
		}

		blob, err := dpapi.ParseDPAPIBlob(blobBytes)
		if err != nil {
			blob, err = dpapi.ParseDPAPIBlob(rawBytes)
			if err != nil {
				continue
			}
		}

		guid := blob.GuidMasterKey
		if guid != "" {
			result.GUIDCounts[guid]++
		}

		if existing, ok := seenHex[hexPayload]; ok {
			if existing.Context == "PolicySecret" && context != "PolicySecret" {
				existing.Context = context
			}
			continue
		}

		secret := &CarvedSecret{
			Index:         i + 1,
			Offset:        int64(matchStart),
			MasterKeyGUID: guid,
			Context:       context,
			RawHex:        hexPayload,
		}

		seenHex[hexPayload] = secret
		result.UniqueBlobs = append(result.UniqueBlobs, secret)
		_ = matchEnd
	}

	naaIdx := 0
	for {
		idx := bytes.Index(data[naaIdx:], []byte("CCM_NetworkAccessAccount"))
		if idx == -1 {
			break
		}
		actualIdx := naaIdx + idx
		windowEnd := actualIdx + 2000
		if windowEnd > len(data) {
			windowEnd = len(data)
		}
		window := data[actualIdx:windowEnd]

		subMatches := cdataRegex.FindAllSubmatchIndex(window, -1)
		for _, sm := range subMatches {
			h := string(window[sm[2]:sm[3]])
			if _, ok := seenHex[h]; !ok {
				rawBytes, err := hex.DecodeString(h)
				if err != nil || len(rawBytes) < 44 {
					continue
				}
				blobBytes := rawBytes
				if len(rawBytes) > 4 {
					blobBytes = rawBytes[4:]
				}
				blob, err := dpapi.ParseDPAPIBlob(blobBytes)
				if err != nil {
					blob, err = dpapi.ParseDPAPIBlob(rawBytes)
					if err != nil {
						continue
					}
				}
				guid := blob.GuidMasterKey
				if guid != "" {
					result.GUIDCounts[guid]++
				}
				secret := &CarvedSecret{
					Index:         len(result.UniqueBlobs) + 1,
					Offset:        int64(actualIdx + sm[0]),
					MasterKeyGUID: guid,
					Context:       "CCM_NetworkAccessAccount",
					RawHex:        h,
				}
				seenHex[h] = secret
				result.UniqueBlobs = append(result.UniqueBlobs, secret)
				result.TotalBlobs++
			}
		}

		naaIdx = actualIdx + len("CCM_NetworkAccessAccount")
	}

	for guid := range result.GUIDCounts {
		result.RequiredGUIDs = append(result.RequiredGUIDs, guid)
	}
	sort.Strings(result.RequiredGUIDs)

	return result, nil
}
