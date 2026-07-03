package main

import (
	"net"
	"strings"
	"crypto/sha1"
	"encoding/hex"

	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"
)

// readMachineID returns a stable per-machine identifier for this Windows PC
// by reading MachineGuid from the registry. This value is generated once
// during Windows setup and persists across reboots, giving a stable unique
// identifier for the NX Device sent as X-Device-ID to the PBX.
//
// Registry key: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
// Readable by standard (non-admin) users; no elevation required.
// Returns empty string if the key cannot be read.
func readMachineID() string {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return ""
	}
	defer k.Close()

	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}

	id := strings.ReplaceAll(strings.TrimSpace(guid), "-", "")
	if len(id) > 32 {
		id = id[:32]
	}
	return id
}

func CreateBranch() (string, error) {
	uuid, err := uuid.NewRandom()
	if err == nil {
		tmp := strings.Split(uuid.String(), "-")
		return "z9hG4bK" + tmp[len(tmp)-1], nil
	}
	return "", err
}

func CreateBranchFromSeed(seed string) (string, error) {
	h := sha1.Sum([]byte(seed))
	return "z9hG4bK" + hex.EncodeToString(h[:])[:16], nil
}

func CreateTag() (string, error) {
	uuid, err := uuid.NewRandom()
	if err == nil {
		tmp := strings.Split(uuid.String(), "-")
		return tmp[len(tmp)-1], nil
	}
	return "", err
}

func inStrArray(s string, a []string) bool {
	for _, t := range a {
		if t == s {
			return true
		}
	}
	return false
}

func strArraySub(a1 []string, a2 []string) []string {
	r := make([]string, 0)
	for _, s := range a1 {
		if !inStrArray(s, a2) {
			r = append(r, s)
		}
	}
	return r
}

func isIPAddress(addr string) bool {
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		addr = addr[1 : len(addr)-1]
	}
	return net.ParseIP(addr) != nil
}

func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}