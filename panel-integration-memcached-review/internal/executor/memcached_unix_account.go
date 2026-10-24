package executor

import (
	"bytes"
	"encoding/json"
	"regexp"

	"local/panel/internal/core"
)

// Distinct closed records, never an IDS/site label or an image default UID.
// These values are not authority until read through the fixed Root-owned
// private directory and checked against fresh NSS and the actual peer.
type memcachedUnixAdminIntent struct {
	Format int    `json:"format"`
	Name   string `json:"name"`
	Nonce  string `json:"nonce"`
}

type memcachedUnixAdminReceipt struct {
	Format    int    `json:"format"`
	Name      string `json:"name"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	IntentSHA string `json:"intent_sha256"`
}

var memcachedUnixRecordSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

func memcachedUnixCanonicalRecord(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return append(raw, '\n')
}

func decodeMemcachedUnixAdminIntent(raw []byte) (memcachedUnixAdminIntent, error) {
	var value memcachedUnixAdminIntent
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &value) != nil ||
		value.Format != 1 || value.Name != memcachedUnixAdminName || !core.ValidID(value.Nonce) ||
		!bytes.Equal(raw, memcachedUnixCanonicalRecord(value)) {
		return memcachedUnixAdminIntent{}, errMemcachedUnixNSS
	}
	return value, nil
}

func decodeMemcachedUnixAdminReceipt(raw []byte) (memcachedUnixAdminReceipt, error) {
	var value memcachedUnixAdminReceipt
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &value) != nil ||
		value.Format != 1 || value.Name != memcachedUnixAdminName || value.UID == 0 || value.UID >= 1000 ||
		value.GID == 0 || value.GID >= 1000 || !memcachedUnixRecordSHA.MatchString(value.IntentSHA) ||
		!bytes.Equal(raw, memcachedUnixCanonicalRecord(value)) {
		return memcachedUnixAdminReceipt{}, errMemcachedUnixNSS
	}
	return value, nil
}
