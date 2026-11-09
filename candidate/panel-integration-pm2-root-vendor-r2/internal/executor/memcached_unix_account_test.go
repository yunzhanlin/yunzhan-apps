package executor

import (
	"bytes"
	"strings"
	"testing"
)

func TestMemcachedUnixAdminOwnershipRecordsHaveSeparateCanonicalClosedSchemas(t *testing.T) {
	intent := memcachedUnixAdminIntent{1, memcachedUnixAdminName, strings.Repeat("a", 32)}
	receipt := memcachedUnixAdminReceipt{1, memcachedUnixAdminName, 800, 801, strings.Repeat("b", 64)}
	i, r := memcachedUnixCanonicalRecord(intent), memcachedUnixCanonicalRecord(receipt)
	beforeI, beforeR := bytes.Clone(i), bytes.Clone(r)
	if v, err := decodeMemcachedUnixAdminIntent(i); err != nil || v != intent {
		t.Fatal("own canonical intent refused", err)
	}
	if v, err := decodeMemcachedUnixAdminReceipt(r); err != nil || v != receipt {
		t.Fatal("own canonical receipt refused", err)
	}
	if _, err := decodeMemcachedUnixAdminIntent(r); err == nil {
		t.Fatal("receipt borrowed intent authority")
	}
	if _, err := decodeMemcachedUnixAdminReceipt(i); err == nil {
		t.Fatal("intent borrowed completed account ownership")
	}
	if !bytes.Equal(i, beforeI) || !bytes.Equal(r, beforeR) {
		t.Fatal("caller input changed")
	}
	for _, item := range []struct {
		name string
		old  string
		new  string
	}{
		{"unknown", `"format":1`, `"other":true,"format":1`},
		{"duplicate", `"format":1`, `"format":1,"format":1`},
		{"alias", `"format":1`, `"Format":1`},
		{"float", `"format":1`, `"format":1.0`},
		{"foreign-version", `"format":1`, `"format":2`},
		{"foreign-user", memcachedUnixAdminName, "panel-network-ids"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := decodeMemcachedUnixAdminIntent(bytes.Replace(i, []byte(item.old), []byte(item.new), 1)); err == nil {
				t.Fatal("non-canonical intent accepted")
			}
			if _, err := decodeMemcachedUnixAdminReceipt(bytes.Replace(r, []byte(item.old), []byte(item.new), 1)); err == nil {
				t.Fatal("non-canonical receipt accepted")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte(`null`), []byte(`[]`), append([]byte(" "), i...), append(i, '\n'), []byte(strings.Repeat("x", 2049))} {
		if _, err := decodeMemcachedUnixAdminIntent(raw); err == nil {
			t.Fatal("incomplete/oversized intent accepted")
		}
	}
	for _, bad := range []string{"", strings.Repeat("A", 32), "../other", strings.Repeat("a", 31)} {
		v := intent
		v.Nonce = bad
		if _, err := decodeMemcachedUnixAdminIntent(memcachedUnixCanonicalRecord(v)); err == nil {
			t.Fatal("invalid creation identity")
		}
	}
	for _, change := range []func(*memcachedUnixAdminReceipt){
		func(v *memcachedUnixAdminReceipt) { v.UID = 0 },
		func(v *memcachedUnixAdminReceipt) { v.GID = 0 },
		func(v *memcachedUnixAdminReceipt) { v.UID = 1000 },
		func(v *memcachedUnixAdminReceipt) { v.GID = 1000 },
		func(v *memcachedUnixAdminReceipt) { v.UID = 1 << 31 },
		func(v *memcachedUnixAdminReceipt) { v.IntentSHA = "" },
		func(v *memcachedUnixAdminReceipt) { v.IntentSHA = strings.Repeat("B", 64) },
	} {
		v := receipt
		change(&v)
		if _, err := decodeMemcachedUnixAdminReceipt(memcachedUnixCanonicalRecord(v)); err == nil {
			t.Fatal("root/non-system/unknown creation receipt accepted")
		}
	}
}
