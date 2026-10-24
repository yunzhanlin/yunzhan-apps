package core

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestMemcachedUnixCacheNativeKeyTokenPreserves250OrExplicitlyRejectsBinary187(t *testing.T) {
	for _, key := range []string{strings.Repeat("k", 250), strings.Repeat("汉", 83) + "x"} {
		encoded := base64.StdEncoding.EncodeToString([]byte(key))
		token, flag, err := MemcachedUnixCacheKeyToken(encoded)
		if err != nil || token != key || flag != "" {
			t.Fatal("long native key was renamed/truncated", err)
		}
	}
	binary := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x00", 186)))
	token, flag, err := MemcachedUnixCacheKeyToken(binary)
	if err != nil || token != binary || flag != " b" {
		t.Fatal("exact binary native token", err)
	}
	binary = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x00", 187)))
	if _, _, err := MemcachedUnixCacheKeyToken(binary); err != ErrMemcachedUnixCacheKeyEncoding {
		t.Fatal("binary encoding overflow falsely advertised", err)
	}
	if err := ValidateMemcachedUnixCacheInput(MemcachedUnixCacheInput{Action: "get", KeyBase64: binary}); err != ErrMemcachedUnixCacheKeyEncoding {
		t.Fatal("invalid binary key escaped Core boundary")
	}
}

func TestMemcachedUnixCacheCanonicalBinaryKeysCASAndClosedCommands(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("云栈😀\r\n\x00键"))
	for _, action := range []string{"get", "add", "cas", "delete"} {
		in := MemcachedUnixCacheInput{Action: action, KeyBase64: key}
		if action == "cas" || action == "delete" {
			in.CAS = "18446744073709551615"
		}
		if action == "add" || action == "cas" {
			in.ValueBase64 = base64.StdEncoding.EncodeToString([]byte("值\r\nEND\r\n"))
			in.TTLSeconds = 30 * 86400
			in.Flags = 0xffffffff
		}
		if err := ValidateMemcachedUnixCacheInput(in); err != nil {
			t.Fatal(action, err)
		}
	}
	for _, name := range []string{"basic", "settings", "items", "slabs"} {
		if ValidateMemcachedUnixCacheInput(MemcachedUnixCacheInput{Action: "stats", Stats: name}) != nil {
			t.Fatal(name)
		}
	}
	for _, in := range []MemcachedUnixCacheInput{
		{Action: "flush_all"}, {Action: "get", KeyBase64: ""}, {Action: "get", KeyBase64: "YQ"}, {Action: "get", KeyBase64: "YQ==\n"},
		{Action: "get", KeyBase64: key, ValueBase64: "Yg=="}, {Action: "get", KeyBase64: key, CAS: "1"}, {Action: "delete", KeyBase64: key},
		{Action: "delete", KeyBase64: key, CAS: "01"}, {Action: "delete", KeyBase64: key, CAS: "0"}, {Action: "delete", KeyBase64: key, CAS: "18446744073709551616"},
		{Action: "cas", KeyBase64: key, CAS: "1\r\nflush_all"}, {Action: "add", KeyBase64: key, CAS: "1"},
		{Action: "add", KeyBase64: key, TTLSeconds: 1}, {Action: "add", KeyBase64: key, TTLSeconds: -1}, {Action: "add", KeyBase64: key, TTLSeconds: 30*86400 + 1},
		{Action: "stats", Stats: "reset"}, {Action: "stats", Stats: "settings\r\nflush_all"}, {Action: "stats", Stats: "basic", KeyBase64: key},
	} {
		if ValidateMemcachedUnixCacheInput(in) == nil {
			t.Fatal("unbound/noncanonical/unsafe command", in.Action)
		}
	}
}

func TestMemcachedUnixCacheEditorCapacityDoesNotPretendToChangeDaemonLimit(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 250)))
	value := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("v", MemcachedUnixConsoleValueBytes)))
	if ValidateMemcachedUnixCacheInput(MemcachedUnixCacheInput{Action: "add", KeyBase64: key, ValueBase64: value}) != nil {
		t.Fatal("exact editor byte budget refused")
	}
	if ValidateMemcachedUnixCacheInput(MemcachedUnixCacheInput{Action: "add", KeyBase64: key, ValueBase64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("v", MemcachedUnixConsoleValueBytes+1)))}) == nil {
		t.Fatal("oversize value accepted")
	}
	if _, err := MemcachedUnixCacheKey(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 251)))); err == nil {
		t.Fatal("native key limit widened")
	}
	for _, raw := range []string{"", "0", "00", "+1", "1 ", "18446744073709551616", "-1"} {
		if MemcachedUnixCASToken(raw, false) {
			t.Fatal("noncanonical CAS", raw)
		}
	}
}
