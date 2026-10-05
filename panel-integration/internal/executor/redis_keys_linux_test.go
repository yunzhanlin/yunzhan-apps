//go:build linux

package executor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRedisScanBoundaries(t *testing.T) {
	page, err := parseRedisScan([]json.RawMessage{json.RawMessage(`"42"`), json.RawMessage(`["site:1","bad\nkey","site:2"]`)}, 2)
	if err != nil || page.DB != 2 || page.Cursor != "42" || len(page.Keys) != 2 || page.Omitted != 1 {
		t.Fatal(page, err)
	}
	for _, raw := range [][]json.RawMessage{
		{json.RawMessage(`"bad"`), json.RawMessage(`[]`)},
		{json.RawMessage(`"0"`), json.RawMessage(`{}`)},
		{json.RawMessage(`"0"`), json.RawMessage(`[` + strings.Repeat(`"x",`, 200) + `"x"]`)},
	} {
		if _, err := parseRedisScan(raw, 0); err == nil {
			t.Fatal("invalid scan accepted", raw)
		}
	}
}

func TestParseRedisStructuredPreview(t *testing.T) {
	hash, err := parseRedisStructuredPreview([]string{"hash", "2", "name", "张三", "role", "admin"}, 3, "profile")
	if err != nil || hash.Kind != "hash" || hash.Total != 2 || !hash.Sampled || hash.Truncated || len(hash.Items) != 2 || hash.Items[0].Value != "张三" {
		t.Fatal(hash, err)
	}
	list, err := parseRedisStructuredPreview([]string{"list", "22", "one", "two"}, 0, "queue")
	if err != nil || !list.Truncated || list.Sampled || list.Items[1].Name != "1" {
		t.Fatal(list, err)
	}
	for _, raw := range [][]string{{"stream", "1"}, {"hash", "2", "field"}, {"list", "bad", "item"}, {"set", "0", "unexpected"}} {
		if _, err := parseRedisStructuredPreview(raw, 0, "invalid"); err == nil {
			t.Fatal("invalid structured preview accepted", raw)
		}
	}
}

func TestDecodeRedisTextHexRejectsBinary(t *testing.T) {
	if value, status := decodeRedisTextHex([]string{"ok", "e4bda0e5a5bd"}); status != "ok" || value != "你好" {
		t.Fatal(value, status)
	}
	for _, raw := range [][]string{{"ok", "ff"}, {"ok", "00"}, {"ok", "zz"}, {"ok", strings.Repeat("61", 4097)}} {
		if _, status := decodeRedisTextHex(raw); status == "ok" {
			t.Fatal("unsafe Redis text accepted", raw[1][:min(len(raw[1]), 16)])
		}
	}
}
