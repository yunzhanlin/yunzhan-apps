//go:build linux && panel_memcached_unix_native_qa

package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Actual fixed-image private fixture only. No public handler, installed user,
// original container or store success is inferred from these low-level calls.
func memcachedUnixNativeConsoleProtocol(t *testing.T, ctx context.Context, dir string, pid int, account memcachedUnixAccount, project string) {
	t.Helper()
	path := filepath.Join(dir, "cache.sock")
	memcachedUnixNativeKeyBoundaries(t, ctx, path, pid, account, project)
	encode := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	call := func(in core.MemcachedUnixCacheInput, want error) core.MemcachedUnixCacheResult {
		t.Helper()
		out, err := exchangeMemcachedUnixCacheAt(ctx, path, pid, account, in)
		if !errors.Is(err, want) {
			t.Fatalf("real fixed-image %s result differs: %v", in.Action, err)
		}
		return out
	}
	key := encode([]byte("qa_" + project + "_云栈\r\n\x00"))
	value := encode([]byte("初始😀\x00\r\nEND\r\n"))
	added := call(core.MemcachedUnixCacheInput{Action: "add", KeyBase64: key, ValueBase64: value, TTLSeconds: 120, Flags: 0xffffffff}, nil)
	if !added.Changed || !core.MemcachedUnixCASToken(added.CAS, false) {
		t.Fatal("real add-only did not return an actual CAS")
	}
	call(core.MemcachedUnixCacheInput{Action: "add", KeyBase64: key, ValueBase64: encode([]byte("must-not-overwrite"))}, errMemcachedUnixExists)
	get := func() core.MemcachedUnixCacheResult {
		return call(core.MemcachedUnixCacheInput{Action: "get", KeyBase64: key}, nil)
	}
	original := get()
	if !original.Found || original.ValueBase64 != value || original.CAS != added.CAS || original.Flags != 0xffffffff || original.TTLRemaining < 1 || original.TTLRemaining > 120 {
		t.Fatal("real binary/meta flags/TTL snapshot differs")
	}
	call(core.MemcachedUnixCacheInput{Action: "cas", KeyBase64: key, ValueBase64: encode([]byte("must-not-overwrite")), CAS: "18446744073709551615"}, errMemcachedUnixCAS)
	if actual := get(); actual.ValueBase64 != original.ValueBase64 || actual.CAS != original.CAS {
		t.Fatal("stale native CAS changed bytes/version")
	}
	changedValue := encode([]byte("已更新🙂\x00\r\nEND\r\n"))
	changed := call(core.MemcachedUnixCacheInput{Action: "cas", KeyBase64: key, ValueBase64: changedValue, CAS: original.CAS, TTLSeconds: 120, Flags: 73}, nil)
	current := get()
	if !changed.Changed || current.CAS != changed.CAS || current.ValueBase64 != changedValue || current.Flags != 73 {
		t.Fatal("real atomic CAS update differs")
	}
	call(core.MemcachedUnixCacheInput{Action: "delete", KeyBase64: key, CAS: original.CAS}, errMemcachedUnixCAS)
	if actual := get(); actual.ValueBase64 != current.ValueBase64 || actual.CAS != current.CAS {
		t.Fatal("stale native CAS delete removed/changed current item")
	}
	deleted := call(core.MemcachedUnixCacheInput{Action: "delete", KeyBase64: key, CAS: current.CAS}, nil)
	if !deleted.Changed || get().Found {
		t.Fatal("actual CAS delete did not remove exact item")
	}
	call(core.MemcachedUnixCacheInput{Action: "delete", KeyBase64: key, CAS: current.CAS}, errMemcachedUnixMissing)
	call(core.MemcachedUnixCacheInput{Action: "cas", KeyBase64: key, CAS: current.CAS, ValueBase64: value}, errMemcachedUnixMissing)
	for _, kind := range []string{"basic", "settings", "items", "slabs"} {
		stats := call(core.MemcachedUnixCacheInput{Action: "stats", Stats: kind}, nil)
		if kind == "basic" && stats.Statistics["version"] != "1.6.45" {
			t.Fatal("actual native version stats")
		}
		if kind == "settings" && stats.Statistics["maxbytes"] != "134217728" {
			t.Fatal("actual128MiB setting not accepted from UI labels")
		}
	}
	boundaryKey := encode([]byte("qa_" + project + "_budget"))
	boundaryValue := encode(bytes.Repeat([]byte{'v'}, core.MemcachedUnixConsoleValueBytes))
	boundary := call(core.MemcachedUnixCacheInput{Action: "add", KeyBase64: boundaryKey, ValueBase64: boundaryValue}, nil)
	readBoundary := call(core.MemcachedUnixCacheInput{Action: "get", KeyBase64: boundaryKey}, nil)
	if readBoundary.ValueBase64 != boundaryValue || readBoundary.ValueBytes != core.MemcachedUnixConsoleValueBytes {
		t.Fatal("exact editor byte bound corrupted")
	}
	call(core.MemcachedUnixCacheInput{Action: "delete", KeyBase64: boundaryKey, CAS: boundary.CAS}, nil)
	// A genuine business client may hold a larger value. Seed only this NEW
	// fixture's nonce key using the existing verified transport, then require
	// explicit refusal instead of truncating/reconstructing it in the editor.
	largeKey := "qa_" + project + "_native_larger_value"
	conn, err := dialMemcachedUnixVerifiedAt(ctx, path, pid, account)
	if err != nil {
		t.Fatal(err)
	}
	large := bytes.Repeat([]byte{'B'}, 64<<10)
	defer clear(large)
	packet := append([]byte(fmt.Sprintf("set %s 0 0 %d\r\n", largeKey, len(large))), large...)
	packet = append(packet, '\r', '\n')
	if n, err := conn.Write(packet); err != nil || n != len(packet) {
		conn.Close()
		t.Fatal("only private oversized seed")
	}
	clear(packet)
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "STORED\r\n" {
		conn.Close()
		t.Fatal("native larger item seed")
	}
	conn.Close()
	readLarge := func() ([]byte, string) {
		t.Helper()
		c, err := dialMemcachedUnixVerifiedAt(ctx, path, pid, account)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		request := []byte("gets " + largeKey + "\r\n")
		if n, err := c.Write(request); err != nil || n != len(request) {
			t.Fatal("private large value read")
		}
		r := bufio.NewReaderSize(c, 4096)
		line, err := memcachedUnixProtocolLine(r)
		fields := strings.Fields(line)
		if err != nil || len(fields) != 5 || fields[0] != "VALUE" || fields[1] != largeKey || fields[2] != "0" || fields[3] != "65536" || !core.MemcachedUnixCASToken(fields[4], false) {
			t.Fatal("private native large snapshot header")
		}
		value := make([]byte, len(large)+2)
		if _, err := io.ReadFull(r, value); err != nil || !bytes.Equal(value[len(large):], []byte("\r\n")) {
			t.Fatal("private large snapshot data")
		}
		end, err := memcachedUnixProtocolLine(r)
		if err != nil || end != "END" {
			t.Fatal("private large snapshot terminator")
		}
		return value[:len(large)], fields[4]
	}
	beforeLarge, beforeCAS := readLarge()
	defer clear(beforeLarge)
	call(core.MemcachedUnixCacheInput{Action: "get", KeyBase64: encode([]byte(largeKey))}, errMemcachedUnixConsoleLarge)
	afterLarge, afterCAS := readLarge()
	defer clear(afterLarge)
	if !bytes.Equal(beforeLarge, large) || !bytes.Equal(afterLarge, large) || beforeCAS != afterCAS {
		t.Fatal("editor refusal changed a genuine larger business item or CAS")
	}
	keyTTL := encode([]byte("qa_" + project + "_meta_expiry"))
	call(core.MemcachedUnixCacheInput{Action: "add", KeyBase64: keyTTL, ValueBase64: value, TTLSeconds: 2}, nil)
	timer := time.NewTimer(3100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal("native expiry qualification cancelled")
	case <-timer.C:
	}
	if call(core.MemcachedUnixCacheInput{Action: "get", KeyBase64: keyTTL}, nil).Found {
		t.Fatal("actual meta TTL did not expire naturally")
	}
}

func memcachedUnixNativeConsoleForeignRequest(ctx context.Context, path string, pid int, account memcachedUnixAccount) error {
	_, err := exchangeMemcachedUnixCacheAt(ctx, path, pid, account, core.MemcachedUnixCacheInput{Action: "get", KeyBase64: base64.StdEncoding.EncodeToString([]byte("qa_native_foreign_peer_probe"))})
	return err
}

// Fixed-image boundary qualification, not a public raw-command surface.
func memcachedUnixNativeKeyBoundaries(t *testing.T, ctx context.Context, path string, pid int, account memcachedUnixAccount, project string) {
	t.Helper()
	call := func(in core.MemcachedUnixCacheInput) core.MemcachedUnixCacheResult {
		t.Helper()
		out, err := exchangeMemcachedUnixCacheAt(ctx, path, pid, account, in)
		if err != nil {
			t.Fatal("actual native key boundary", err)
		}
		return out
	}
	prefix := "qa_" + project + "_"
	ascii := []byte(prefix + strings.Repeat("K", 250-len(prefix)))
	unicode := []byte(prefix + strings.Repeat("汉", (250-len(prefix))/3))
	for len(unicode) < 250 {
		unicode = append(unicode, 'u')
	}
	binary := bytes.Repeat([]byte{0, 13, 10}, 62)
	for _, key := range [][]byte{ascii, unicode, binary} {
		encoded := base64.StdEncoding.EncodeToString(key)
		original := call(core.MemcachedUnixCacheInput{Action: "add", KeyBase64: encoded, ValueBase64: "dmFsdWU=", TTLSeconds: 120})
		current := call(core.MemcachedUnixCacheInput{Action: "get", KeyBase64: encoded})
		if !current.Found || current.CAS != original.CAS || current.ValueBase64 != "dmFsdWU=" {
			t.Fatal("native long/binary key renamed or truncated")
		}
		changed := call(core.MemcachedUnixCacheInput{Action: "cas", KeyBase64: encoded, ValueBase64: "dXBkYXRl", CAS: current.CAS, TTLSeconds: 120})
		actual := call(core.MemcachedUnixCacheInput{Action: "get", KeyBase64: encoded})
		if !changed.Changed || actual.CAS != changed.CAS || actual.ValueBase64 != "dXBkYXRl" {
			t.Fatal("native long key CAS differs")
		}
		call(core.MemcachedUnixCacheInput{Action: "delete", KeyBase64: encoded, CAS: actual.CAS})
		if call(core.MemcachedUnixCacheInput{Action: "get", KeyBase64: encoded}).Found {
			t.Fatal("native long key delete missed original")
		}
	}
	rejected := false
	_, err := exchangeMemcachedUnixCacheGatedAt(ctx, path, pid, account, core.MemcachedUnixCacheInput{Action: "get", KeyBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0, 'x'}, 125))}, func(context.Context) error { rejected = true; return nil })
	if !errors.Is(err, core.ErrMemcachedUnixCacheKeyEncoding) || rejected {
		t.Fatal("unrepresentable long binary key reached live transport or claimed success", err)
	}
	key := base64.StdEncoding.EncodeToString([]byte(prefix + "late_authority"))
	denied := errors.New("private current authority deliberately revoked after peer verification")
	checked := false
	_, err = exchangeMemcachedUnixCacheGatedAt(ctx, path, pid, account, core.MemcachedUnixCacheInput{Action: "add", KeyBase64: key, ValueBase64: "bXVzdC1ub3QtYmUtc2VudA=="}, func(context.Context) error { checked = true; return denied })
	if !errors.Is(err, denied) || !checked {
		t.Fatal("actual verified connection missed before-write authority gate")
	}
	if call(core.MemcachedUnixCacheInput{Action: "get", KeyBase64: key}).Found {
		t.Fatal("revoked-before-write gate created a cache item")
	}
}
