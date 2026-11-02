//go:build linux

package executor

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func apacheCCEventFixture() map[string]any {
	now := time.Date(2026, 11, 3, 4, 0, 0, 123456000, time.UTC)
	return map[string]any{"epoch": now.Unix(), "epoch_us": now.UnixMicro(), "status": 429, "site_id": strings.Repeat("a", 32), "site": "owned.localhost", "ip": "::ffff:203.0.113.7", "peer": "127.0.0.1", "method": "GET", "path": `/literal\x25`, "reason": "cc", "action": "block"}
}

func TestApacheCCReaderPreservesNativeEscapesPrivacyAndActualOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	first := apacheCCEventFixture()
	second := apacheCCEventFixture()
	second["action"] = "observe"
	second["status"] = 200
	second["path_truncated"] = true
	b1, _ := json.Marshal(first)
	b2, _ := json.Marshal(second)
	data := append(append(append([]byte{}, b1...), '\n'), append(b2, '\n')...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	page, exists, err := readApacheCCEventsAt(path, os.Geteuid(), os.Getegid())
	if err != nil || !exists || len(page.Events) != 2 || !page.MetadataBestEffort || page.HasMore {
		t.Fatal(page, exists, err)
	}
	if page.Events[0].Rate != "REJECTED_DRY_RUN" || page.Events[1].Rate != "REJECTED" || !page.Events[0].PathTruncated || page.Events[0].IP != "203.0.113.7" || page.Events[0].Path != first["path"] || page.Events[0].Time != "2026-11-03T04:00:00.123456Z" {
		t.Fatal("native JSON was treated as legacy C escapes or relabeled", page.Events)
	}
	after, _ := os.ReadFile(path)
	if sha256.Sum256(after) != sha256.Sum256(data) {
		t.Fatal("read-only report changed original log bytes")
	}
	for name, mutate := range map[string]func(map[string]any){"cookie": func(v map[string]any) { v["cookie"] = "private" }, "wrong-reason": func(v map[string]any) { v["reason"] = "arbitrary" }, "wrong-action": func(v map[string]any) { v["action"] = "allow" }, "wrong-clock": func(v map[string]any) { v["epoch_us"] = 1 }, "invalid-IP": func(v map[string]any) { v["ip"] = "client.invalid" }} {
		t.Run(name, func(t *testing.T) {
			v := apacheCCEventFixture()
			mutate(v)
			b, _ := json.Marshal(v)
			b = append(b, '\n')
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			page, _, err := readApacheCCEventsAt(path, os.Geteuid(), os.Getegid())
			if err != nil || len(page.Events) != 0 || !page.HasMore {
				t.Fatal("private or malformed native event exposed as verified", page, err)
			}
		})
	}
}

func TestApacheCCReaderRefusesUnsafeFilesWithoutAdoption(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "events.log")
	line, _ := json.Marshal(apacheCCEventFixture())
	line = append(line, '\n')
	if err := os.WriteFile(path, line, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readApacheCCEventsAt(path, os.Geteuid()+1, os.Getegid()); err == nil {
		t.Fatal("another owner adopted")
	}
	if _, _, err := readApacheCCEventsAt(path, os.Geteuid(), os.Getegid()+1); err == nil {
		t.Fatal("another group adopted")
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readApacheCCEventsAt(path, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("public/private permission mismatch adopted")
	}
	_ = os.Chmod(path, 0600)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readApacheCCEventsAt(alias, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("symlink followed")
	}
	_ = os.Remove(alias)
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readApacheCCEventsAt(path, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("hardlinked log adopted")
	}
	_ = os.Remove(alias)
	if err := syscall.Mkfifo(alias, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readApacheCCEventsAt(alias, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("FIFO accepted")
	}
	_ = os.Remove(alias)
	if err := os.Truncate(path, apacheCCLogMaxBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readApacheCCEventsAt(path, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("oversized file adopted")
	}
	if err := os.Truncate(path, apacheCCLogMaxBytes); err != nil {
		t.Fatal(err)
	}
	page, _, err := readApacheCCEventsAt(path, os.Geteuid(), os.Getegid())
	if err != nil || !page.HasMore || !page.CCLogCapacityNearLimit {
		t.Fatal("capacity or incomplete-tail warning absent", page, err)
	}
}
