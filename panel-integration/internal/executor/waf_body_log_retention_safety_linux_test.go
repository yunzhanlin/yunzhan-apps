//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWAFBodyRetentionUnsafeRecordsRefusedWithoutChangingEvidence(t *testing.T) {
	s, path, row, cfg, now := retentionFixture(t)
	if _, err := runRetentionFixture(t, s, cfg, now, nil); err != nil {
		t.Fatal(err)
	}
	valid, _ := os.ReadFile(s.wafBodyRetentionPath())
	for _, kind := range []string{"null", "duplicate", "case", "missing-uid", "unknown", "tail", "oversize", "world-readable", "hard-link", "symbolic-link"} {
		t.Run(kind, func(t *testing.T) {
			data := append([]byte{}, valid...)
			switch kind {
			case "null":
				data = bytes.Replace(data, []byte(`"history": []`), []byte(`"history": null`), 1)
			case "duplicate":
				data = bytes.Replace(data, []byte(`"format": 1`), []byte(`"format": 1, "format": 1`), 1)
			case "case":
				data = bytes.Replace(data, []byte(`"uid":`), []byte(`"UID":`), 1)
			case "missing-uid":
				var value map[string]any
				json.Unmarshal(valid, &value)
				op := value["operation"].(map[string]any)
				items := op["plan"].(map[string]any)["inventory"].([]any)
				delete(items[0].(map[string]any), "uid")
				data, _ = json.Marshal(value)
			case "unknown":
				data = bytes.Replace(data, []byte(`"format": 1`), []byte(`"format": 1, "path":"/private"`), 1)
			case "tail":
				data = append(data, []byte(` {}`)...)
			case "oversize":
				data = append(data, bytes.Repeat([]byte(" "), wafBodyRetentionRecordLimit)...)
			}
			if err := os.WriteFile(s.wafBodyRetentionPath(), data, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "world-readable" {
				os.Chmod(s.wafBodyRetentionPath(), 0644)
			}
			link := filepath.Join(t.TempDir(), "owned-link")
			if kind == "symbolic-link" {
				if err := os.Rename(s.wafBodyRetentionPath(), link); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(link, s.wafBodyRetentionPath()); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "hard-link" {
				if err := os.Link(s.wafBodyRetentionPath(), link); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := s.readWAFBodyRetentionRecord(); err == nil {
				t.Fatal("unsafe record accepted", kind)
			}
			if _, err := runRetentionFixture(t, s, cfg, now.Add(time.Minute), func(string) error { t.Fatal("unsafe record deleted data"); return nil }); err == nil {
				t.Fatal("unsafe worker accepted")
			}
			actual, _ := os.ReadFile(s.wafBodyRetentionPath())
			live, _ := os.ReadFile(path)
			if !bytes.Equal(actual, data) || !bytes.Equal(live, row) {
				t.Fatal("evidence or current log overwritten")
			}
			if kind == "hard-link" {
				os.Remove(link)
			}
			if kind == "symbolic-link" {
				if err := os.Remove(s.wafBodyRetentionPath()); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(link, s.wafBodyRetentionPath()); err != nil {
					t.Fatal(err)
				}
			}
			os.Chmod(s.wafBodyRetentionPath(), 0600)
		})
	}
}

func TestWAFBodyRetentionDisabledAndOldVersionsNeverCreateWorkerState(t *testing.T) {
	for _, kind := range []string{"absent", "nil", "disabled", "old-version"} {
		t.Run(kind, func(t *testing.T) {
			s := wafPolicyFixture(t)
			cfg := core.DefaultWAFConfig()
			version := core.WAFVersion
			if kind == "disabled" {
				v := core.DefaultWAFBodyLogRetention()
				cfg.BodyLogRetention = &v
			}
			if kind == "old-version" {
				cfg = wafRotationTestConfig()
				cfg.BodyLogRetention = &core.WAFBodyLogRetentionConfig{Enabled: true, ConfirmDelete: true, Days: 30, KeepLatest: 1}
				version = "2.4.0"
			}
			if kind != "absent" {
				if err := os.MkdirAll(s.Config.SecurityDir, 0750); err != nil {
					t.Fatal(err)
				}
				data, _ := json.Marshal(softwareManifest{ID: "nginx-waf", Version: version, InstalledAt: core.Now(), Settings: core.WAFSettings(cfg)})
				if err := os.WriteFile(s.softwareManifestPath("nginx-waf"), data, 0640); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.runWAFBodyLogRetentionOnce(context.Background(), time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{s.wafBodyRetentionPath(), s.wafBodyLogArchiveDirectory(), filepath.Join(s.Config.SecurityDir, "waf-configuration.lock")} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("default policy mutated state", path, err)
				}
			}
		})
	}
}

func TestWAFBodyRetentionStatusAndReviewClosedInputsDoNotTouchCurrentLog(t *testing.T) {
	s, path, row := wafBodyLogFixture(t)
	base := "/v1/software/nginx-waf/body-log/retention"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", base, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"available":false`) {
		t.Fatal(w.Code, w.Body.String())
	}
	valid := `{"sha256":"` + strings.Repeat("a", 64) + `","acknowledge_unknown_deletion_not_repeated":true}`
	for _, body := range []string{`null`, `{}`, strings.Replace(valid, "sha256", "SHA256", 1), strings.TrimSuffix(valid, "}") + `,"sha256":null}`, valid + ` {}`} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", base+"/retain", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	live, _ := os.ReadFile(path)
	if !bytes.Equal(live, row) {
		t.Fatal("read/rejected request changed current log")
	}
	if _, err := os.Lstat(s.wafBodyRetentionPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("status created worker record", err)
	}
}

func TestWAFBodyRetentionCanceledMissingAndSharedLocksNeverDelete(t *testing.T) {
	for _, kind := range []string{"canceled", "missing-lock", "shared-lock"} {
		t.Run(kind, func(t *testing.T) {
			s, path, row, cfg, now := retentionFixture(t)
			before, err := s.wafBodyRetentionInventory(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			var lock *os.File
			if kind == "shared-lock" {
				lock, err = s.lockWAFObservation()
			} else if kind == "canceled" {
				lock, err = s.lockWAFConfiguration()
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			if err != nil {
				t.Fatal(err)
			}
			if lock != nil {
				defer lock.Close()
			}
			if _, err := s.runWAFBodyRetentionLocked(ctx, now, lock, cfg, func(string) error { t.Fatal("invalid context/lock started deletion"); return nil }); err == nil {
				t.Fatal("invalid context/lock accepted")
			}
			after, err := s.wafBodyRetentionInventory(context.Background())
			live, _ := os.ReadFile(path)
			if err != nil || !reflect.DeepEqual(before, after) || !bytes.Equal(live, row) {
				t.Fatal("invalid context/lock changed data", err)
			}
			if _, err := os.Lstat(s.wafBodyRetentionPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid context/lock created operation", err)
			}
		})
	}
}
