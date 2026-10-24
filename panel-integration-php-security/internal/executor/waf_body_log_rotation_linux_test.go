//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func wafRotationTestConfig() core.WAFConfig {
	cfg := core.DefaultWAFConfig()
	cfg.Body = &core.WAFBodyConfig{EngineJobID: strings.Repeat("a", 32), Sites: []core.WAFBodySitePolicy{}}
	cfg.BodyLogRotation = &core.WAFBodyLogRotationConfig{Enabled: true, RotateMiB: 1, MaxAgeMinutes: 10}
	return cfg
}

func runRotationFixture(t *testing.T, s *Service, cfg core.WAFConfig, now time.Time, checkpoint func(string) error) (wafBodyRotationRecord, error) {
	t.Helper()
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	return s.runWAFBodyRotationLocked(context.Background(), now, lock, cfg, func(string) (wafBodyLogArchive, error) {
		return s.snapshotAndTruncateWAFBodyLogAt(context.Background(), checkpoint)
	})
}

func TestWAFBodyAutomaticRotationPersistsWindowSameInodeAndNeverReloads(t *testing.T) {
	s, path, row := wafBodyLogFixture(t)
	cfg := wafRotationTestConfig()
	now := time.Now().UTC().Truncate(time.Second)
	data := bytes.Repeat(row, (1<<20)/len(row)+1)
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	first, err := runRotationFixture(t, s, cfg, now, nil)
	if err != nil || first.State != "completed" || first.Archive == nil || first.Archive.SHA256 != core.Hash(string(data)) || len(first.History) != 1 {
		t.Fatal(first, err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) || after.Size() != 0 || after.Mode() != before.Mode() {
		t.Fatal("active writer inode or permissions lost")
	}
	if err := os.WriteFile(path, row, 0640); err != nil {
		t.Fatal(err)
	}
	fresh := New(s.Config)
	idle, err := runRotationFixture(t, fresh, cfg, now.Add(9*time.Minute), nil)
	if err != nil || idle.State != "idle" || idle.WindowStartedAt != first.WindowStartedAt {
		t.Fatal("restart reset durable window", idle, err)
	}
	second, err := runRotationFixture(t, New(s.Config), cfg, now.Add(10*time.Minute), nil)
	if err != nil || second.State != "completed" || second.ArchiveCount != 2 || len(second.History) != 2 || second.ID == first.ID {
		t.Fatal(second, err)
	}
	current, _ := os.Stat(path)
	if !os.SameFile(before, current) || current.Size() != 0 {
		t.Fatal("age rotation replaced active inode")
	}
	archives, err := s.wafBodyLogArchives()
	if err != nil || len(archives) != 2 {
		t.Fatal(archives, err)
	}
	for _, a := range archives {
		if a.State != "completed" {
			t.Fatal("automatic rotation fabricated completion", a)
		}
	}
}

func TestWAFBodyAutomaticRotationCapacityNeverDeletesEvidence(t *testing.T) {
	s, path, row := wafBodyLogFixture(t)
	for i := 0; i < wafBodyLogArchiveLimit; i++ {
		if err := os.WriteFile(path, row, 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := s.snapshotAndTruncateWAFBodyLog(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	archives, _ := s.wafBodyLogArchives()
	data := bytes.Repeat(row, (1<<20)/len(row)+1)
	_ = os.WriteFile(path, data, 0640)
	out, err := runRotationFixture(t, s, wafRotationTestConfig(), time.Now().UTC(), func(string) error { t.Fatal("capacity called truncate primitive"); return nil })
	if err != nil || out.State != "blocked" || out.ErrorCode != "archive_capacity" {
		t.Fatal(out, err)
	}
	after, _ := s.wafBodyLogArchives()
	b, _ := json.Marshal(archives)
	a, _ := json.Marshal(after)
	current, _ := os.ReadFile(path)
	if !bytes.Equal(b, a) || !bytes.Equal(current, data) {
		t.Fatal("capacity pruned evidence or live log")
	}
}

func TestWAFBodyAutomaticRotationSameSizeCorruptionNeverCompletesOrRepeats(t *testing.T) {
	s, path, row := wafBodyLogFixture(t)
	cfg := wafRotationTestConfig()
	now := time.Now().UTC().Truncate(time.Second)
	data := bytes.Repeat(row, (1<<20)/len(row)+1)
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	changed := false
	out, err := runRotationFixture(t, s, cfg, now, func(at string) error {
		if at != "completed-durable" {
			return nil
		}
		files, err := filepath.Glob(filepath.Join(s.wafBodyLogArchiveDirectory(), "*.log"))
		if err != nil || len(files) != 1 {
			t.Fatal("unexpected fixture snapshot", files, err)
		}
		copy := append([]byte{}, data...)
		copy[0] ^= 1
		if err := os.WriteFile(files[0], copy, 0600); err != nil {
			t.Fatal(err)
		}
		changed = true
		return nil
	})
	if !changed || err == nil || out.State != "unknown" || out.ErrorCode != "verification_failed" || len(out.History) != 0 || out.LastRotationAt != "" {
		t.Fatal("same-size corrupted snapshot falsely completed", out, err)
	}
	before, _ := os.ReadFile(path)
	record, _ := os.ReadFile(s.wafBodyRotationPath())
	if _, err := runRotationFixture(t, New(s.Config), cfg, now.Add(time.Minute), func(string) error { t.Fatal("corruption repeated truncate"); return nil }); err == nil {
		t.Fatal("unknown automatic result accepted")
	}
	after, _ := os.ReadFile(path)
	next, _ := os.ReadFile(s.wafBodyRotationPath())
	if !bytes.Equal(before, after) || !bytes.Equal(record, next) {
		t.Fatal("corruption recovery overwrote evidence")
	}
}

func TestWAFBodyAutomaticRotationSixFailuresNeverRepeatOrInventSuccess(t *testing.T) {
	for _, cut := range []string{"intent-durable", "snapshot-created", "snapshot-durable", "prepared-durable", "truncate-durable", "completed-durable"} {
		t.Run(cut, func(t *testing.T) {
			s, path, row := wafBodyLogFixture(t)
			cfg := wafRotationTestConfig()
			now := time.Now().UTC().Truncate(time.Second)
			data := bytes.Repeat(row, (1<<20)/len(row)+1)
			_ = os.WriteFile(path, data, 0640)
			unknown, err := runRotationFixture(t, s, cfg, now, func(at string) error {
				if at == cut {
					return errors.New("owned interruption")
				}
				return nil
			})
			if err == nil || unknown.State != "unknown" || unknown.Archive == nil || len(unknown.History) != 0 {
				t.Fatal(unknown, err)
			}
			live, _ := os.ReadFile(path)
			recordBefore, _ := os.ReadFile(s.wafBodyRotationPath())
			if err := s.wafBodyLogHealth(context.Background()); err == nil || !strings.Contains(err.Error(), "自动轮转结果仍未知") {
				t.Fatal("unknown scheduler outcome falsely healthy", err)
			}
			if _, err := s.rotateWAFBodyLog(context.Background()); err == nil || !strings.Contains(err.Error(), "自动轮转结果未知") {
				t.Fatal("manual rotation bypassed unknown automatic intent", err)
			}
			fresh := New(s.Config)
			if _, err := runRotationFixture(t, fresh, cfg, now.Add(time.Minute), func(string) error { t.Fatal("unknown result automatically repeated truncate"); return nil }); err == nil {
				t.Fatal("unknown result accepted")
			}
			after, _ := os.ReadFile(path)
			recordAfter, _ := os.ReadFile(s.wafBodyRotationPath())
			if !bytes.Equal(live, after) || !bytes.Equal(recordBefore, recordAfter) {
				t.Fatal("restart mutated unknown result")
			}
			pending, err := fresh.wafBodyLogRecoveryEntries(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(pending) != 0 {
				if len(pending) != 1 {
					t.Fatal(pending)
				}
				if err := fresh.retainWAFBodyLogSnapshot(context.Background(), pending[0]); err != nil {
					t.Fatal(err)
				}
			}
			_, sha, err := fresh.readWAFBodyRotationRecord()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fresh.retainWAFBodyRotationOutcome(context.Background(), strings.Repeat("0", 64), now.Add(time.Minute)); err == nil {
				t.Fatal("stale digest accepted")
			}
			retained, err := fresh.retainWAFBodyRotationOutcome(context.Background(), sha, now.Add(time.Minute))
			if err != nil || retained.State != "retained_unknown" || len(retained.History) != 1 || retained.History[0].Outcome != "unknown_retained" || retained.LastRotationAt != "" {
				t.Fatal("unknown result falsely completed", retained, err)
			}
			current, _ := os.ReadFile(path)
			if !bytes.Equal(live, current) {
				t.Fatal("retention double-truncated live data")
			}
			if _, err := fresh.retainWAFBodyRotationOutcome(context.Background(), sha, now.Add(time.Minute)); err == nil {
				t.Fatal("old retention request replay silently overwrote current state")
			}
		})
	}
}

func TestWAFBodyAutomaticRotationStatusRefusesCorruptManifestAndClosedRetain(t *testing.T) {
	s, path, row := wafBodyLogFixture(t)
	get := func(target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		return w
	}
	base := "/v1/software/nginx-waf/body-log/rotation"
	if w := get(base); w.Code != 200 || !strings.Contains(w.Body.String(), `"available":false`) {
		t.Fatal("no record reported available", w.Code, w.Body.String())
	}
	if w := get(base + "?force=true"); w.Code != 400 {
		t.Fatal("status query injection", w.Code)
	}
	if err := os.MkdirAll(s.Config.SecurityDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.softwareManifestPath("nginx-waf"), []byte(`{"id":"nginx-waf","settings":{"unknown":true}}`), 0640); err != nil {
		t.Fatal(err)
	}
	if w := get(base); w.Code != 503 {
		t.Fatal("corrupt actual policy reported disabled instead of unverified", w.Code, w.Body.String())
	}
	valid := `{"sha256":"` + strings.Repeat("a", 64) + `","acknowledge_unknown_rotation_not_repeated":true}`
	for _, body := range []string{`null`, `{}`, strings.TrimSuffix(valid, "}") + `,"sha256":null}`, strings.TrimSuffix(valid, "}") + `,"path":"/etc/shadow"}`, valid + ` {}`} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", base+"/retain", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal("unclosed privileged retention", w.Code, w.Body.String())
		}
	}
	actual, _ := os.ReadFile(path)
	if !bytes.Equal(actual, row) {
		t.Fatal("status/rejected retention changed live log")
	}
	if _, err := os.Lstat(s.wafBodyRotationPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read status created a record", err)
	}
}

func TestWAFBodyAutomaticRotationHistoryNeverDropsUnknownEvidence(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	record := wafBodyRotationRecord{History: []wafBodyRotationOutcome{}}
	for i := 0; i < wafBodyRotationHistoryLimit; i++ {
		record.History = append(record.History, wafBodyRotationOutcome{ID: core.ID(), At: now, Outcome: "unknown_retained"})
	}
	before, _ := json.Marshal(record.History)
	if err := appendWAFRotationOutcome(&record, wafBodyRotationOutcome{ID: core.ID(), At: now, Outcome: "unknown_retained"}); err == nil {
		t.Fatal("full unknown history silently pruned")
	}
	after, _ := json.Marshal(record.History)
	if !bytes.Equal(before, after) {
		t.Fatal("capacity mutated unknown evidence")
	}
}

func TestWAFBodyAutomaticRotationPausedEngineStillRequiresNativeVerification(t *testing.T) {
	s := wafPolicyFixture(t)
	cfg := wafRotationTestConfig()
	if err := s.verifyWAFBodyEngine(cfg); err == nil {
		t.Fatal("paused invented engine accepted for automatic rotation")
	}
	cfg.BodyLogRotation.Enabled = false
	if err := s.verifyWAFBodyEngine(cfg); err != nil {
		t.Fatal("disabled rotation unexpectedly activates paused engine", err)
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := s.rotateWAFBodyLogWithIntent(context.Background(), lock, core.ID()); err == nil || !strings.Contains(err.Error(), "持久意图身份") {
		t.Fatal("nonexistent intent accepted", err)
	}
}

func TestWAFBodyAutomaticRotationDisabledOrAbsentNeverCreatesWorkerState(t *testing.T) {
	for _, kind := range []string{"absent", "nil", "disabled", "old-version"} {
		t.Run(kind, func(t *testing.T) {
			s := wafPolicyFixture(t)
			cfg := core.DefaultWAFConfig()
			version := core.WAFVersion
			if kind == "disabled" {
				v := core.DefaultWAFBodyLogRotation()
				cfg.BodyLogRotation = &v
			}
			if kind == "old-version" {
				cfg = wafRotationTestConfig()
				version = "2.3.0"
			}
			if kind != "absent" {
				if err := os.MkdirAll(s.Config.SecurityDir, 0750); err != nil {
					t.Fatal(err)
				}
				v := softwareManifest{ID: "nginx-waf", Version: version, InstalledAt: core.Now(), Settings: core.WAFSettings(cfg)}
				data, _ := json.Marshal(v)
				if err := os.WriteFile(s.softwareManifestPath("nginx-waf"), data, 0640); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.runWAFBodyLogRotationOnce(context.Background(), time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{s.wafBodyRotationPath(), s.systemPath(wafBodyLogPath), filepath.Join(s.Config.SecurityDir, "waf-configuration.lock")} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("default/old policy caused worker mutation", path, err)
				}
			}
		})
	}
}

func TestWAFBodyAutomaticRotationSharedLockAndUnsafeRecordRefused(t *testing.T) {
	s, path, row := wafBodyLogFixture(t)
	cfg := wafRotationTestConfig()
	now := time.Now().UTC()
	shared, err := s.lockWAFObservation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.runWAFBodyRotationLocked(context.Background(), now, shared, cfg, func(string) (wafBodyLogArchive, error) {
		t.Fatal("shared observation impersonated an exclusive writer")
		return wafBodyLogArchive{}, nil
	}); err == nil {
		t.Fatal("shared lock accepted")
	}
	shared.Close()
	if _, err := runRotationFixture(t, s, cfg, now, nil); err != nil {
		t.Fatal(err)
	}
	valid, _ := os.ReadFile(s.wafBodyRotationPath())
	for _, kind := range []string{"world-readable", "hard-link", "extra-json", "invalid-time", "unknown-field", "null-history", "null-bytes", "duplicate-field"} {
		t.Run(kind, func(t *testing.T) {
			_ = os.WriteFile(s.wafBodyRotationPath(), valid, 0600)
			_ = os.Chmod(s.wafBodyRotationPath(), 0600)
			link := s.wafBodyRotationPath() + ".owned-link"
			switch kind {
			case "world-readable":
				_ = os.Chmod(s.wafBodyRotationPath(), 0644)
			case "hard-link":
				if err := os.Link(s.wafBodyRotationPath(), link); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(link)
			case "extra-json":
				_ = os.WriteFile(s.wafBodyRotationPath(), append(append([]byte{}, valid...), []byte(" {}")...), 0600)
			case "invalid-time":
				_ = os.WriteFile(s.wafBodyRotationPath(), bytes.Replace(valid, []byte(now.UTC().Format(time.RFC3339)), []byte("invalid"), 1), 0600)
			case "unknown-field":
				_ = os.WriteFile(s.wafBodyRotationPath(), append([]byte("{\"prune\":true,"), bytes.TrimSpace(valid)[1:]...), 0600)
			case "null-history":
				_ = os.WriteFile(s.wafBodyRotationPath(), bytes.Replace(valid, []byte("\"history\": []"), []byte("\"history\": null"), 1), 0600)
			case "null-bytes":
				_ = os.WriteFile(s.wafBodyRotationPath(), bytes.Replace(valid, []byte("\"log_bytes\": "+fmt.Sprint(len(row))), []byte("\"log_bytes\": null"), 1), 0600)
			case "duplicate-field":
				_ = os.WriteFile(s.wafBodyRotationPath(), append([]byte("{\"log_bytes\":0,"), bytes.TrimSpace(valid)[1:]...), 0600)
			}
			before, _ := os.ReadFile(s.wafBodyRotationPath())
			if _, err := runRotationFixture(t, s, cfg, now.Add(time.Hour), nil); err == nil {
				t.Fatal("unsafe persistent record accepted", kind)
			}
			after, _ := os.ReadFile(s.wafBodyRotationPath())
			data, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) || !bytes.Equal(data, row) {
				t.Fatal("rejection overwrote record or truncated log")
			}
		})
	}
}

func TestWAFBodyAutomaticRotationCancellationDoesNotCreateIntent(t *testing.T) {
	s, path, row := wafBodyLogFixture(t)
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.runWAFBodyRotationLocked(ctx, time.Now().UTC(), lock, wafRotationTestConfig(), func(string) (wafBodyLogArchive, error) {
		t.Fatal("cancelled cycle entered truncate")
		return wafBodyLogArchive{}, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s.wafBodyRotationPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled cycle created durable intent", err)
	}
	actual, _ := os.ReadFile(path)
	if !bytes.Equal(actual, row) {
		t.Fatal("cancelled cycle changed current log")
	}
}

func TestWAFBodyRotationOmittedPolicyReplayAndLegacyMigration(t *testing.T) {
	s := wafPolicyFixture(t)
	cfg := core.DefaultWAFConfig()
	rotation := core.DefaultWAFBodyLogRotation()
	cfg.BodyLogRotation = &rotation
	if err := s.applyWAF(context.Background(), core.WAFSettings(cfg), true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	manifest, _ := s.readSoftwareManifest("nginx-waf")
	cfg, _ = core.DecodeWAFConfig(manifest.Settings)
	raw := core.WAFSettings(cfg)
	delete(raw, "body_log_rotation")
	raw["profile"] = "strict"
	for i := 0; i < 2; i++ {
		if err := s.applyWAF(context.Background(), raw, false, func(string) {}); err != nil {
			t.Fatal("omitted rotation/replay", err)
		}
	}
	manifest, _ = s.readSoftwareManifest("nginx-waf")
	cfg, _ = core.DecodeWAFConfig(manifest.Settings)
	if cfg.BodyLogRotation == nil || *cfg.BodyLogRotation != rotation || cfg.Policy.Revision != 2 {
		t.Fatal("omission erased rotation or replay bumped revision", cfg)
	}
	if _, err := s.prepareWAFSettings(map[string]any{"body_log_rotation": core.WAFSettings(cfg)["body_log_rotation"]}, false); err == nil {
		t.Fatal("unrevisioned rotation accepted")
	}
	old, previous := wafLegacyVersionFixture(t, "2.3.0")
	prior, _ := old.readSoftwareManifest("nginx-waf")
	main, _ := os.ReadFile(old.Config.NginxConf)
	invalid := core.WAFSettings(previous)
	invalid["body_log_rotation"] = core.WAFSettings(cfg)["body_log_rotation"]
	if _, err := old.prepareWAFSettings(invalid, false); err == nil {
		t.Fatal("legacy installed package advertised rotation")
	}
	if err := old.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {}); err != nil {
		t.Fatal("actual 2.3 migration", err)
	}
	after, _ := old.readSoftwareManifest("nginx-waf")
	got, err := core.DecodeWAFConfig(after.Settings)
	previous.Policy.Revision++
	want, _ := json.Marshal(previous)
	actual, _ := json.Marshal(got)
	nowMain, _ := os.ReadFile(old.Config.NginxConf)
	if err != nil || !bytes.Equal(want, actual) || got.BodyLogRotation != nil || after.InstalledAt != prior.InstalledAt || !bytes.Equal(main, nowMain) {
		t.Fatal("version migration opted into rotation or lost existing configuration", after, err)
	}
}
