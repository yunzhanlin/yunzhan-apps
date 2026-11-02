//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func apacheRotationFixture(t *testing.T) (*Service, string, []byte, core.WAFConfig, time.Time) {
	t.Helper()
	s, live, row := apacheNumericLogFixture(t)
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	now := time.Now().UTC().Truncate(time.Second)
	record := apacheNumericRotationRecord{Format: 1, ConfigRevision: 1, Policy: core.WAFBodyLogRotationConfig{Enabled: true, RotateMiB: 1, MaxAgeMinutes: 10}, ID: core.ID(), State: "idle", WindowStartedAt: now.Format(time.RFC3339), CheckedAt: now.Format(time.RFC3339), History: []apacheNumericRotationOutcome{}}
	if err = s.writeApacheNumericRotationRecord(record); err != nil {
		t.Fatal(err)
	}
	cfg := core.DefaultApacheWAFConfig()
	cfg.Body = &core.WAFBodyConfig{EngineJobID: strings.Repeat("a", 32), Sites: []core.WAFBodySitePolicy{}}
	return s, live, row, cfg, now
}

func runApacheRotationFixture(t *testing.T, s *Service, cfg core.WAFConfig, now time.Time, checkpoint func(string) error) (apacheNumericRotationRecord, error) {
	t.Helper()
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	return s.runApacheNumericRotationLocked(context.Background(), now, lock, cfg, func(intent string) (apacheNumericLogArchive, error) {
		if err := s.apacheNumericRotationFence(context.Background(), intent); err != nil {
			return apacheNumericLogArchive{}, err
		}
		return s.snapshotAndTruncateApacheNumericLogAt(context.Background(), checkpoint)
	})
}

func TestApacheNumericAutomaticWindowSameInodeAndServiceFreeMaintenance(t *testing.T) {
	s, live, row, cfg, now := apacheRotationFixture(t)
	before, _ := os.Stat(live)
	calls := 0
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		calls++
		return "", errors.New("no service commands allowed")
	}
	initial, err := runApacheRotationFixture(t, s, cfg, now.Add(9*time.Minute), nil)
	if err != nil || initial.State != "idle" {
		t.Fatal(initial, err)
	}
	completed, err := runApacheRotationFixture(t, s, cfg, now.Add(10*time.Minute), nil)
	if err != nil || completed.State != "completed" || completed.Archive == nil || len(completed.History) != 1 {
		t.Fatal(completed, err)
	}
	after, _ := os.Stat(live)
	if !os.SameFile(before, after) || after.Size() != 0 || before.Mode() != after.Mode() || calls != 0 {
		t.Fatal("live identity or services changed")
	}
	copy, err := os.ReadFile(filepath.Join(s.apacheNumericLogArchiveDirectory(), completed.Archive.ID+".log"))
	if err != nil || !bytes.Equal(copy, row) {
		t.Fatal("snapshot bytes", err)
	}
	again, err := runApacheRotationFixture(t, s, cfg, now.Add(11*time.Minute), nil)
	if err != nil || again.State != "idle" || again.LastRotationAt != completed.LastRotationAt || again.WindowStartedAt != completed.WindowStartedAt || len(again.History) != 1 {
		t.Fatal("window or history reset", again, err)
	}
}

func TestApacheNumericAutomaticSizeAndCapacityPreserveAllEvidence(t *testing.T) {
	s, live, row, cfg, now := apacheRotationFixture(t)
	data := bytes.Repeat(row, (1<<20)/len(row)+1)
	if err := os.WriteFile(live, data, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runApacheRotationFixture(t, s, cfg, now, nil)
	if err != nil || out.State != "completed" || out.Archive.Bytes != int64(len(data)) {
		t.Fatal(out, err)
	}
	for i := 1; i < apacheNumericLogArchiveLimit; i++ {
		if err = os.WriteFile(live, row, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = s.snapshotAndTruncateApacheNumericLog(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(live, data, 0600); err != nil {
		t.Fatal(err)
	}
	original, _ := s.apacheNumericLogArchives()
	out, err = runApacheRotationFixture(t, s, cfg, now.Add(time.Minute), nil)
	if err != nil || out.State != "blocked" || out.ErrorCode != "archive_capacity" {
		t.Fatal(out, err)
	}
	after, _ := os.ReadFile(live)
	if !bytes.Equal(after, data) {
		t.Fatal("full capacity truncated current log")
	}
	rows, err := s.apacheNumericLogArchives()
	if err != nil || len(rows) != len(original) {
		t.Fatal("archive inventory changed", err)
	}
	for _, entry := range original {
		path := filepath.Join(s.apacheNumericLogArchiveDirectory(), entry.ID+".log")
		if digest, e := wafNativeFileSHA(context.Background(), path, apacheNumericLogLimit); e != nil || digest != entry.SHA256 {
			t.Fatal("evidence deleted or changed", e)
		}
	}
}

func TestApacheNumericAutomaticSixFaultsNeverReplayOrInventCompletion(t *testing.T) {
	for _, cut := range []string{"intent-durable", "snapshot-created", "snapshot-durable", "prepared-durable", "truncate-durable", "completed-durable"} {
		t.Run(cut, func(t *testing.T) {
			s, live, row, cfg, now := apacheRotationFixture(t)
			fault := errors.New("owned automatic interruption")
			out, err := runApacheRotationFixture(t, s, cfg, now.Add(10*time.Minute), func(stage string) error {
				if stage == cut {
					return fault
				}
				return nil
			})
			if !errors.Is(err, fault) || out.State != "unknown" || len(out.History) != 0 {
				t.Fatal("fault not preserved as unknown", out, err)
			}
			current, _ := os.ReadFile(live)
			truncated := cut == "truncate-durable" || cut == "completed-durable"
			if truncated && len(current) != 0 || !truncated && !bytes.Equal(current, row) {
				t.Fatal("unexpected truncate point")
			}
			record, _ := os.ReadFile(s.apacheNumericRotationPath())
			attempted := false
			lock, e := s.lockWAFConfiguration()
			if e != nil {
				t.Fatal(e)
			}
			_, e = s.runApacheNumericRotationLocked(context.Background(), now.Add(20*time.Minute), lock, cfg, func(string) (apacheNumericLogArchive, error) { attempted = true; return apacheNumericLogArchive{}, nil })
			lock.Close()
			if e == nil || attempted {
				t.Fatal("automatic uncertain operation replayed", e)
			}
			if e = s.apacheNumericRotationFence(context.Background(), ""); e == nil {
				t.Fatal("manual/upgrade/config fence bypassed")
			}
			if _, e = s.retainApacheNumericRotationOutcome(context.Background(), strings.Repeat("0", 64), now.Add(20*time.Minute)); e == nil {
				t.Fatal("wrong digest adopted")
			}
			after, _ := os.ReadFile(s.apacheNumericRotationPath())
			if !bytes.Equal(record, after) {
				t.Fatal("uncertain evidence rewritten")
			}
			if cut == "completed-durable" {
				_, digest, e := s.readApacheNumericRotationRecord()
				if e != nil {
					t.Fatal(e)
				}
				retained, e := s.retainApacheNumericRotationOutcome(context.Background(), digest, now.Add(20*time.Minute))
				if e != nil || retained.State != "retained_unknown" || len(retained.History) != 1 || retained.History[0].Outcome != "unknown_retained" {
					t.Fatal("explicit retention fabricated success", retained, e)
				}
			}
		})
	}
}

func TestApacheNumericAutomaticCancelClockLockAndStrictRecordRefusal(t *testing.T) {
	s, live, _, cfg, now := apacheRotationFixture(t)
	original, _ := os.ReadFile(s.apacheNumericRotationPath())
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err = s.runApacheNumericRotationLocked(ctx, now, lock, cfg, func(string) (apacheNumericLogArchive, error) { called = true; return apacheNumericLogArchive{}, nil })
	lock.Close()
	if !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled operation started", err)
	}
	if _, err = runApacheRotationFixture(t, s, cfg, now.Add(-2*time.Minute), nil); err == nil {
		t.Fatal("backwards clock adopted")
	}
	writer, err := os.OpenFile(live, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err = syscall.Flock(int(writer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	out, err := runApacheRotationFixture(t, s, cfg, now.Add(10*time.Minute), nil)
	if err == nil || out.State != "unknown" {
		t.Fatal("BSD writer exclusion bypassed", out, err)
	}
	// Use a fresh private fixture for malformed records, never edit an uncertain
	// original merely to make the next test eligible.
	fresh, _, _, _, _ := apacheRotationFixture(t)
	for _, raw := range [][]byte{[]byte("null"), bytes.Replace(original, []byte(`"format": 1`), []byte(`"format": 1,"format":1`), 1), bytes.Replace(original, []byte(`"enabled": true`), []byte(`"enabled": null`), 1)} {
		if err = os.WriteFile(fresh.apacheNumericRotationPath(), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err = fresh.readApacheNumericRotationRecord(); err == nil {
			t.Fatal("malformed private record adopted", string(raw))
		}
	}
}

func TestApacheNumericAutomationAbsentDisabledAndRevisionNeverClearUncertainty(t *testing.T) {
	s, _, _ := apacheNumericLogFixture(t)
	ctx := context.Background()
	before, err := s.apacheNumericAutomationStatus(ctx)
	if err != nil || before["configured"] != false {
		t.Fatal(before, err)
	}
	if _, err = os.Lstat(s.apacheNumericRotationPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read created policy")
	}
	if err = s.runApacheNumericLogRotationOnce(ctx, time.Now()); err != nil {
		t.Fatal("isolated fixture attempted production", err)
	}
	s, _, _, _, now := apacheRotationFixture(t)
	record, _, _ := s.readApacheNumericRotationRecord()
	record.State = "unknown"
	record.ErrorCode = "rotation_failed"
	if err = s.writeApacheNumericRotationRecord(record); err != nil {
		t.Fatal(err)
	}
	request := apacheNumericAutomationRequest{ExpectedRevision: 1, Enabled: false, RotateMiB: 2, MaxAgeMinutes: 20}
	status, err := s.configureApacheNumericAutomation(ctx, request, now)
	if err != nil || status["policy_revision"] != int64(2) {
		t.Fatal(status, err)
	}
	preserved, _, _ := s.readApacheNumericRotationRecord()
	if preserved.State != "unknown" || preserved.ID != record.ID || preserved.WindowStartedAt != record.WindowStartedAt || preserved.Policy.Enabled {
		t.Fatal("disable reset uncertain evidence", preserved)
	}
	if err = s.apacheNumericLogHealthLocked(ctx); err == nil {
		t.Fatal("disabled uncertainty bypassed upgrade/config fence")
	}
	if _, err = s.configureApacheNumericAutomation(ctx, request, now); err == nil {
		t.Fatal("stale revision accepted")
	}
	request.ExpectedRevision = 2
	status, err = s.configureApacheNumericAutomation(ctx, request, now)
	if err != nil || status["policy_revision"] != int64(2) {
		t.Fatal("identical policy incremented revision", status, err)
	}
	request.Enabled = true
	if _, err = s.configureApacheNumericAutomation(ctx, request, now); err == nil {
		t.Fatal("unknown outcome re-enabled")
	}
	// Persisted policy round-trip includes a fixed complete scalar object.
	raw, _ := os.ReadFile(s.apacheNumericRotationPath())
	var decoded map[string]json.RawMessage
	if json.Unmarshal(raw, &decoded) != nil || decoded["policy"] == nil {
		t.Fatal("missing durable policy")
	}
}

func TestApacheNumericAutomationUsesActualModuleAuthorityAndPausedEngineVerification(t *testing.T) {
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.Revision = 7
	cfg.Body = &core.WAFBodyConfig{EngineJobID: core.ID(), Sites: []core.WAFBodySitePolicy{}}
	s, original := apacheNativeRecordFixture(t, core.ApacheWAFNativeBodyVersion, cfg)
	// A conflicting, otherwise well-shaped generic manifest cannot substitute
	// for the Apache module record. Removing only our fixture module must report
	// absent even while this unrelated file remains.
	foreign := filepath.Join(s.Config.SecurityDir, "apache-waf.json")
	other := core.DefaultApacheWAFConfig()
	other.Policy.Revision = 999
	data, _ := json.Marshal(map[string]any{"id": "apache-waf", "version": core.ApacheWAFNativeBodyVersion, "settings": core.WAFSettings(other)})
	if err := os.WriteFile(foreign, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, native, err := s.apacheNumericInstalledConfig()
	if err != nil || !native || got.Policy.Revision != 7 || got.Body == nil || got.Body.EngineJobID != cfg.Body.EngineJobID {
		t.Fatal("did not consume real Apache module", got, native, err)
	}
	if apacheBodyActive(got) {
		t.Fatal("fixture unexpectedly has active body sites")
	}
	if err = verifyApacheNumericRotationEngine(context.Background(), got); err == nil {
		t.Fatal("paused sites bypassed missing sealed engine")
	}
	unchanged, _ := os.ReadFile(filepath.Join(s.moduleDir("apache-waf"), "installed.json"))
	if !bytes.Equal(original, unchanged) {
		t.Fatal("reader rewrote module identity")
	}
	if err = os.Remove(filepath.Join(s.moduleDir("apache-waf"), "installed.json")); err != nil {
		t.Fatal(err)
	}
	if _, native, err = s.apacheNumericInstalledConfig(); err != nil || native {
		t.Fatal("unrelated software manifest adopted", native, err)
	}
	after, _ := os.ReadFile(foreign)
	if !bytes.Equal(after, data) {
		t.Fatal("foreign manifest changed")
	}
	legacy, _ := apacheNativeRecordFixture(t, core.ApacheWAFVersion, core.DefaultApacheWAFConfig())
	if _, native, err = legacy.apacheNumericInstalledConfig(); err != nil || native {
		t.Fatal("metadata-only app granted numerical automation", native, err)
	}
	broken, _ := apacheNativeRecordFixture(t, core.ApacheWAFNativeBodyVersion, cfg)
	if err = os.Chmod(filepath.Join(broken.moduleDir("apache-waf"), "installed.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = broken.apacheNumericInstalledConfig(); err == nil {
		t.Fatal("unsafe module authority treated as absent/default")
	}
}
