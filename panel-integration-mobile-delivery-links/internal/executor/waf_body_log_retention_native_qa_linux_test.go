//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Only the outer isolated managed-site gate calls this. Original dormant logs
// have already been moved to a private backup and are restored by that gate.
// Dates on owned snapshots are an explicit expiration fixture, not a claim
// that thirty days elapsed. Log rows must come from actual native requests.
func wafRetentionManagedNativeQA(t *testing.T, s *Service, site, domain, backup string) {
	t.Helper()
	ctx := context.Background()
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil || manifest.Version != core.WAFVersion || cfg.Body == nil || len(cfg.Body.Sites) != 1 || cfg.Body.Sites[0].SiteID != site || cfg.Body.Sites[0].Policy.Mode != "block" || cfg.BodyLogRetention != nil {
		t.Fatal("unbound native retention scope", err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	marker := "private_retention_" + core.ID()
	visit := func() {
		req, _ := http.NewRequest("POST", "http://127.0.0.1:19101/probe", strings.NewReader(`{"term":"<script>alert('`+marker+`')</script>"}`))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "203.0.113.42")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("real native retention traffic", err)
		}
		_, e := io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		res.Body.Close()
		if e != nil || res.StatusCode != 403 {
			t.Fatal("native body enforcement lost", res.StatusCode, e)
		}
	}
	initial, err := s.wafBodyLogArchives()
	if err != nil || len(initial) != 1 {
		t.Fatal("expected only owned automatic-rotation snapshot", initial, err)
	}
	for i := 0; i < 2; i++ {
		visit()
		if _, err := s.snapshotAndTruncateWAFBodyLog(ctx); err != nil {
			t.Fatal(err)
		}
	}
	inventory, err := s.wafBodyRetentionInventory(ctx)
	if err != nil || len(inventory) != 3 {
		t.Fatal(inventory, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range inventory {
		item.Archive.CapturedAt = now.Add(-time.Duration(38+i) * 24 * time.Hour).Format(time.RFC3339)
		if err := s.writeWAFBodyLogIndex(ctx, item.Archive); err != nil {
			lock.Close()
			t.Fatal(err)
		}
	}
	lock.Close()
	rotationDisabled := core.DefaultWAFBodyLogRotation()
	cfg.BodyLogRotation = &rotationDisabled
	cfg.BodyLogRetention = &core.WAFBodyLogRetentionConfig{Enabled: true, ConfirmDelete: true, Days: 30, KeepLatest: 1}
	if err := wafNativeRetryLockBusy(ctx, func() error {
		return s.applyWAF(ctx, core.WAFSettings(cfg), false, func(string) {})
	}); err != nil {
		t.Fatal("actual native engine retention policy apply", err)
	}
	visit()
	live, err := os.ReadFile(wafBodyLogPath)
	liveInfo, statErr := os.Stat(wafBodyLogPath)
	if err != nil || statErr != nil || len(live) == 0 || bytes.Contains(live, []byte(marker)) {
		t.Fatal("native numerical log missing or private request leaked", err, statErr)
	}
	inventory, err = s.wafBodyRetentionInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nativeBefore := wafQANativeProtectedSnapshot(t)
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); s.runWAFBodyLogRetentionWorker(workerCtx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("retention worker did not stop before original restoration")
		}
	}()
	var completed wafBodyRetentionRecord
	for deadline := time.Now().Add(20 * time.Second); ; {
		completed, _, err = s.readWAFBodyRetentionRecord()
		if err == nil && completed.Operation != nil && completed.Operation.State == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real retention worker startup did not complete", completed, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(completed.Operation.Deleted) != 2 || len(completed.History) != 0 {
		t.Fatal("native cleanup progress mismatch", completed)
	}
	remaining, err := s.wafBodyRetentionInventory(ctx)
	if err != nil || len(remaining) != 1 || remaining[0] != inventory[0] {
		t.Fatal("protected native snapshot changed", remaining, err)
	}
	current, readErr := os.ReadFile(wafBodyLogPath)
	currentInfo, statErr := os.Stat(wafBodyLogPath)
	if readErr != nil || statErr != nil || !bytes.Equal(live, current) || !os.SameFile(liveInfo, currentInfo) || liveInfo.Mode() != currentInfo.Mode() {
		t.Fatal("native retention changed active writer file", readErr, statErr)
	}
	var tick wafBodyRetentionRecord
	for deadline := time.Now().Add(80 * time.Second); ; {
		tick, _, err = s.readWAFBodyRetentionRecord()
		checked, _ := time.Parse(time.RFC3339, tick.CheckedAt)
		first, _ := time.Parse(time.RFC3339, completed.CheckedAt)
		if err == nil && checked.Sub(first) >= 55*time.Second {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real retention minute tick not observed", tick, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !reflect.DeepEqual(tick.Operation, completed.Operation) || len(tick.History) != 0 {
		t.Fatal("minute tick replayed original deletion", tick)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("native retention worker failed to retire")
	}
	var oldNative, nextNative map[string]string
	if json.Unmarshal([]byte(nativeBefore), &oldNative) != nil || json.Unmarshal([]byte(wafQANativeProtectedSnapshot(t)), &nextNative) != nil {
		t.Fatal("invalid native preservation inventory")
	}
	recordBytes, err := os.ReadFile(s.wafBodyRetentionPath())
	if err != nil || nextNative[s.wafBodyRetentionPath()] != core.Hash(string(recordBytes)) {
		t.Fatal("actual retention record not included in preservation inventory", err)
	}
	delete(oldNative, s.wafBodyRetentionPath())
	delete(nextNative, s.wafBodyRetentionPath())
	oldJSON, _ := json.Marshal(oldNative)
	nextJSON, _ := json.Marshal(nextNative)
	if changed, okay := wafQANativeChanges(string(oldJSON), string(nextJSON)); !okay {
		t.Fatal("native retention signaled/reloaded or changed other config", changed)
	}
	current, readErr = os.ReadFile(wafBodyLogPath)
	if readErr != nil || !bytes.Equal(live, current) {
		t.Fatal("minute tick changed current log", readErr)
	}
	remaining, err = s.wafBodyRetentionInventory(ctx)
	if err != nil || len(remaining) != 1 || remaining[0] != inventory[0] {
		t.Fatal("minute tick changed latest snapshot", err)
	}
	visit()
	resumed, err := os.ReadFile(wafBodyLogPath)
	resumedInfo, statErr := os.Stat(wafBodyLogPath)
	if err != nil || statErr != nil || len(resumed) <= len(live) || !os.SameFile(liveInfo, resumedInfo) || bytes.Contains(resumed, []byte(marker)) {
		t.Fatal("native writer failed to resume privately", err, statErr)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(resumed), []byte{'\n'}) {
		if _, okay := parseWAFBodyEvent(line); !okay {
			t.Fatal("non-numeric native retention event")
		}
	}
	if err := moduleWrite(filepath.Join(backup, "automatic-rotation-native-qa", "retention-acceptance.json"), map[string]any{
		"passed": true, "source_candidate_only": true, "signed_release_acceptance": false, "direct_signed_API_business_proof": false,
		"actual_native_requests_verified": true, "expiration_dates_explicitly_aged_on_owned_QA_indices": true, "not_thirty_days_elapsed": true,
		"real_clock_production_worker_startup_and_minute_tick": true, "completed": completed, "minute_tick": tick, "protected_latest_identity_preserved": true,
		"current_log_bytes_and_inode_preserved_during_cleanup": true, "native_writer_resumed_HTTP403": true, "no_native_reload_or_signal_during_cleanup": true,
		"original_dormant_evidence_restored_by_outer_gate": true,
	}); err != nil {
		t.Fatal(err)
	}
}
