//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func geoCacheServiceFixture(t *testing.T, f *geoStoreFixture) (*Service, string) {
	t.Helper()
	security := filepath.Join(filepath.Dir(f.store.base), "cache-security")
	dir := filepath.Join(security, "modules", "website-statistics-v2")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	id := core.ID()
	raw, _ := json.Marshal(map[string]any{"id": "website-statistics-v2", "version": "2.6.0", "installation_id": id, "installed_at": "2026-10-01T00:00:00Z", "settings": map[string]any{}})
	if err := os.WriteFile(filepath.Join(dir, "installed.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	s := New(Config{SystemRoot: "/", SecurityDir: security})
	t.Cleanup(func() {
		s.geoCache.mu.Lock()
		old := s.geoCache.snapshot
		s.geoCache.snapshot = nil
		s.geoCache.mu.Unlock()
		if old != nil {
			old.Close()
		}
	})
	return s, id
}

func TestStatisticsGeoCacheColdRestartVerifiesExplicitPreviousWithoutDiskSwitch(t *testing.T) {
	f := geoStoreRootFixture(t)
	old := f.install(t, "2026-09")
	current := f.install(t, "2026-10")
	selected := filepath.Join(f.store.base, "selected.json")
	before, _ := os.ReadFile(selected)
	path := filepath.Join(f.store.base, geoStoreName(current), "database.mmdb.gz")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, id := geoCacheServiceFixture(t, f)
	s.refreshStatisticsGeoCacheStore(context.Background(), id, f.store)
	lookup, release, enabled, message := s.statisticsGeoSnapshotLease()
	if lookup == nil {
		release()
		t.Fatal("missing cold verified fallback", message)
	}
	if !enabled || lookup == nil || !strings.Contains(message, "旧库") || lookup.Lookup("8.8.8.8").City != "Synthetic 2026-09" {
		release()
		t.Fatal("cold restart failed to independently verify retained reference", message)
	}
	release()
	after, _ := os.ReadFile(selected)
	if !bytes.Equal(before, after) || f.selected(t).Dataset != geoStoreName(current) {
		t.Fatal("report fallback silently changed disk selection")
	}
	previous := filepath.Join(f.store.base, geoStoreName(old), "database.mmdb.gz")
	if err = os.WriteFile(previous, []byte("owned broken older copy"), 0600); err != nil {
		t.Fatal(err)
	}
	s.refreshStatisticsGeoCacheStore(context.Background(), id, f.store)
	lookup, release, _, message = s.statisticsGeoSnapshotLease()
	if lookup == nil || !strings.Contains(message, "保留已完整") || lookup.Lookup("8.8.8.8").Status != "located" {
		release()
		t.Fatal("live corruption closed verified in-use bytes", message)
	}
	release()
	restarted := New(s.Config)
	restarted.refreshStatisticsGeoCacheStore(context.Background(), id, f.store)
	lookup, release, _, message = restarted.statisticsGeoSnapshotLease()
	defer release()
	if lookup != nil || !strings.Contains(message, "没有可用于报表") || strings.Contains(message, "保留已完整") {
		t.Fatal("unverified cold cache falsely claimed old memory", message)
	}
}

func TestStatisticsGeoCacheNoGuessAfterInvalidSelectorAndCloseWaitsForReport(t *testing.T) {
	f := geoStoreRootFixture(t)
	f.install(t, "2026-10")
	s, id := geoCacheServiceFixture(t, f)
	s.refreshStatisticsGeoCacheStore(context.Background(), id, f.store)
	s.geoCache.mu.Lock()
	old := s.geoCache.snapshot
	s.geoCache.loadedAt = time.Time{}
	s.geoCache.mu.Unlock()
	if old == nil {
		t.Fatal("fixture never loaded verified snapshot")
	}
	_, release, _, _ := s.statisticsGeoSnapshotLease()
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		s.refreshStatisticsGeoCacheStore(context.Background(), id, f.store)
		close(done)
	}()
	<-started
	if s.geoCache.mu.TryLock() {
		s.geoCache.mu.Unlock()
		t.Fatal("report lease did not own read lock")
	}
	if !old.Metadata(time.Now()).Available {
		t.Fatal("reader closed during report lease")
	}
	release()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not finish after report lease release")
	}
	if old.Metadata(time.Now()).Available {
		t.Fatal("retired reader not closed after safe publication")
	}
	if err := os.WriteFile(filepath.Join(f.store.base, "selected.json"), []byte(`{"format":1,"dataset":"../guess"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cold := New(s.Config)
	cold.refreshStatisticsGeoCacheStore(context.Background(), id, f.store)
	if cold.geoCache.snapshot != nil {
		t.Fatal("cold cache guessed retained dataset after corrupt selection")
	}
}

func TestStatisticsGeoVerifierFixedSandboxAndUpgradeGuard(t *testing.T) {
	unit := statisticsGeoVerifyPrefix + core.ID() + ".service"
	if !programQueueCriticalUnit(unit) || decodeProgramQueueUnits(unit+" loaded active running owned verifier\n") == nil {
		t.Fatal("active verifier escaped upgrade guard")
	}
	args := statisticsGeoVerifierArguments(unit, "/opt/panel/bin/panel-executor")
	for _, value := range []string{"--property=DynamicUser=yes", "--property=CapabilityBoundingSet=", "--property=RestrictAddressFamilies=AF_UNIX", "--property=RuntimeMaxSec=300s", "--property=MemoryMax=768M", "--property=MemorySwapMax=0", "--no-ask-password", "--statistics-geodata-reader"} {
		found := false
		for _, arg := range args {
			if arg == value {
				found = true
			}
		}
		if !found {
			t.Fatal("missing fixed sandbox contract", value)
		}
	}
	if _, err := statisticsGeoVerifierProgram(); err == nil {
		t.Fatal("outside-installation test executable accepted as production verifier")
	}
}

func TestStatisticsGeoVerifierCancellationOnlyOwnNonceAndClosedState(t *testing.T) {
	token := core.ID()
	valid := "LoadState=loaded\nActiveState=active\nSubState=running\nEnvironment=GOMEMLIMIT=512MiB PANEL_GEODATA_VERIFY_TOKEN=" + token + "\n"
	if !statisticsGeoVerifyOwned(valid, token) {
		t.Fatal("owned unit was not recognizable")
	}
	for _, raw := range []string{valid + "LoadState=loaded\n", strings.Replace(valid, "Environment=", "ENVIRONMENT=", 1), strings.Replace(valid, token, core.ID(), 1), strings.Replace(valid, "LoadState=loaded", "LoadState=not-found", 1), strings.Replace(valid, "GOMEMLIMIT=512MiB", "GOMEMLIMIT=512MiB EXTRA=untrusted", 1)} {
		if statisticsGeoVerifyOwned(raw, token) {
			t.Fatal("unknown or foreign verifier would be stopped")
		}
	}
	if _, err := statisticsGeoVerifyState("LoadState=not-found\n"); err == nil {
		t.Fatal("partial state was mistaken for empty slot")
	}
}
