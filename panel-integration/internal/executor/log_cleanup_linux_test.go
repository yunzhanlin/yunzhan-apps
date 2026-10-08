//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type siteLogSizedInfo struct {
	os.FileInfo
	bytes int64
}

func (info siteLogSizedInfo) Size() int64 { return info.bytes }

func TestLogCleanupExpiredBytesRejectOverflowBeforeMutation(t *testing.T) {
	for _, sizes := range [][]int64{{math.MaxInt64, 1}, {-1}, {0, math.MaxInt64}} {
		items := []plannedSiteLog{}
		for _, size := range sizes {
			items = append(items, plannedSiteLog{info: siteLogSizedInfo{bytes: size}})
		}
		total, e := siteLogExpiredBytes(items)
		valid := len(sizes) == 2 && sizes[0] == 0
		if (e == nil) != valid || valid && total != math.MaxInt64 {
			t.Fatal("unsafe byte accumulation", sizes, total, e)
		}
	}
}

func TestLogCleanupRetirementRefusalPreservesOldAndNewLogs(t *testing.T) {
	_, in, logs, now := siteLogLedgerFixture(t)
	name := "panel-" + in.SiteID + ".access.log"
	archive := name + "." + now.UTC().Format("20060102-150405")
	retired := name + ".20260901-100000"
	siteLogFixtureWrite(t, filepath.Join(logs, name), "before")
	siteLogFixtureWrite(t, filepath.Join(logs, retired), "retired")
	reopened := false
	result, e := cleanupSiteLogsAtGuarded(t.Context(), logs, in.SiteID, 2, now, func(context.Context) error {
		reopened = true
		siteLogFixtureWrite(t, filepath.Join(logs, name), "after")
		return nil
	}, nil, func() error { return errors.New("writer appeared after reopen") })
	if e == nil || !reopened || result.Rotated != 1 || result.Deleted != 0 {
		t.Fatal("retirement refusal was accepted", result, e)
	}
	for file, body := range map[string]string{name: "after", archive: "before", retired: "retired"} {
		if actual, e := os.ReadFile(filepath.Join(logs, file)); e != nil || string(actual) != body {
			t.Fatal("retirement refusal changed bytes", file, e)
		}
	}
}

func TestLogCleanupUsesFixedSiteNamesAndRollsBackReopenFailure(t *testing.T) {
	base := t.TempDir()
	id, other := core.ID(), core.ID()
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	write := func(name, body string) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(base, name), []byte(body), 0640); e != nil {
			t.Fatal(e)
		}
	}
	write("panel-"+id+".access.log", "active")
	write("panel-"+id+".error.log", "")
	write("panel-"+id+".access.log.20260910-120000", "old")
	write("panel-"+id+".error.log.20260919-110000", "recent")
	write("panel-"+other+".access.log.20260910-120000", "other")
	reopened := false
	result, e := cleanupSiteLogsAt(context.Background(), base, id, 2, now, func(context.Context) error { reopened = true; return nil })
	if e != nil || !reopened || result.Rotated != 1 || result.Deleted != 1 || result.DeletedBytes != 3 {
		t.Fatal("log cleanup result", result, reopened, e)
	}
	if _, e = os.Stat(filepath.Join(base, "panel-"+other+".access.log.20260910-120000")); e != nil {
		t.Fatal("another site's log changed", e)
	}
	write("panel-"+id+".access.log", "again")
	_, e = cleanupSiteLogsAt(context.Background(), base, id, 2, now.Add(time.Second), func(context.Context) error { return errors.New("reopen fault") })
	if e == nil {
		t.Fatal("reopen failure was accepted")
	}
	if content, readErr := os.ReadFile(filepath.Join(base, "panel-"+id+".access.log")); readErr != nil || string(content) != "again" {
		t.Fatal("active log was not restored", string(content), readErr)
	}
}
