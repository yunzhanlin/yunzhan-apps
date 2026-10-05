//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
