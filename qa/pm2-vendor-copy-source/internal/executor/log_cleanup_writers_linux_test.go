//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogCleanupExpiredWriterModesRejectBeforeDeletionAndAllowReadOnlyDescriptors(t *testing.T) {
	for _, flags := range []string{"0100000", "0100001", "0100002", "invalid", "0100003", "0100001\nflags:\t0100000"} {
		t.Run(strings.ReplaceAll(flags, "\n", "-"), func(t *testing.T) {
			root := t.TempDir()
			file := filepath.Join(t.TempDir(), "retired-log")
			siteLogFixtureWrite(t, file, "preserved")
			info, e := os.Lstat(file)
			if e != nil {
				t.Fatal(e)
			}
			wafReloadFixtureStat(t, root, 1, 0, 0, "S") // Legitimate boot-time PID 1.
			wafReloadFixtureLink(t, root, "1/fd/7", file)
			wafReloadFixtureFile(t, root, "1/fdinfo/7", "pos:\t0\nflags:\t"+flags+"\n")
			e = siteLogExpiredOpenWriters(t.Context(), root, []plannedSiteLog{{name: filepath.Base(file), info: info}})
			if (e == nil) != (flags == "0100000") {
				t.Fatal("writer flag interpretation", flags, e)
			}
			if body, e := os.ReadFile(file); e != nil || string(body) != "preserved" {
				t.Fatal("writer inspection changed file", e)
			}
		})
	}
}

func TestLogCleanupExpiredRealOpenWriteDescriptorPreventsRetirement(t *testing.T) {
	if os.Getenv("PANEL_QA_LOG_NATIVE") != "1" {
		t.Skip("explicit private read-only namespace required")
	}
	file := filepath.Join(t.TempDir(), "retired-log")
	siteLogFixtureWrite(t, file, "preserved")
	info, e := os.Lstat(file)
	if e != nil {
		t.Fatal(e)
	}
	writer, e := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	if e = siteLogExpiredOpenWriters(t.Context(), "/proc", []plannedSiteLog{{name: filepath.Base(file), info: info}}); e == nil || !strings.Contains(e.Error(), "写入模式") {
		t.Fatal("live writer was not detected", e)
	}
	if body, e := os.ReadFile(file); e != nil || string(body) != "preserved" {
		t.Fatal("live writer inspection changed bytes", e)
	}
}

func TestLogCleanupLedgerWriterRejectionHasNoOperationOrFileMutation(t *testing.T) {
	s, in, logs, now := siteLogLedgerFixture(t)
	name := "panel-" + in.SiteID + ".access.log"
	retired := filepath.Join(logs, name+".20260901-100000")
	siteLogFixtureWrite(t, filepath.Join(logs, name), "active-preserved")
	siteLogFixtureWrite(t, retired, "retired-preserved")
	proc := s.systemPath("/proc")
	wafReloadFixtureStat(t, proc, 1, 0, 0, "S")
	wafReloadFixtureLink(t, proc, "1/fd/7", retired)
	wafReloadFixtureFile(t, proc, "1/fdinfo/7", "flags:\t0100001\n")
	if _, e := s.guardedSiteLogCleanup(t.Context(), in, now, nil); e == nil || !strings.Contains(e.Error(), "写入模式") {
		t.Fatal("production preflight did not reject writer", e)
	}
	for file, body := range map[string]string{filepath.Join(logs, name): "active-preserved", retired: "retired-preserved"} {
		if actual, e := os.ReadFile(file); e != nil || string(actual) != body {
			t.Fatal("preflight changed file", file, e)
		}
	}
	db, closeDB, e := s.openSiteLogLedger(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer closeDB()
	var count int
	if e = db.QueryRowContext(t.Context(), "SELECT count(*) FROM operations").Scan(&count); e != nil || count != 0 {
		t.Fatal("preflight created an operation", count, e)
	}
}

func TestLogCleanupExpiredWriterContextAndDescriptorBudgetsAreNonMutating(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	root := t.TempDir()
	file := filepath.Join(t.TempDir(), "retired-log")
	siteLogFixtureWrite(t, file, "preserved")
	info, e := os.Lstat(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = siteLogExpiredOpenWriters(ctx, root, []plannedSiteLog{{info: info}}); !errors.Is(e, context.Canceled) {
		t.Fatal("cancel ignored", e)
	}
	wafReloadFixtureStat(t, root, 100, 1, 200, "S")
	wafReloadFixtureLink(t, root, "100/fd/7", file)
	wafReloadFixtureFile(t, root, "100/fdinfo/7", "flags:\t0100000\n")
	budget := 0
	if e = siteLogProcessExpiredWriter(t.Context(), root, 100, map[siteLogInode]bool{}, &budget); e == nil {
		t.Fatal("descriptor budget bypassed")
	}
	if body, e := os.ReadFile(file); e != nil || string(body) != "preserved" {
		t.Fatal("budget check changed file", e)
	}
	t.Log(fmt.Sprintf("fixed expired identity %s remains unchanged", core.Hash("preserved")))
}
