//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func TestWAFNativeSealAndRuleCopyBoundaries(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "program")
	if err := os.Mkdir(prefix, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(prefix, "lib"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "lib/engine.so"), []byte("fixed library"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("engine.so", filepath.Join(prefix, "lib/engine.link")); err != nil {
		t.Fatal(err)
	}
	if err := sealWAFNativeTree(prefix, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		p    string
		mode os.FileMode
	}{{prefix, 0755}, {filepath.Join(prefix, "lib"), 0755}, {filepath.Join(prefix, "lib/engine.so"), 0644}} {
		st, err := os.Stat(pair.p)
		if err != nil || st.Mode().Perm() != pair.mode {
			t.Fatal("tree not sealed", pair.p, err)
		}
	}
	sum, err := wafNativeFileSHA(context.Background(), filepath.Join(prefix, "lib/engine.so"), 32)
	if err != nil || len(sum) != 64 {
		t.Fatal("program digest failed", err)
	}
	if _, err := wafNativeFileSHA(context.Background(), filepath.Join(prefix, "lib/engine.so"), 2); err == nil {
		t.Fatal("program byte cap ignored")
	}
	dest := filepath.Join(t.TempDir(), "library")
	if err := copyWAFNativeFile(context.Background(), filepath.Join(prefix, "lib/engine.so"), dest, 32, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	if err := copyWAFNativeFile(context.Background(), filepath.Join(prefix, "lib/engine.so"), dest, 32, os.Geteuid()); err == nil {
		t.Fatal("overwrote published program")
	}
	if err := copyWAFRuleTree(context.Background(), prefix, filepath.Join(t.TempDir(), "rules")); err == nil {
		t.Fatal("published symlink in fixed rule tree")
	}
	for _, kind := range []string{"outside-link", "cycle", "dangling", "hardlink", "fifo", "root-link"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "tree")
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(filepath.Dir(dir), "original")
			if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "outside-link":
				if err := os.Symlink("../original", filepath.Join(dir, "bad")); err != nil {
					t.Fatal(err)
				}
			case "cycle":
				if err := os.Symlink("bad", filepath.Join(dir, "bad")); err != nil {
					t.Fatal(err)
				}
			case "dangling":
				if err := os.Symlink("missing", filepath.Join(dir, "bad")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(outside, filepath.Join(dir, "bad")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(filepath.Join(dir, "bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "root-link":
				link := dir + ".link"
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			}
			if err := sealWAFNativeTree(dir, os.Geteuid()); err == nil {
				t.Fatal("unsafe program tree sealed as valid")
			}
			data, _ := os.ReadFile(outside)
			if string(data) != "unchanged" {
				t.Fatal("unrelated file modified")
			}
		})
	}
}

func TestWAFEngineCancellationDoesNotCreateOrTrustRecords(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyWAFEngineBuildContext(ctx, core.ID()); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled verification did work or trusted state", err)
	}
	if os.Geteuid() == 0 {
		id := core.ID()
		if err := runWAFEngineBuildContext(ctx, id); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled build did work", err)
		}
		if _, err := os.Lstat(filepath.Join(wafEngineJobs, id+".json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("canceled-before-dispatch build created a record", err)
		}
	}
}

func TestWAFBuildRecordCannotOverwriteAndCancelledCommandDoesNotStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "build.json")
	record := wafEngineBuildRecord{Format: 1, JobID: core.ID(), State: "building"}
	if err := createWAFBuildRecord(path, record); err != nil {
		t.Fatal(err)
	}
	if err := createWAFBuildRecord(path, wafEngineBuildRecord{State: "ready"}); err == nil {
		t.Fatal("overwrote existing build evidence")
	}
	var actual wafEngineBuildRecord
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &actual); err != nil || actual.JobID != record.JobID || actual.State != "building" {
		t.Fatal("original record changed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runWAFNativeBuildCommand(ctx, wafBuildCommand{Program: "/bin/false"}, "/missing", "/missing"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled compiler started", err)
	}
	for _, id := range []string{"", "../outside", "not-a-job", strings.Repeat("f", 33)} {
		if err := RunWAFEngineBuild(id); err == nil {
			t.Fatal("invalid job accepted")
		}
	}
}
