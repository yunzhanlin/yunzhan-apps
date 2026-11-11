//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestTaskSysVStartupVerifiesDirectLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires the native Root ownership checks")
	}
	root := t.TempDir()
	for _, name := range []string{"init.d", "rc2.d", "rc3.d", "rc6.d"} {
		if err := os.MkdirAll(filepath.Join(root, "etc", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"enabled", "different", "shutdown", "writable"} {
		script := filepath.Join(root, "etc/init.d", name)
		if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if name == "writable" {
			if err := os.Chmod(script, 0o777); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, target := range map[string]string{
		"init.d/symlink":     "enabled",
		"rc2.d/S01enabled":   "../init.d/enabled",
		"rc2.d/S02enabled":   "../init.d/enabled",
		"rc3.d/S01enabled":   "/etc/init.d/enabled",
		"rc3.d/S03different": "../init.d/enabled",
		"rc3.d/S09symlink":   "../init.d/symlink",
		"rc4.d":              "rc2.d",
		"rc6.d/S01shutdown":  "../init.d/shutdown",
	} {
		if err := os.Symlink(target, filepath.Join(root, "etc", name)); err != nil {
			t.Fatal(err)
		}
	}
	service := New(Config{SystemRoot: root})
	out := taskInventory{View: "startup"}
	if err := service.taskSysVStartup(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Partial || len(out.Rows) != 3 {
		t.Fatal("unexpected verified rows", out)
	}
	for _, row := range out.Rows {
		switch row["name"] {
		case "enabled":
			if row["runlevels"] != "2、3" || row["startup_state"] != "已登记启动链接" {
				t.Fatal("wrong verified runlevels", row)
			}
		case "different", "shutdown":
			if row["runlevels"] != "" {
				t.Fatal("unrelated or shutdown link was counted as startup", row)
			}
		default:
			t.Fatal("unverified script was listed", row)
		}
	}
}

func TestTaskSysVStartupReadsActualLinuxScripts(t *testing.T) {
	if os.Getenv("PANEL_TASK_INVENTORY_NATIVE") != "isolated-arm64" {
		t.Skip("requires the existing isolated Ubuntu ARM64 guest")
	}
	hostname, err := os.Hostname()
	if err != nil || hostname != "lima-panel-openlitespeed-c92r2-arm64-qa" || os.Geteuid() != 0 {
		t.Fatal("unexpected native test host")
	}
	if _, err := os.Lstat("/etc/init.d/cron"); err != nil {
		t.Fatal(err)
	}
	out := taskInventory{View: "startup"}
	if err := New(Config{}).taskSysVStartup(&out); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(out.Rows, func(row map[string]string) bool {
		return row["name"] == "cron" && row["source"] == "SysV" && row["runlevels"] != ""
	}) {
		t.Fatal("the actual Ubuntu SysV cron startup links were missing", len(out.Rows), out.Partial)
	}
	t.Logf("Actual SysV startup entries: %d", len(out.Rows))
}
