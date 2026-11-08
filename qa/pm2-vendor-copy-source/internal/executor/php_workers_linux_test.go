//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPHPWorkerFrameworkEntryRejectsLinkedComponents(t *testing.T) {
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "bin"), 0750); e != nil {
		t.Fatal(e)
	}
	for _, entry := range []string{"artisan", "bin/console", "worker space.php"} {
		if e := os.WriteFile(filepath.Join(root, entry), []byte("<?php echo PHP_VERSION;"), 0640); e != nil {
			t.Fatal(e)
		}
		if _, e := phpWorkerScriptPath(root, entry); e != nil {
			t.Fatal(entry, e)
		}
	}
	if e := os.Symlink(filepath.Join(root, "bin"), filepath.Join(root, "linked")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(root, "artisan"), filepath.Join(root, "linked.php")); e != nil {
		t.Fatal(e)
	}
	for _, entry := range []string{"linked/console", "linked.php", "../artisan", "bin"} {
		if _, e := phpWorkerScriptPath(root, entry); e == nil {
			t.Fatal("unsafe worker entry accepted", entry)
		}
	}
}

func TestPHPWorkerRepeatedStopDoesNotHideUnknownOrLiveState(t *testing.T) {
	for _, test := range []struct {
		name, observed, boot string
		queryFails, wantOK   bool
	}{
		{"removed links", "ActiveState=inactive\nMainPID=0", "Failed to get unit file state: No such file or directory", false, true},
		{"disabled", "ActiveState=inactive\nMainPID=0", "disabled", false, true},
		{"still live", "ActiveState=active\nMainPID=123", "disabled", false, false},
		{"still enabled", "ActiveState=inactive\nMainPID=0", "enabled", false, false},
		{"bus failed", "", "disabled", true, false},
		{"boot query failed", "ActiveState=inactive\nMainPID=0", "Failed to connect to bus", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := New(Config{Run: func(ctx context.Context, binary string, args ...string) (string, error) {
				switch args[0] {
				case "disable", "stop":
					return "", errors.New("disable failed")
				case "show":
					if test.queryFails {
						return "", errors.New("bus failed")
					}
					return test.observed, nil
				case "is-enabled":
					if strings.HasPrefix(test.boot, "Failed") {
						return test.boot, errors.New("unit unavailable")
					}
					return test.boot, nil
				default:
					t.Fatal(args)
					return "", nil
				}
			}})
			if e := s.stopPHPWorker(context.Background(), core.PHPWorker{ID: core.ID()}); (e == nil) != test.wantOK {
				t.Fatal(e)
			}
		})
	}
}

func TestPHPWorkerMissingOrMalformedPropertiesCannotProveStopped(t *testing.T) {
	for _, output := range []string{"", "MainPID=0", "ActiveState=inactive", "ActiveState=inactive\nMainPID=garbage", "ActiveState=inactive\nMainPID=-1", "ActiveState=unexpected\nMainPID=0"} {
		s := New(Config{Run: func(context.Context, string, ...string) (string, error) { return output, nil }})
		got := s.inspectPHPWorker(context.Background(), core.PHPWorker{ID: core.ID()})
		if got.Status != "unknown" || got.LastError == "" {
			t.Fatal("unproven process state accepted", output, got)
		}
	}
}
