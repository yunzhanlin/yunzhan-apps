//go:build linux

package executor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const wafReloadFixtureBinary = "/usr/sbin/nginx"

func wafReloadFixtureStat(t *testing.T, root string, pid, parent int, start uint64, state string) {
	t.Helper()
	fields := strings.Fields("S 1 1 1 0 0 0 0 0 0 0 1 1 0 0 20 0 1 0 100 1024 1")
	fields[0], fields[1], fields[19] = state, strconv.Itoa(parent), strconv.FormatUint(start, 10)
	path := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "stat"), []byte(fmt.Sprintf("%d (nginx (worker)) %s\n", pid, strings.Join(fields, " "))), 0600); err != nil {
		t.Fatal(err)
	}
}

func wafReloadFixtureFile(t *testing.T, root, path, value string) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func wafReloadFixtureLink(t *testing.T, root, path, value string) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(value, path); err != nil {
		t.Fatal(err)
	}
}

func wafReloadFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	wafReloadFixtureStat(t, root, 100, 1, 200, "S")
	wafReloadFixtureStat(t, root, 101, 100, 300, "S")
	wafReloadFixtureStat(t, root, 102, 100, 400, "S")
	wafReloadFixtureLink(t, root, "100/exe", wafReloadFixtureBinary)
	wafReloadFixtureLink(t, root, "101/exe", wafReloadFixtureBinary)
	wafReloadFixtureLink(t, root, "102/exe", wafReloadFixtureBinary)
	wafReloadFixtureFile(t, root, "100/task/100/children", "101 102\n")
	wafReloadFixtureFile(t, root, "101/cmdline", "nginx: worker process\x00")
	wafReloadFixtureFile(t, root, "102/cmdline", "nginx: cache manager process\x00")
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6"} {
		wafReloadFixtureFile(t, root, "100/net/"+protocol, "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
	}
	wafReloadFixtureFile(t, root, "100/net/tcp", "header\n0: 0100007F:4A9D 00000000:0000 0A 0:0 00:0 0 0 0 700\n1: 0100007F:4A9D 0100007F:8000 01 0:0 00:0 0 0 0 701\n")
	wafReloadFixtureFile(t, root, "100/net/udp", "header\n0: 00000000:01BB 00000000:0000 07 0:0 00:0 0 0 0 702\n1: 0100007F:8000 0100007F:0202 01 0:0 00:0 0 0 0 703\n")
	wafReloadFixtureFile(t, root, "100/net/unix", "Num RefCount Protocol Flags Type St Inode Path\n0000: 00000002 00000000 00010000 0001 01 704 /run/nginx.sock\n0001: 00000002 00000000 00000000 0001 03 705\n")
	for _, inode := range []string{"700", "701", "702", "703", "704", "705"} {
		wafReloadFixtureLink(t, root, "100/fd/"+inode, "socket:["+inode+"]")
	}
	wafReloadFixtureLink(t, root, "101/fd/7", "socket:[700]")
	wafReloadFixtureLink(t, root, "101/fd/8", "socket:[701]")
	wafReloadFixtureLink(t, root, "101/fd/9", "socket:[705]")
	return root
}

func TestWAFReloadGenerationWaitsForListenersNotExistingClients(t *testing.T) {
	root := wafReloadFixture(t)
	g, err := captureWAFReloadGeneration(context.Background(), root, wafReloadFixtureBinary, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Workers) != 1 || g.Workers[0].PID != 101 || !reflect.DeepEqual(g.Listeners, map[string]bool{"700": true, "702": true, "704": true}) {
		t.Fatalf("wrong generation: %#v", g)
	}
	wafReloadFixtureFile(t, root, "101/cmdline", "nginx: worker process is shutting down\x00")
	if done, err := g.drained(context.Background()); err != nil || done {
		t.Fatal("process title is NOT a listener-close acknowledgement", done, err)
	}
	if err := os.Remove(filepath.Join(root, "101/fd/7")); err != nil {
		t.Fatal(err)
	}
	if done, err := g.drained(context.Background()); err != nil || !done {
		t.Fatal("old established clients/control channels must not block reload", done, err)
	}
	if err := waitWAFReloadGeneration(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "101/stat")); err != nil {
		t.Fatal("old worker unexpectedly killed", err)
	}
}

func TestWAFReloadGenerationRefusesUnverifiedLiveProcesses(t *testing.T) {
	for _, tc := range []string{"wrong_master_exe", "wrong_worker_exe", "wrong_parent", "duplicate_child", "invalid_child", "no_workers", "broken_stat", "missing_table", "malformed_table", "no_master_listener"} {
		t.Run(tc, func(t *testing.T) {
			root := wafReloadFixture(t)
			switch tc {
			case "wrong_master_exe", "wrong_worker_exe":
				path := "100/exe"
				if tc == "wrong_worker_exe" {
					path = "101/exe"
				}
				os.Remove(filepath.Join(root, path))
				wafReloadFixtureLink(t, root, path, "/foreign/nginx")
			case "wrong_parent":
				wafReloadFixtureStat(t, root, 101, 999, 300, "S")
			case "duplicate_child":
				wafReloadFixtureFile(t, root, "100/task/100/children", "101 101")
			case "invalid_child":
				wafReloadFixtureFile(t, root, "100/task/100/children", "../101")
			case "no_workers":
				wafReloadFixtureFile(t, root, "101/cmdline", "foreign daemon\x00")
			case "broken_stat":
				wafReloadFixtureFile(t, root, "101/stat", "101 (broken)")
			case "missing_table":
				os.Remove(filepath.Join(root, "100/net/tcp"))
			case "malformed_table":
				wafReloadFixtureFile(t, root, "100/net/tcp", "header\ninvalid\n")
			case "no_master_listener":
				for _, n := range []string{"700", "702", "704"} {
					os.Remove(filepath.Join(root, "100/fd", n))
				}
			}
			if _, err := captureWAFReloadGeneration(context.Background(), root, wafReloadFixtureBinary, 100); err == nil {
				t.Fatal("accepted unverified generation")
			}
		})
	}
}

func TestWAFReloadGenerationPIDReuseAndFailures(t *testing.T) {
	for _, tc := range []string{"old_exit", "old_pid_reused", "old_zombie", "master_reused", "master_exe_changed", "live_stat_corrupt", "live_fd_unreadable", "context_cancelled", "listener_still_open"} {
		t.Run(tc, func(t *testing.T) {
			root := wafReloadFixture(t)
			g, err := captureWAFReloadGeneration(context.Background(), root, wafReloadFixtureBinary, 100)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantDone, wantError := false, false
			switch tc {
			case "old_exit":
				os.Remove(filepath.Join(root, "101/stat"))
				wantDone = true
			case "old_pid_reused":
				wafReloadFixtureStat(t, root, 101, 999, 301, "S")
				wantDone = true
			case "old_zombie":
				wafReloadFixtureStat(t, root, 101, 100, 300, "Z")
				wantDone = true
			case "master_reused":
				wafReloadFixtureStat(t, root, 100, 1, 201, "S")
				wantError = true
			case "master_exe_changed":
				os.Remove(filepath.Join(root, "100/exe"))
				wafReloadFixtureLink(t, root, "100/exe", "/foreign/nginx")
				wantError = true
			case "live_stat_corrupt":
				wafReloadFixtureFile(t, root, "101/stat", "foreign")
				wantError = true
			case "live_fd_unreadable":
				wafReloadFixtureFile(t, root, "101/fd/99", "not a proc symlink")
				wantError = true
			case "context_cancelled":
				cancel()
				wantError = true
			}
			done, err := g.drained(ctx)
			if done != wantDone || (err != nil) != wantError {
				t.Fatalf("done=%v error=%v", done, err)
			}
		})
	}
}

func TestWAFListenerTablesRejectUnknownAndInvalidInodes(t *testing.T) {
	for _, tc := range []struct{ protocol, data string }{
		{"http", "header\n"}, {"tcp", ""}, {"tcp", "header\n0: 1 2 0A 0 0 0 0 0 invalid\n"}, {"tcp", "header\n0: 1 2 0A 0 0 0 0 0 0\n"}, {"udp", "header\nshort\n"}, {"unix", "header\nshort\n"},
	} {
		if _, err := wafListenerTable([]byte(tc.data), tc.protocol); err == nil {
			t.Fatal("invalid listener table accepted", tc)
		}
	}
	if _, err := wafListenerTable([]byte("header\n"+strings.Repeat("\n", 131073)), "tcp"); err == nil {
		t.Fatal("unbounded socket table accepted")
	}
}
