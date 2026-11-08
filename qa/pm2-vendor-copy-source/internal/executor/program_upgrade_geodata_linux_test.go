//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func TestProgramUpgradeQueuesGeoNativeUnitIsCritical(t *testing.T) {
	unit := "panel-statistics-geodata@" + core.ID() + ".service"
	if !programQueueCriticalUnit(unit) {
		t.Fatal("geographic worker omitted from native upgrade inventory")
	}
	for _, state := range []string{"active running", "activating start", "deactivating stop-sigterm", "failed failed"} {
		if decodeProgramQueueUnits(unit+" loaded "+state+" owned geographic worker\n") == nil {
			t.Fatal("incomplete native geographic worker crossed upgrade preflight", state)
		}
	}
	if err := decodeProgramQueueUnits(unit + " loaded inactive dead owned geographic worker\n"); err != nil {
		t.Fatal("completed inactive unit refused", err)
	}
}

func TestProgramUpgradeQueuesGeoOriginalReceiptAndLock(t *testing.T) {
	for _, kind := range []string{"succeeded", "failed", "queued", "running", "needs-attention", "missing-result", "missing-started", "changed-started", "changed-envelope", "changed-instance", "false-success", "empty-failure", "held-lock", "nonempty-lock", "unknown-file", "unfinished-stage"} {
		t.Run(kind, func(t *testing.T) {
			root := programQueueFixture(t)
			id := core.ID()
			relative := "var/lib/panel-executor/statistics-geodata-jobs/" + id
			selection := core.StatisticsGeoSelection{Action: "install", AppVersion: "2.6.0", AppManifestSHA: strings.Repeat("a", 64), InstallationID: strings.Repeat("b", 32), Release: "2026-10", DataManifestSHA: strings.Repeat("c", 64)}
			envelope := []byte("owned opaque queue fixture; not a signed geographic database")
			request := statisticsGeoRequest{Format: 1, JobID: id, Selection: selection, EnvelopeSHA: core.Hash(string(envelope))}
			writeProgramQueueFixture(t, root, relative, "request", request)
			base := filepath.Join(root, relative)
			if err := os.WriteFile(filepath.Join(base, "envelope.json"), envelope, 0600); err != nil {
				t.Fatal(err)
			}
			started := request
			if kind == "changed-started" {
				started.JobID = core.ID()
			}
			if kind != "missing-started" {
				writeProgramQueueFixture(t, root, relative, "started", started)
			}
			result := core.StatisticsGeoOperation{JobID: id, Selection: selection, State: "succeeded", Steps: []core.Step{}}
			switch kind {
			case "failed":
				result.State, result.Error = "failed", "owned preserved failure"
			case "queued", "running", "needs-attention":
				result.State = kind
			case "false-success":
				result.Error = "must not conceal failure"
			case "empty-failure":
				result.State = "failed"
			case "changed-instance":
				result.Selection.InstallationID = strings.Repeat("d", 32)
			}
			if kind != "missing-result" {
				writeProgramQueueFixture(t, root, relative, "result", result)
			}
			if kind == "changed-envelope" {
				if err := os.WriteFile(filepath.Join(base, "envelope.json"), []byte("changed owned delivery"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "unknown-file" {
				if err := os.WriteFile(filepath.Join(base, "unknown.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			lockPath := filepath.Join(base, "install.lock")
			lockBytes := []byte{}
			if kind == "nonempty-lock" {
				lockBytes = []byte("owned unexpected content")
			}
			if err := os.WriteFile(lockPath, lockBytes, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "held-lock" {
				lock, err := os.OpenFile(lockPath, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "unfinished-stage" {
				if err := os.Rename(base, filepath.Join(filepath.Dir(base), ".request-"+id)); err != nil {
					t.Fatal(err)
				}
			}
			before := programQueueTree(t, root)
			err := checkProgramUpgradeQueues(context.Background(), root)
			if (err == nil) != (kind == "succeeded" || kind == "failed") {
				t.Fatal("unproven geographic job crossed upgrade preflight", kind, err)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("geographic preflight mutated original request or receipt")
			}
		})
	}
}
