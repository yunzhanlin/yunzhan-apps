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

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func TestStatisticsGeoJobExportOriginalBytesAndInodesInActiveAndArchive(t *testing.T) {
	for _, archived := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "archive"}[archived], func(t *testing.T) {
			store, id, archive, files := geoArchiveRootFixture(t)
			if archived {
				if _, err := store.archiveJob(context.Background(), archive); err != nil {
					t.Fatal(err)
				}
			}
			dir := filepath.Join(store.active, id)
			if archived {
				dir = filepath.Join(store.archive, id)
			}
			before := map[string]os.FileInfo{}
			for name := range files {
				before[name], _ = os.Lstat(filepath.Join(dir, name))
			}
			in := core.StatisticsGeoExportInput{JobID: id, SHA: archive.SHA}
			out, err := store.exportJob(context.Background(), in)
			if err != nil || out.Record.Archived != archived {
				t.Fatal(err)
			}
			wire, _ := json.Marshal(out)
			verified, err := core.DecodeStatisticsGeoExportResult(wire, in)
			if err != nil {
				t.Fatal(err)
			}
			var bundle core.StatisticsGeoEvidenceBundle
			if json.Unmarshal(verified.Bundle, &bundle) != nil {
				t.Fatal("bundle decode")
			}
			for name, want := range files {
				raw, e := os.ReadFile(filepath.Join(dir, name))
				after, ae := os.Lstat(filepath.Join(dir, name))
				if e != nil || ae != nil || !bytes.Equal(raw, want) || !bytes.Equal(bundle.Files[name], want) || !geoStoreStableInfo(before[name], after) {
					t.Fatal("original bytes or identity changed", name, e, ae)
				}
			}
			again, err := store.exportJob(context.Background(), in)
			if err != nil || !bytes.Equal(out.Bundle, again.Bundle) || out.BundleSHA != again.BundleSHA {
				t.Fatal("same unchanged evidence not deterministic", err)
			}
		})
	}
}
func TestStatisticsGeoJobExportRejectsPendingLocksChangedAndUnsafeEvidence(t *testing.T) {
	for _, mode := range []string{"pending", "locked", "wrong-sha", "symlink", "hardlink", "foreign", "changed-final", "replaced-final", "duplicate-final", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			store, id, archive, files := geoArchiveRootFixture(t)
			dir := filepath.Join(store.active, id)
			in := core.StatisticsGeoExportInput{JobID: id, SHA: archive.SHA}
			ctx := context.Background()
			switch mode {
			case "pending":
				if err := os.Remove(filepath.Join(dir, "result.json")); err != nil {
					t.Fatal(err)
				}
			case "locked":
				f, err := os.Open(filepath.Join(dir, "install.lock"))
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
					t.Fatal("fixture lock")
				}
			case "wrong-sha":
				in.SHA = strings.Repeat("a", 64)
			case "symlink":
				if err := os.Remove(filepath.Join(dir, "envelope.json")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(dir, "request.json"), filepath.Join(dir, "envelope.json")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(dir, "request.json"), filepath.Join(filepath.Dir(store.active), "extra-link")); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err := os.Chown(filepath.Join(dir, "request.json"), 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "changed-final":
				store.fault = func(point string) error {
					return os.WriteFile(filepath.Join(dir, "result.json"), append(files["result.json"], ' '), 0600)
				}
			case "replaced-final":
				store.fault = func(point string) error {
					p := filepath.Join(dir, "result.json")
					if err := os.Rename(p, p+".old"); err != nil {
						return err
					}
					return os.WriteFile(p, files["result.json"], 0600)
				}
			case "duplicate-final":
				store.fault = func(point string) error {
					if err := os.Mkdir(store.archive, 0700); err != nil {
						return err
					}
					return os.Mkdir(filepath.Join(store.archive, id), 0700)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if out, err := store.exportJob(ctx, in); err == nil || len(out.Bundle) != 0 {
				t.Fatal("unsafe partial evidence exported", mode, err)
			}
		})
	}
}
