//go:build linux

package diskjob

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/diskusage"
)

// Exercises the actual production journal-to-index handoff; standalone ledger
// tests using os.OpenRoot(base) cannot catch a non-canonical nested Root.Name.
func TestHostJournalNativeSpoolCreatesFreshStrictLedger(t *testing.T) {
	tree := nativeJournalFixture(t)
	j, replay, err := publishRootRequest(tree, journalRequest())
	if err != nil || replay {
		t.Fatal("new private original journal unavailable", err)
	}
	defer j.Close()
	r, err := j.SpoolRoot()
	if err != nil {
		t.Fatal("production fixed spool handle unavailable", err)
	}
	defer r.Close()
	before, err := j.root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := r.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		t.Fatal("spool handoff lost original held directory", err)
	}
	wanted := filepath.Join(tree.name, j.id)
	if r.Name() != wanted {
		t.Fatalf("spool name %q is not exact canonical original %q", r.Name(), wanted)
	}
	ledger, err := diskusage.NewLedger(context.Background(), r, 64)
	if err != nil {
		t.Fatal("production journal spool refused by unchanged strict ledger", err)
	}
	defer ledger.Close()
	if err := ledger.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ledger.Close() != nil || r.Close() != nil {
		t.Fatal("independent spool handle failed to close")
	}
	if original, err := j.Request(); err != nil || original != journalRequest() {
		t.Fatal("opening fixed spool changed original request", err)
	}
}

func TestHostJournalNativeSpoolRejectsChangedOriginalIdentityWithoutRepair(t *testing.T) {
	for _, kind := range []string{"public-mode", "replaced-job", "replaced-base"} {
		t.Run(kind, func(t *testing.T) {
			tree := nativeJournalFixture(t)
			j, replay, err := publishRootRequest(tree, journalRequest())
			if err != nil || replay {
				t.Fatal(err)
			}
			defer j.Close()
			job := filepath.Join(tree.name, j.id)
			switch kind {
			case "public-mode":
				if err := os.Chmod(job, 0755); err != nil {
					t.Fatal(err)
				}
			case "replaced-job":
				if os.Rename(job, job+"-retained") != nil || os.Mkdir(job, 0700) != nil {
					t.Fatal("owned job replacement fixture unavailable")
				}
			case "replaced-base":
				if os.Rename(tree.name, tree.name+"-retained") != nil || os.Mkdir(tree.name, 0700) != nil || os.Mkdir(job, 0700) != nil {
					t.Fatal("owned base replacement fixture unavailable")
				}
			}
			if r, err := j.SpoolRoot(); !errors.Is(err, ErrJournal) || r != nil {
				if r != nil {
					r.Close()
				}
				t.Fatal("changed private original became a trusted spool", err)
			}
			if kind == "public-mode" {
				info, err := os.Lstat(job)
				if err != nil || info.Mode().Perm() != 0755 {
					t.Fatal("pre-existing unsafe mode repaired", err)
				}
			}
			if _, err := os.Lstat(filepath.Join(job, "inode-index.db")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused handoff wrote an index", err)
			}
		})
	}
}
