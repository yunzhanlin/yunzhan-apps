//go:build linux

package executor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func TestIntrusionJournalStoreObservationDoesNotCreateLockOrArchive(t *testing.T) {
	f := newHardeningFixture(t)
	before, err := os.Lstat(f.s.Config.SecurityDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.s.intrusionJournalPending(); !os.IsNotExist(err) {
		t.Fatal("known absence not identified", err)
	}
	if inventory, e := f.s.intrusionJournalInventoryRead(); e != nil || len(inventory.Records) != 0 || inventory.TemporaryFiles != 0 {
		t.Fatal(inventory, e)
	}
	for _, name := range []string{intrusionPendingName, intrusionMutationLockName, intrusionJournalDirectory} {
		if _, e := os.Lstat(filepath.Join(f.s.Config.SecurityDir, name)); !os.IsNotExist(e) {
			t.Fatal("observation created artifact", name, e)
		}
	}
	after, _ := os.Lstat(f.s.Config.SecurityDir)
	if !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || f.writes != 0 {
		t.Fatal("observation changed root or kernel")
	}
}

func TestIntrusionJournalStoreExclusivePrepareKeepsSharedRootAndOriginalRecord(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"private": 0700, "shared-group": 0750, "shared-read": 0755} {
		t.Run(name, func(t *testing.T) {
			f := newHardeningFixture(t)
			p := intrusionJournalFixture(t)
			if err := os.Chmod(f.s.Config.SecurityDir, mode); err != nil {
				t.Fatal(err)
			}
			lock, err := f.s.intrusionMutationLock()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			raw, err := f.s.intrusionJournalPrepare(lock, p)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(f.s.Config.SecurityDir, intrusionPendingName)
			before, err := os.Lstat(file)
			if err != nil || before.Mode().Perm() != 0600 {
				t.Fatal(before, err)
			}
			got, again, err := f.s.intrusionJournalPending()
			if err != nil || got.ID != p.ID || !bytes.Equal(raw, again) {
				t.Fatal("original authority changed", err)
			}
			if _, err = f.s.intrusionJournalPrepare(lock, p); err == nil {
				t.Fatal("pending original job replayed")
			}
			after, _ := os.Lstat(file)
			data, _ := os.ReadFile(file)
			root, _ := os.Lstat(f.s.Config.SecurityDir)
			if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || !bytes.Equal(raw, data) || root.Mode().Perm() != mode || f.writes != 0 {
				t.Fatal("prepare replay repaired authority, shared root or kernel")
			}
		})
	}
}

func TestIntrusionJournalStoreRequiresActualNamedExclusiveLock(t *testing.T) {
	f := newHardeningFixture(t)
	p := intrusionJournalFixture(t)
	if _, err := f.s.intrusionJournalPrepare(nil, p); err == nil {
		t.Fatal("missing lock accepted")
	}
	lock, err := f.s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if other, e := f.s.intrusionMutationLock(); e == nil {
		other.Close()
		t.Fatal("independent second descriptor acquired same exclusive lock")
	}
	foreign, err := os.CreateTemp(f.s.Config.SystemRoot, "unrelated-private-")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if _, err = f.s.intrusionJournalPrepare(foreign, p); err == nil {
		t.Fatal("unrelated private file became mutation lock")
	}
	if _, _, err = f.s.intrusionJournalPending(); !os.IsNotExist(err) || f.writes != 0 {
		t.Fatal("lock refusal created pending or changed kernel", err)
	}
}

func TestIntrusionJournalStoreUnsafePendingIsNeverAbsentOrRepaired(t *testing.T) {
	for _, kind := range []string{"partial", "symlink", "hardlink", "public", "directory", "fifo", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			f := newHardeningFixture(t)
			p := intrusionJournalFixture(t)
			file := filepath.Join(f.s.Config.SecurityDir, intrusionPendingName)
			foreign := filepath.Join(f.s.Config.SystemRoot, "foreign.json")
			if err := os.WriteFile(foreign, []byte("foreign original\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "partial":
				err = os.WriteFile(file, []byte("{"), 0600)
			case "symlink":
				err = os.Symlink(foreign, file)
			case "hardlink":
				err = os.Link(foreign, file)
			case "public":
				err = os.WriteFile(file, []byte("{}\n"), 0644)
			case "directory":
				err = os.Mkdir(file, 0700)
			case "fifo":
				err = unix.Mkfifo(file, 0600)
			case "oversized":
				err = os.WriteFile(file, bytes.Repeat([]byte(" "), intrusionJournalBytes+1), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(file)
			if err = f.s.intrusionJournalRequireClosed(); err == nil {
				t.Fatal("unsafe pending became closed")
			}
			lock, err := f.s.intrusionMutationLock()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if _, err = f.s.intrusionJournalPrepare(lock, p); err == nil {
				t.Fatal("unsafe pending overwritten")
			}
			after, _ := os.Lstat(file)
			data, _ := os.ReadFile(foreign)
			if !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || string(data) != "foreign original\n" || f.writes != 0 {
				t.Fatal("unsafe original or foreign target changed")
			}
		})
	}
}

func TestIntrusionJournalStoreIncompleteTemporaryRetainedNotPromoted(t *testing.T) {
	f := newHardeningFixture(t)
	root, err := f.s.intrusionJournalArchiveRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	file := filepath.Join(f.s.Config.SecurityDir, intrusionJournalDirectory, ".intrusion-terminal-"+core.ID()+".tmp")
	if err = os.WriteFile(file, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Lstat(file)
	out, err := f.s.intrusionJournalInventoryRead()
	if err != nil || len(out.Records) != 0 || out.TemporaryFiles != 1 || out.Bytes != 1 {
		t.Fatal("temporary lost or promoted", out, err)
	}
	after, _ := os.Lstat(file)
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || f.writes != 0 {
		t.Fatal("temporary repaired or deleted")
	}
}

func TestIntrusionJournalStoreOldTerminalPreventsOriginalIDReuse(t *testing.T) {
	f := newHardeningFixture(t)
	p := intrusionJournalFixture(t)
	root, err := f.s.intrusionJournalArchiveRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	raw, _ := intrusionJournalEncode(p)
	record := intrusionJournalTerminal{Format: 1, State: "rolled_back", PlanSHA256: hardeningJournalDigest(raw), Plan: p, FinishedAt: "2026-10-20T00:00:01Z"}
	data, err := intrusionJournalEncode(record)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(f.s.Config.SecurityDir, intrusionJournalDirectory, p.ID+".json")
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Lstat(file)
	lock, err := f.s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err = f.s.intrusionJournalPrepare(lock, p); err == nil {
		t.Fatal("original terminal identity reused")
	}
	after, _ := os.Lstat(file)
	again, _ := os.ReadFile(file)
	if !os.SameFile(before, after) || !bytes.Equal(data, again) || f.writes != 0 {
		t.Fatal("original failed job rewritten")
	}
}

func TestIntrusionJournalStoreUnknownArchiveOrUnsafeRootBlocksWithoutRepair(t *testing.T) {
	for _, kind := range []string{"unknown-record", "public-archive", "linked-archive", "public-lock", "linked-lock", "writable-root"} {
		t.Run(kind, func(t *testing.T) {
			f := newHardeningFixture(t)
			p := intrusionJournalFixture(t)
			archive := filepath.Join(f.s.Config.SecurityDir, intrusionJournalDirectory)
			lockPath := filepath.Join(f.s.Config.SecurityDir, intrusionMutationLockName)
			foreign := filepath.Join(f.s.Config.SystemRoot, "foreign")
			if err := os.Mkdir(foreign, 0700); err != nil {
				t.Fatal(err)
			}
			var err error
			file := archive
			switch kind {
			case "unknown-record":
				err = os.Mkdir(archive, 0700)
				if err == nil {
					file = filepath.Join(archive, "unknown.json")
					err = os.WriteFile(file, []byte("foreign\n"), 0600)
				}
			case "public-archive":
				err = os.Mkdir(archive, 0755)
			case "linked-archive":
				err = os.Symlink(foreign, archive)
			case "public-lock":
				file = lockPath
				err = os.WriteFile(file, nil, 0644)
			case "linked-lock":
				file = lockPath
				err = os.Symlink(foreign, lockPath)
			case "writable-root":
				file = f.s.Config.SecurityDir
				err = os.Chmod(file, 0777)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(file)
			lock, err := f.s.intrusionMutationLock()
			if err == nil {
				defer lock.Close()
				_, err = f.s.intrusionJournalPrepare(lock, p)
			}
			if err == nil {
				t.Fatal("unsafe archive/root accepted")
			}
			after, _ := os.Lstat(file)
			if !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || f.writes != 0 {
				t.Fatal("unsafe archive/root repaired")
			}
		})
	}
}

func TestIntrusionJournalTerminalIsClosedSchemaAndBoundToOriginalDigest(t *testing.T) {
	p := intrusionJournalFixture(t)
	raw, _ := intrusionJournalEncode(p)
	base := intrusionJournalTerminal{Format: 1, State: "rolled_back", PlanSHA256: hardeningJournalDigest(raw), Plan: p, FinishedAt: "2026-10-20T00:00:01Z"}
	data, _ := intrusionJournalEncode(base)
	if _, err := intrusionJournalTerminalDecode(data, p.ID); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*intrusionJournalTerminal){
		"digest":             func(r *intrusionJournalTerminal) { r.PlanSHA256 = core.ID() },
		"future-state":       func(r *intrusionJournalTerminal) { r.State = "success" },
		"chronology":         func(r *intrusionJournalTerminal) { r.FinishedAt = "2026-10-19T00:00:00Z" },
		"same-recovery-job":  func(r *intrusionJournalTerminal) { r.RecoveryJobID = p.ID },
		"committed-recovery": func(r *intrusionJournalTerminal) { r.State = "committed"; r.RecoveryJobID = core.ID() },
	} {
		t.Run(name, func(t *testing.T) {
			record := base
			mutate(&record)
			data, _ := intrusionJournalEncode(record)
			if _, err := intrusionJournalTerminalDecode(data, p.ID); err == nil {
				t.Fatal("unknown or conflicting receipt accepted")
			}
		})
	}
}
