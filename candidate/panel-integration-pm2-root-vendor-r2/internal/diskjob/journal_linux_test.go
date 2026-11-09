//go:build linux

package diskjob

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func nativeJournalFixture(t *testing.T) jobTree {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-native journal not executed; no commercial acceptance")
	}
	for _, p := range []string{"/", "/var", "/var/lib"} {
		var s unix.Stat_t
		if unix.Lstat(p, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Uid != 0 || s.Mode&0022 != 0 {
			t.Fatal("unsafe fixture ancestor; not repaired")
		}
	}
	if err := os.Mkdir("/var/lib/panel-executor", 0750); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	var s unix.Stat_t
	if unix.Lstat("/var/lib/panel-executor", &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Uid != 0 || s.Mode&0022 != 0 {
		t.Fatal("unsafe fixture anchor; not repaired")
	}
	base, err := os.MkdirTemp("/var/lib/panel-executor", "disk-host-journal-test.")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained owned journal fixture:", base)
	return jobTree{filepath.Join(base, "jobs")}
}

func journalRequest() Request {
	return Request{Format: 1, JobID: strings.Repeat("5", 32), ActorID: strings.Repeat("6", 32), AccessRevision: "1", Selection: selectionFixture()}
}

func TestHostJournalNativeImmutableRequestProgressTerminalAndLease(t *testing.T) {
	tree := nativeJournalFixture(t)
	in := journalRequest()
	j, replay, err := publishRootRequest(tree, in)
	if err != nil || replay {
		t.Fatal(j, replay, err)
	}
	defer j.Close()
	if got, err := j.Request(); err != nil || got != in {
		t.Fatal("original request changed", got, err)
	}
	same, replay, err := publishRootRequest(tree, in)
	if err != nil || !replay {
		t.Fatal("identical request not read-only replay", replay, err)
	}
	same.Close()
	changed := in
	changed.ActorID = strings.Repeat("7", 32)
	if other, _, err := publishRootRequest(tree, changed); !errors.Is(err, ErrJournal) {
		if other != nil {
			other.Close()
		}
		t.Fatal("original actor adopted/overwritten")
	}
	lock, err := j.Lease()
	if err != nil {
		t.Fatal(err)
	}
	other, err := tree.openJob(in.JobID, false)
	if err != nil {
		t.Fatal(err)
	}
	if leaked, err := other.Lease(); !errors.Is(err, ErrJournal) {
		if leaked != nil {
			leaked.Close()
		}
		t.Fatal("original worker lock stolen")
	}
	other.Close()
	lock.Close()
	raw, _ := json.Marshal(map[string]any{"id": in.JobID, "known_entries": "64"})
	if j.WriteProgress(raw) != nil {
		t.Fatal("native progress publication failed")
	}
	raw2, _ := json.Marshal(map[string]any{"id": in.JobID, "known_entries": "128"})
	if j.WriteProgress(raw2) != nil {
		t.Fatal("native atomic progress update failed")
	}
	if got, err := j.Read("progress.json"); err != nil || string(got) != string(raw2) {
		t.Fatal("progress replaced outside original journal", err)
	}
	result, _ := json.Marshal(map[string]any{"id": in.JobID, "state": "partial"})
	if j.WriteImmutable("result.json", result) != nil {
		t.Fatal("native terminal receipt failed")
	}
	if j.WriteImmutable("result.json", result) == nil || j.WriteProgress(raw) == nil {
		t.Fatal("original terminal result overwritten or progress revived")
	}
	if present, err := j.HasOriginalResult(); err != nil || !present {
		t.Fatal("original terminal receipt not retained")
	}
}

func TestHostJournalNativeEmptyInterruptedPreparationAndPendingAreNotReplayed(t *testing.T) {
	tree := nativeJournalFixture(t)
	base, _, err := tree.open(true)
	if err != nil {
		t.Fatal(err)
	}
	in := journalRequest()
	if base.Mkdir(in.JobID, 0700) != nil {
		t.Fatal("owned interrupted preparation failed")
	}
	base.Close()
	if j, _, err := publishRootRequest(tree, in); !errors.Is(err, ErrJournal) {
		if j != nil {
			j.Close()
		}
		t.Fatal("original empty interrupted preparation filled/replayed")
	}
	in.JobID = strings.Repeat("8", 32)
	j, _, err := publishRootRequest(tree, in)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if j.write("progress.pending", []byte(`{"original_partial":true}`)) != nil {
		t.Fatal("owned interrupted fsync fixture failed")
	}
	if j.WriteProgress([]byte(`{"new":true}`)) == nil {
		t.Fatal("original pending file overwritten/removed as automatic recovery")
	}
	if _, err := j.root.Lstat("progress.pending"); err != nil {
		t.Fatal("original pending evidence lost")
	}
}

func TestHostJournalNativeUnsafeFilesAndParentSubstitutionRefused(t *testing.T) {
	tree := nativeJournalFixture(t)
	in := journalRequest()
	j, _, err := publishRootRequest(tree, in)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if j.root.Symlink("request.json", "started.json") != nil {
		t.Fatal("owned link fixture failed")
	}
	if _, err := j.Read("started.json"); !errors.Is(err, ErrJournal) {
		t.Fatal("symlink receipt read")
	}
	if j.root.Link("request.json", "dispatch.json") != nil {
		t.Fatal("owned hardlink fixture failed")
	}
	if _, err := j.Request(); !errors.Is(err, ErrJournal) {
		t.Fatal("multi-link original request accepted")
	}
	in.JobID = strings.Repeat("9", 32)
	valid, _, err := publishRootRequest(tree, in)
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()
	original := filepath.Join(tree.name, in.JobID)
	if os.Rename(original, original+"-retained-original") != nil || os.Mkdir(original, 0700) != nil {
		t.Fatal("owned parent replacement fixture failed")
	}
	if _, err := valid.Request(); !errors.Is(err, ErrJournal) {
		t.Fatal("detached parent treated as current original request")
	}
	if valid.WriteImmutable("started.json", []byte(`{"id":"old"}`)) == nil {
		t.Fatal("substituted parent got writes")
	}
	if _, err := os.Lstat(filepath.Join(original, "started.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement folder received original job writes")
	}
}
