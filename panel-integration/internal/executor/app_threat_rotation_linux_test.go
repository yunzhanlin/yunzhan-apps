//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestThreatIDSStoppedUnitStrictOrderIndependentNoUnknownStates(t *testing.T) {
	for _, v := range []string{"MainPID=0\nActiveState=inactive\n", "ActiveState=inactive\nMainPID=0\n"} {
		if !threatIDSStoppedUnit(v, false) {
			t.Fatal("field order affected stopped proof")
		}
	}
	if !threatIDSStoppedUnit("ActiveState=inactive\nLoadState=not-found\nMainPID=0\n", true) {
		t.Fatal("actual absent unit rejected")
	}
	for _, v := range []string{"", "MainPID=0\n", "MainPID=0\nActiveState=failed\n", "MainPID=2\nActiveState=inactive\n", "MainPID=0\nActiveState=inactive\nMainPID=0\n", "MainPID=0\nActiveState=inactive\nExtra=yes\n"} {
		if threatIDSStoppedUnit(v, false) {
			t.Fatal("unknown or malformed stopped state accepted", v)
		}
	}
}

func TestThreatIDSRotationRecordClosedCapacityAndSealingIdentity(t *testing.T) {
	entry := threatIDSArchive{ID: core.ID(), At: core.Now(), SHA: core.Hash("closed evidence"), Bytes: 12, Device: 1, Inode: 2}
	p := &threatIDSRotationPending{ID: entry.ID, At: entry.At, Device: 1, Inode: 2, UID: 800, GID: 801, Revision: 1, RuntimeSHA: core.Hash("runtime"), UnitSHA: core.Hash("unit"), Sealed: &entry}
	v := threatIDSRotation{Format: 1, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}, Pending: p}
	if err := validateThreatIDSRotation(v); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*threatIDSRotation){
		func(v *threatIDSRotation) { v.Pending.Sealed.ID = core.ID() },
		func(v *threatIDSRotation) { v.Pending.Sealed.Inode++ },
		func(v *threatIDSRotation) { v.Pending.Sealed.SHA = "unknown" },
		func(v *threatIDSRotation) { v.Pending.UID = 0 },
		func(v *threatIDSRotation) { v.Pending.Revision = 0 },
		func(v *threatIDSRotation) { v.Format = 2 },
	} {
		b, _ := json.Marshal(v)
		var bad threatIDSRotation
		if err := json.Unmarshal(b, &bad); err != nil {
			t.Fatal(err)
		}
		mutate(&bad)
		if validateThreatIDSRotation(bad) == nil {
			t.Fatal("bad sealing record accepted")
		}
	}
	encoded, _ := json.Marshal(v)
	for _, bad := range []string{strings.Replace(string(encoded), "\"format\":1", "\"format\":1,\"format\":1", 1), strings.TrimSuffix(string(encoded), "}") + ",\"extra\":1}"} {
		var decoded threatIDSRotation
		if decodeThreatIDSPrivateJSON([]byte(bad), &decoded) == nil {
			t.Fatal("duplicate or unknown rotation JSON accepted")
		}
	}
}

func threatIDSRotationRootFixture(t *testing.T) *Service {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires actual Linux root private fixture")
	}
	base := "/var/lib/panel-executor"
	if err := threatIDSTrustedParents(base, false); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(base, "ids-rotation-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	// Retain bounded own fixture data alongside proof on failure. No cleanup
	// can erase evidence while this test is diagnosing unknown file edits.
	s := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security")}).threatIDSTransactionService()
	if err := threatIDSTrustedParents(s.moduleDir("network-threat-detection"), true); err != nil {
		t.Fatal(err)
	}
	if err := threatIDSTrustedParents(s.systemPath("/var/lib/panel-network-ids"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.threatIDSHistoryDirectory(true); err != nil {
		t.Fatal(err)
	}
	t.Log("bounded retained private fixture", root)
	return s
}

func threatIDSRotationArchiveFixture(t *testing.T, s *Service) (threatIDSArchive, string) {
	t.Helper()
	id := core.ID()
	path := s.systemPath("/var/lib/panel-network-ids/history/eve-" + id + ".json")
	data := []byte("private synthetic alert metadata\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return threatIDSArchive{ID: id, At: core.Now(), SHA: core.Hash(string(data)), Bytes: int64(len(data)), Device: uint64(st.Dev), Inode: st.Ino}, path
}

func TestThreatIDSArchiveSealingPersistsDigestBeforeOwnershipAndRejectsEdits(t *testing.T) {
	s := threatIDSRotationRootFixture(t)
	entry, path := threatIDSRotationArchiveFixture(t, s)
	account := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	if err := os.Chown(path, 800, 801); err != nil {
		t.Fatal(err)
	}
	p := &threatIDSRotationPending{ID: entry.ID, At: entry.At, Device: entry.Device, Inode: entry.Inode, UID: 800, GID: 801, Revision: 1, RuntimeSHA: core.Hash("runtime"), UnitSHA: core.Hash("unit")}
	v := threatIDSRotation{Format: 1, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}, Pending: p}
	if _, err := threatIDSSealArchive(context.Background(), path, p, account, func() error { return errors.New("injected persistence failure") }); err == nil {
		t.Fatal("failed intent write allowed ownership mutation")
	}
	info, _ := os.Lstat(path)
	if info.Sys().(*syscall.Stat_t).Uid != 800 {
		t.Fatal("archive sealed before durable digest")
	}
	p.Sealed = nil
	sealed, err := threatIDSSealArchive(context.Background(), path, p, account, func() error {
		info, _ := os.Lstat(path)
		if info.Sys().(*syscall.Stat_t).Uid != 800 {
			t.Fatal("persist occurred after ownership change")
		}
		return s.writeThreatIDSRotation(v)
	})
	if err != nil || sealed != entry {
		t.Fatal(sealed, entry, err)
	}
	persisted, err := s.readThreatIDSRotation()
	if err != nil || persisted.Pending.Sealed == nil || *persisted.Pending.Sealed != entry {
		t.Fatal("durable sealed digest missing", persisted, err)
	}
	info, _ = os.Lstat(path)
	if st := info.Sys().(*syscall.Stat_t); st.Uid != 0 || st.Gid != 0 {
		t.Fatal("sealed archive not root private")
	}
	if _, err := threatIDSSealArchive(context.Background(), path, persisted.Pending, account, func() error { t.Fatal("verified replay rewrote evidence"); return nil }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := threatIDSSealArchive(context.Background(), path, persisted.Pending, account, func() error { t.Fatal("edited archive re-authenticated"); return nil }); err == nil {
		t.Fatal("same-inode same-size external edit adopted")
	}
	if _, err := s.threatIDSArchiveFile(entry); err == nil {
		t.Fatal("edited archive matched old digest")
	}
	unknown := *p
	unknown.Sealed = nil
	if _, err := threatIDSSealArchive(context.Background(), path, &unknown, account, func() error { t.Fatal("unknown root archive persisted"); return nil }); err == nil {
		t.Fatal("unknown root-owned archive adopted")
	}
}

func TestThreatIDSArchiveRetirementRequiresDurableOwnedFullDigest(t *testing.T) {
	s := threatIDSRotationRootFixture(t)
	v := threatIDSRotation{Format: 1, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}}
	paths := []string{}
	for range threatIDSHistoryLimit + 1 {
		entry, path := threatIDSRotationArchiveFixture(t, s)
		v.Archives = append(v.Archives, entry)
		paths = append(paths, path)
	}
	if err := s.writeThreatIDSRotation(v); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(paths[0])
	changed := append([]byte{}, original...)
	changed[0] ^= 1
	if err := os.WriteFile(paths[0], changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.retireThreatIDSArchive(v); err == nil {
		t.Fatal("foreign edit retired")
	}
	actual, _ := os.ReadFile(paths[0])
	if string(actual) != string(changed) {
		t.Fatal("external evidence was replaced")
	}
	if err := os.WriteFile(paths[0], original, 0600); err != nil {
		t.Fatal(err)
	}
	first := v.Archives[0]
	v.Retiring = &first
	stage := filepath.Join(filepath.Dir(paths[0]), "retiring-eve-"+first.ID+".json")
	if err := os.Rename(paths[0], stage); err != nil {
		t.Fatal(err)
	}
	if _, err := readThreatIDSPrivateArchiveFile(context.Background(), first, stage); err != nil {
		t.Fatal(err)
	}
	v.RetirementUnlink = true
	if err := s.writeThreatIDSRotation(v); err != nil {
		t.Fatal(err)
	}
	// Exact journal-bound unlink simulates the interruption after deletion but
	// before record commit. This synthetic file was created by this fixture.
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	resumed, err := s.retireThreatIDSArchive(v)
	if err != nil || len(resumed.Archives) != threatIDSHistoryLimit || len(resumed.Retired) != 1 || resumed.Retired[0] != first || resumed.Retiring != nil {
		t.Fatal("durable retirement did not resume", resumed, err)
	}
	for _, path := range paths[1:] {
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("unselected archive changed", err)
		}
	}
	// Without an owned durable retirement marker a disappeared known archive
	// cannot be claimed as a successful prune.
	s2 := threatIDSRotationRootFixture(t)
	v2 := threatIDSRotation{Format: 1, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}}
	for range threatIDSHistoryLimit + 1 {
		e, _ := threatIDSRotationArchiveFixture(t, s2)
		v2.Archives = append(v2.Archives, e)
	}
	if err := s2.writeThreatIDSRotation(v2); err != nil {
		t.Fatal(err)
	}
	path, err := s2.threatIDSArchiveFile(v2.Archives[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.retireThreatIDSArchive(v2); err == nil {
		t.Fatal("unknown missing archive was retired")
	}
}

func TestThreatIDSArchiveRetirementPrivateSlotRecoveryRefusesUnknownPhases(t *testing.T) {
	for _, kind := range []string{"before-unlink", "unknown-missing", "edited-slot", "both-paths", "unknown-file"} {
		t.Run(kind, func(t *testing.T) {
			s := threatIDSRotationRootFixture(t)
			v := threatIDSRotation{Format: 1, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}}
			var original string
			for range threatIDSHistoryLimit + 1 {
				entry, path := threatIDSRotationArchiveFixture(t, s)
				v.Archives = append(v.Archives, entry)
				if original == "" {
					original = path
				}
			}
			first := v.Archives[0]
			v.Retiring = &first
			if err := s.writeThreatIDSRotation(v); err != nil {
				t.Fatal(err)
			}
			staged := filepath.Join(filepath.Dir(original), "retiring-eve-"+first.ID+".json")
			if err := os.Rename(original, staged); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unknown-missing":
				if err := os.Rename(staged, s.systemPath("/retained-unknown-fixture")); err != nil {
					t.Fatal(err)
				}
			case "edited-slot":
				data, err := os.ReadFile(staged)
				if err != nil {
					t.Fatal(err)
				}
				data[0] ^= 1
				if err := os.WriteFile(staged, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "both-paths":
				if err := os.WriteFile(original, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-file":
				if err := os.WriteFile(filepath.Join(filepath.Dir(staged), "unknown"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(s.threatIDSRotationPath())
			recovered, err := s.retireThreatIDSArchiveContext(context.Background(), v)
			if kind == "before-unlink" {
				if err != nil || recovered.Retiring != nil || recovered.RetirementUnlink || len(recovered.Archives) != threatIDSHistoryLimit || len(recovered.Retired) != 1 || recovered.Retired[0] != first {
					t.Fatal(recovered, err)
				}
				if _, err := os.Lstat(staged); !os.IsNotExist(err) {
					t.Fatal("retirement slot not cleared")
				}
			} else {
				if err == nil {
					t.Fatal("unknown/foreign phase reported retired", kind)
				}
				after, _ := os.ReadFile(s.threatIDSRotationPath())
				if string(after) != string(before) {
					t.Fatal("failed retirement changed durable intent", kind)
				}
				if kind != "unknown-missing" {
					if _, err := os.Lstat(staged); err != nil {
						t.Fatal("foreign retirement evidence removed", kind)
					}
				}
			}
			for _, entry := range v.Archives[1:] {
				if _, err := s.threatIDSArchiveFile(entry); err != nil {
					t.Fatal("unselected archive changed", kind, err)
				}
			}
		})
	}
	if validateThreatIDSRotation(threatIDSRotation{Format: 1, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}, RetirementUnlink: true}) == nil {
		t.Fatal("unlink phase without an exact retirement entry accepted")
	}
}
