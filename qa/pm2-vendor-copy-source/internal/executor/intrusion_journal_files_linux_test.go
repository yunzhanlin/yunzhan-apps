//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func TestIntrusionJournalFixedFileStepsCommitAndRestoreOnlyOriginalThreeFiles(t *testing.T) {
	s, _, calls, lock, p, raw := intrusionPendingObservationFixture(t)
	if _, _, err := s.intrusionJournalObserveFilesAndTree(context.Background(), p, "rolled_back"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.intrusionJournalWriteFile(context.Background(), lock, p, raw, i, "committed"); err != nil {
			t.Fatal("commit", i, err)
		}
	}
	if _, _, err := s.intrusionJournalObserveFilesAndTree(context.Background(), p, "committed"); err != nil {
		t.Fatal(err)
	}
	for i := 2; i >= 0; i-- {
		if err := s.intrusionJournalWriteFile(context.Background(), lock, p, raw, i, "rolled_back"); err != nil {
			t.Fatal("rollback", i, err)
		}
	}
	if _, _, err := s.intrusionJournalObserveFilesAndTree(context.Background(), p, "rolled_back"); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatal("file step executed a service command", *calls)
	}
	_, again, err := s.intrusionJournalPending()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("filesystem step replaced original authority", err)
	}
}

func TestIntrusionJournalFixedFileNoOpDoesNotReplaceInodesOrRunCommands(t *testing.T) {
	s, _, calls, lock, p, raw := intrusionPendingObservationFixture(t)
	paths := s.intrusionJournalPaths()
	for i := 0; i < 2; i++ {
		before, err := os.Lstat(paths[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := s.intrusionJournalWriteFile(context.Background(), lock, p, raw, i, "rolled_back"); err != nil {
			t.Fatal(err)
		}
		after, err := os.Lstat(paths[i])
		if err != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
			t.Fatal("known no-op replaced original file", err)
		}
	}
	if err := s.intrusionJournalWriteFile(context.Background(), lock, p, raw, 2, "rolled_back"); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatal("known file no-op reached a command")
	}
}

func TestIntrusionJournalFileStepRetainsBoundedOriginalPartialEvidenceWithoutPromotingIt(t *testing.T) {
	s, _, _, lock, p, raw := intrusionPendingObservationFixture(t)
	name := ".intrusion-" + p.ID + "-jail-" + core.ID() + ".tmp"
	file := filepath.Join(filepath.Dir(s.intrusionJournalPaths()[0]), name)
	partial := []byte("partial")
	if err := os.WriteFile(file, partial, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.intrusionJournalWriteFile(context.Background(), lock, p, raw, 0, "committed"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(file)
	data, readErr := os.ReadFile(file)
	if err != nil || readErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !bytes.Equal(partial, data) {
		t.Fatal("partial evidence removed, repaired or promoted", err, readErr)
	}
	actual, err := os.ReadFile(s.intrusionJournalPaths()[0])
	if err != nil || !bytes.Equal(actual, p.Files[0].After.Data) {
		t.Fatal("partial became actual Jail", err)
	}
}

func TestIntrusionJournalFileStepRejectsForeignDataUnsafeParentsAndUnboundRecords(t *testing.T) {
	for _, kind := range []string{"foreign-jail", "foreign-manifest", "policy-symlink", "unsafe-parent", "foreign-temporary", "wrong-slot-temporary", "fifo-temporary", "lock", "record", "slot", "state"} {
		t.Run(kind, func(t *testing.T) {
			s, _, calls, lock, p, raw := intrusionPendingObservationFixture(t)
			paths := s.intrusionJournalPaths()
			slot, state := 0, "committed"
			switch kind {
			case "foreign-jail":
				if err := os.WriteFile(paths[0], []byte("# manual foreign jail\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "foreign-manifest":
				if err := os.WriteFile(paths[1], []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "policy-symlink":
				if err := os.Symlink("intrusion-prevention.json", paths[2]); err != nil {
					t.Fatal(err)
				}
			case "unsafe-parent":
				if err := os.Chmod(filepath.Dir(paths[0]), 0777); err != nil {
					t.Fatal(err)
				}
			case "foreign-temporary":
				name := ".intrusion-" + core.ID() + "-jail-" + core.ID() + ".tmp"
				if err := os.WriteFile(filepath.Join(filepath.Dir(paths[0]), name), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-slot-temporary":
				name := ".intrusion-" + p.ID + "-manifest-" + core.ID() + ".tmp"
				if err := os.WriteFile(filepath.Join(filepath.Dir(paths[0]), name), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "fifo-temporary":
				name := ".intrusion-" + p.ID + "-jail-" + core.ID() + ".tmp"
				if err := unix.Mkfifo(filepath.Join(filepath.Dir(paths[0]), name), 0600); err != nil {
					t.Fatal(err)
				}
			case "lock":
				lock = nil
			case "record":
				raw = append(bytes.Clone(raw), ' ')
			case "slot":
				slot = 3
			case "state":
				state = "unban --all"
			}
			before, err := os.ReadFile(paths[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := s.intrusionJournalWriteFile(context.Background(), lock, p, raw, slot, state); err == nil {
				t.Fatal("unsafe original state produced filesystem mutation")
			}
			after, err := os.ReadFile(paths[0])
			if err != nil || !bytes.Equal(before, after) || *calls != 0 {
				t.Fatal("repaired foreign state or invoked command", err)
			}
		})
	}
}

func TestIntrusionJournalTemporaryClassifierIsClosedAndNotMutationAuthority(t *testing.T) {
	p := intrusionJournalFixture(t)
	name := ".intrusion-" + p.ID + "-jail-" + core.ID() + ".tmp"
	entry := intrusionConfigurationEntry{Kind: "file", Mode: 0600, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), Device: 1, Inode: 90, Size: 0, SHA256: core.Hash("")}
	if err := intrusionJournalTemporaryValidate(p, name, 0, entry); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"uid", "gid", "mode", "type", "size", "hash", "slot", "id", "nonce"} {
		v := entry
		file := name
		slot := 0
		switch kind {
		case "uid":
			v.UID++
		case "gid":
			v.GID += 100
		case "mode":
			v.Mode = 0666
		case "type":
			v.Kind = "directory"
		case "size":
			v.Size = int64(len(p.Files[0].After.Data) + len(p.Files[0].Before.Data) + 1)
		case "hash":
			v.SHA256 = strings.Repeat("z", 64)
		case "slot":
			slot = 1
		case "id":
			file = strings.Replace(file, p.ID, core.ID(), 1)
		case "nonce":
			file = strings.Replace(file, ".tmp", "x.tmp", 1)
		}
		if err := intrusionJournalTemporaryValidate(p, file, slot, v); err == nil {
			t.Fatal("unknown temporary ignored", kind)
		}
	}
}
