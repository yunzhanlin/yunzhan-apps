//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func threatIDSIndependentFixture(t *testing.T) (*Service, threatIDSArchive, string, *threatIDSRotationPending, threatIDSRotation) {
	t.Helper()
	s := threatIDSRotationRootFixture(t)
	entry, path := threatIDSRotationArchiveFixture(t, s)
	if err := os.Chown(path, 800, 801); err != nil {
		t.Fatal(err)
	}
	p := &threatIDSRotationPending{CopyFormat: 2, ID: entry.ID, At: entry.At, Device: entry.Device, Inode: entry.Inode,
		UID: 800, GID: 801, Revision: 1, RuntimeSHA: core.Hash("runtime"), UnitSHA: core.Hash("unit")}
	v := threatIDSRotation{Format: 2, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}, Pending: p}
	if err := s.writeThreatIDSRotation(v); err != nil {
		t.Fatal(err)
	}
	return s, entry, path, p, v
}

func TestThreatIDSIndependentArchiveRecordFormat(t *testing.T) {
	witness := &threatIDSArchiveSource{Device: 1, Inode: 2, UID: 800, GID: 801, Bytes: 12, SHA: core.Hash("source")}
	entry := threatIDSArchive{ID: core.ID(), At: core.Now(), Device: 1, Inode: 3, Bytes: 12, SHA: witness.SHA, Source: witness}
	p := &threatIDSRotationPending{CopyFormat: 2, ID: entry.ID, At: entry.At, Device: 1, Inode: 2, UID: 800, GID: 801,
		Revision: 1, RuntimeSHA: core.Hash("runtime"), UnitSHA: core.Hash("unit"), Source: witness, Sealed: &entry}
	v := threatIDSRotation{Format: 2, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}, Pending: p}
	if err := validateThreatIDSRotation(v); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*threatIDSRotation){
		func(v *threatIDSRotation) { v.Format = 1 },
		func(v *threatIDSRotation) { v.Pending.CopyFormat = 1 },
		func(v *threatIDSRotation) { v.Pending.Source.Inode++ },
		func(v *threatIDSRotation) { v.Pending.Source.UID = 0 },
		func(v *threatIDSRotation) { v.Pending.Source.Bytes = threatEVEByteLimit + 1 },
		func(v *threatIDSRotation) { v.Pending.Sealed.Source = nil },
		func(v *threatIDSRotation) { v.Pending.Sealed.Inode = v.Pending.Inode },
		func(v *threatIDSRotation) { v.Pending.Sealed.SHA = core.Hash("different") },
	} {
		raw, _ := json.Marshal(v)
		var bad threatIDSRotation
		if err := json.Unmarshal(raw, &bad); err != nil {
			t.Fatal(err)
		}
		mutate(&bad)
		if validateThreatIDSRotation(bad) == nil {
			t.Fatal("unbound copy record accepted")
		}
	}
	raw, _ := json.Marshal(v)
	var decoded threatIDSRotation
	if err := decodeThreatIDSPrivateJSON(raw, &decoded); err != nil || !sameThreatIDSArchive(*decoded.Pending.Sealed, entry) {
		t.Fatal("valid independent witness did not survive its private journal", err)
	}
}

func TestThreatIDSIndependentArchiveInterruptedPreparation(t *testing.T) {
	account := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	for _, phase := range []string{"source-persist-fails", "copy-persist-fails", "copy-persisted-before-publication"} {
		t.Run(phase, func(t *testing.T) {
			s, original, path, p, v := threatIDSIndependentFixture(t)
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = threatIDSSealArchive(context.Background(), path, p, account, func() error {
				if phase == "source-persist-fails" && p.Sealed == nil {
					return errors.New("owned source persistence failure")
				}
				if p.Sealed != nil {
					if phase == "copy-persisted-before-publication" {
						if err := s.writeThreatIDSRotation(v); err != nil {
							return err
						}
					}
					return errors.New("owned copy preparation failure")
				}
				return s.writeThreatIDSRotation(v)
			})
			if err == nil {
				t.Fatal("failed journal allowed publication")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("unpublished copy acquired a pathname", err)
			}
			producer := filepath.Join(filepath.Dir(path), threatIDSProducerName(p.ID))
			got, err := os.ReadFile(producer)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("original producer changed", err)
			}
			info, err := os.Lstat(producer)
			if err != nil {
				t.Fatal(err)
			}
			owner := info.Sys().(*syscall.Stat_t)
			if owner.Uid != 800 || owner.Gid != 801 || owner.Ino != original.Inode {
				t.Fatal("producer metadata changed before private publication")
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(producer) {
				t.Fatal("anonymous failure left a named partial or hid another file", err)
			}
			recovered, err := s.readThreatIDSRotation()
			if err != nil || recovered.Pending == nil {
				t.Fatal(err)
			}
			switch phase {
			case "source-persist-fails":
				if recovered.Pending.Source != nil || recovered.Pending.Sealed != nil {
					t.Fatal("failed source write was treated as durable")
				}
			case "copy-persist-fails":
				if recovered.Pending.Source == nil || recovered.Pending.Sealed != nil {
					t.Fatal("wrong persisted preparation stage")
				}
			case "copy-persisted-before-publication":
				if recovered.Pending.Source == nil || recovered.Pending.Sealed == nil {
					t.Fatal("durable preparation was lost")
				}
			}
			sealed, err := threatIDSSealArchive(context.Background(), path, recovered.Pending, account, func() error { return s.writeThreatIDSRotation(recovered) })
			if err != nil || sealed.Source == nil || sealed.Inode == original.Inode {
				t.Fatal("exact retained source could not finish preparation", err)
			}
			got, err = s.readThreatIDSArchiveSnapshot(context.Background(), sealed)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("recovered copy changed bytes", err)
			}
			if _, err := threatIDSSealArchive(context.Background(), path, recovered.Pending, account, func() error {
				t.Fatal("verified published copy rewrote its preparation")
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestThreatIDSIndependentArchivePreparedSourceEditRefused(t *testing.T) {
	s, _, path, p, v := threatIDSIndependentFixture(t)
	account := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	_, err := threatIDSSealArchive(context.Background(), path, p, account, func() error {
		if err := s.writeThreatIDSRotation(v); err != nil {
			return err
		}
		if p.Sealed != nil {
			return errors.New("owned interruption after durable preparation")
		}
		return nil
	})
	if err == nil {
		t.Fatal("interruption not retained")
	}
	recovered, err := s.readThreatIDSRotation()
	if err != nil || recovered.Pending.Sealed == nil {
		t.Fatal(err)
	}
	witness := *recovered.Pending.Source
	producer := filepath.Join(filepath.Dir(path), threatIDSProducerName(p.ID))
	if err := os.WriteFile(producer, []byte("changed producer retained as evidence\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := threatIDSSealArchive(context.Background(), path, recovered.Pending, account, func() error {
		t.Fatal("changed producer was reauthenticated")
		return nil
	}); err == nil {
		t.Fatal("changed producer produced a different authoritative copy")
	}
	if *recovered.Pending.Source != witness {
		t.Fatal("original witness was overwritten")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("changed source was published", err)
	}
}

func TestThreatIDSIndependentArchiveUnsafeSourcePreserved(t *testing.T) {
	account := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	for _, kind := range []string{"symlink", "hardlink", "foreign-owner", "public-mode", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			s, _, path, p, _ := threatIDSIndependentFixture(t)
			switch kind {
			case "symlink":
				target := filepath.Join(s.Config.SystemRoot, "owned-link-target")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(s.Config.SystemRoot, "owned-linked-source")); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				if err := os.Chown(path, 900, 901); err != nil {
					t.Fatal(err)
				}
			case "public-mode":
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "fifo", "directory":
				if err := os.Rename(path, filepath.Join(s.Config.SystemRoot, "owned-original-source")); err != nil {
					t.Fatal(err)
				}
				if kind == "fifo" {
					if err := syscall.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := threatIDSSealArchive(context.Background(), path, p, account, func() error {
				t.Fatal("unsafe source wrote preparation metadata")
				return nil
			}); err == nil {
				t.Fatal("unsafe source accepted", kind)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("unsafe source repaired or replaced", err)
			}
			if _, err := os.Lstat(filepath.Join(filepath.Dir(path), threatIDSProducerName(p.ID))); !os.IsNotExist(err) {
				t.Fatal("unsafe source was moved", err)
			}
		})
	}
}

func threatIDSIndependentRetirementFixture(t *testing.T) (*Service, threatIDSRotation) {
	t.Helper()
	s := threatIDSRotationRootFixture(t)
	v := threatIDSRotation{Format: 2, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}}
	for range threatIDSHistoryLimit + 1 {
		entry, path := threatIDSRotationArchiveFixture(t, s)
		if err := os.Chown(path, 800, 801); err != nil {
			t.Fatal(err)
		}
		p := &threatIDSRotationPending{CopyFormat: 2, ID: entry.ID, At: entry.At, Device: entry.Device, Inode: entry.Inode,
			UID: 800, GID: 801, Revision: 1, RuntimeSHA: core.Hash("runtime"), UnitSHA: core.Hash("unit")}
		sealed, err := threatIDSSealArchive(context.Background(), path, p, threatIDSAccount{Format: 1, UID: 800, GID: 801}, func() error {
			return moduleWrite(filepath.Join(s.Config.SystemRoot, "preparation-"+entry.ID+".json"), p)
		})
		if err != nil {
			t.Fatal(err)
		}
		v.Archives = append(v.Archives, sealed)
	}
	if err := s.writeThreatIDSRotation(v); err != nil {
		t.Fatal(err)
	}
	return s, v
}

func TestThreatIDSIndependentArchivePairedRetirement(t *testing.T) {
	s, v := threatIDSIndependentRetirementFixture(t)
	oldest := v.Archives[0]
	dir, err := s.threatIDSHistoryDirectory(false)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.retireThreatIDSArchiveContext(context.Background(), v)
	if err != nil || len(result.Archives) != threatIDSHistoryLimit || len(result.Retired) != 1 || !sameThreatIDSArchive(result.Retired[0], oldest) {
		t.Fatal(result, err)
	}
	for _, name := range []string{"eve-" + oldest.ID + ".json", "retiring-eve-" + oldest.ID + ".json", threatIDSProducerName(oldest.ID), threatIDSRetiringProducerName(oldest.ID)} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("retired pair left an unexpected object", name, err)
		}
	}
	for _, entry := range result.Archives {
		if _, err := s.readThreatIDSArchiveSnapshot(context.Background(), entry); err != nil {
			t.Fatal(err)
		}
	}
	sources, summary, err := s.threatIDSHistorySources(context.Background())
	if err != nil || len(sources) != threatIDSHistoryLimit || summary.IndependentCopies != threatIDSHistoryLimit || summary.LegacyArchives != 0 {
		t.Fatal(summary, err)
	}
}

func TestThreatIDSIndependentArchiveRetirementInterrupted(t *testing.T) {
	for _, phase := range []string{"intent", "copy-staged", "pair-staged", "authorized", "producer-removed", "pair-removed", "producer-bytes-changed"} {
		t.Run(phase, func(t *testing.T) {
			s, v := threatIDSIndependentRetirementFixture(t)
			oldest := v.Archives[0]
			dir, err := s.threatIDSHistoryDirectory(false)
			if err != nil {
				t.Fatal(err)
			}
			v.Retiring = &oldest
			original := filepath.Join(dir, "eve-"+oldest.ID+".json")
			staged := filepath.Join(dir, "retiring-eve-"+oldest.ID+".json")
			if phase == "producer-bytes-changed" {
				if err := os.WriteFile(filepath.Join(dir, threatIDSProducerName(oldest.ID)), []byte("old producer descriptor changed these bytes\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if phase != "intent" {
				if err := os.Rename(original, staged); err != nil {
					t.Fatal(err)
				}
				if phase != "copy-staged" {
					if err := threatIDSStageProducerRetirement(context.Background(), dir, oldest); err != nil {
						t.Fatal(err)
					}
					if phase != "pair-staged" {
						v.RetirementUnlink = true
						if phase == "producer-removed" || phase == "pair-removed" {
							if err := threatIDSUnlinkRetiringProducer(context.Background(), dir, oldest, true); err != nil {
								t.Fatal(err)
							}
						}
						if phase == "pair-removed" {
							if err := os.Remove(staged); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
			}
			if err := wafBodyLogSyncDirectory(dir); err != nil {
				t.Fatal(err)
			}
			if err := s.writeThreatIDSRotation(v); err != nil {
				t.Fatal(err)
			}
			// Re-read the durable JSON rather than passing shared pointer identities.
			recovered, err := s.readThreatIDSRotation()
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.retireThreatIDSArchiveContext(context.Background(), recovered)
			if err != nil || result.Retiring != nil || result.RetirementUnlink || len(result.Archives) != threatIDSHistoryLimit || len(result.Retired) != 1 || !sameThreatIDSArchive(result.Retired[0], oldest) {
				t.Fatal(result, err)
			}
			sources, summary, err := s.threatIDSHistorySources(context.Background())
			if err != nil || len(sources) != threatIDSHistoryLimit || summary.IndependentCopies != threatIDSHistoryLimit {
				t.Fatal(summary, err)
			}
			before, err := os.ReadFile(s.threatIDSRotationPath())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.retireThreatIDSArchiveContext(context.Background(), result); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(s.threatIDSRotationPath())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("completed retirement rewrote its journal", err)
			}
		})
	}
}

func TestThreatIDSIndependentArchiveRetirementUnknownPreserved(t *testing.T) {
	for _, kind := range []string{"unknown", "producer-missing", "producer-hardlink", "producer-symlink", "producer-mode", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			s, v := threatIDSIndependentRetirementFixture(t)
			dir, err := s.threatIDSHistoryDirectory(false)
			if err != nil {
				t.Fatal(err)
			}
			oldest := v.Archives[0]
			producer := filepath.Join(dir, threatIDSProducerName(oldest.ID))
			switch kind {
			case "unknown":
				if err := os.WriteFile(filepath.Join(dir, "unknown-evidence"), []byte("keep\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "producer-missing":
				if err := os.Rename(producer, filepath.Join(s.Config.SystemRoot, "preserved-missing-producer")); err != nil {
					t.Fatal(err)
				}
			case "producer-hardlink":
				if err := os.Link(producer, filepath.Join(s.Config.SystemRoot, "preserved-producer-link")); err != nil {
					t.Fatal(err)
				}
			case "producer-symlink":
				target := filepath.Join(s.Config.SystemRoot, "preserved-link-target")
				if err := os.Rename(producer, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, producer); err != nil {
					t.Fatal(err)
				}
			case "producer-mode":
				if err := os.Chmod(producer, 0640); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			if kind == "canceled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			result, err := s.retireThreatIDSArchiveContext(ctx, v)
			if err == nil || len(result.Archives) != threatIDSHistoryLimit+1 || len(result.Retired) != 0 {
				t.Fatal("unknown state became successful retirement", err)
			}
			path := filepath.Join(dir, "eve-"+oldest.ID+".json")
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				path = filepath.Join(dir, "retiring-eve-"+oldest.ID+".json")
			}
			if _, err := readThreatIDSPrivateArchiveFile(context.Background(), oldest, path); err != nil {
				t.Fatal("authoritative old copy lost", err)
			}
			for _, entry := range v.Archives[1:] {
				if _, err := s.readThreatIDSArchiveSnapshot(context.Background(), entry); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
