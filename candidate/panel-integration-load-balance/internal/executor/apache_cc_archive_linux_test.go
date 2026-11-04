//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func apacheCCArchiveFixture(t *testing.T, data []byte) (*Service, string, string, []byte) {
	t.Helper()
	s, body, originalBody := apacheNumericLogFixture(t)
	live := s.systemPath(apacheCCLogPath)
	if err := os.WriteFile(live, data, 0600); err != nil {
		t.Fatal(err)
	}
	return s, live, body, originalBody
}

func TestApacheCCArchiveOriginalBytesAndInterruptedPhasesNeverReplay(t *testing.T) {
	for _, failAt := range []string{"", "intent-durable", "copy-created", "copy-durable", "prepared-durable", "names-exchanged", "sealed-durable", "completed-durable"} {
		t.Run(failAt, func(t *testing.T) {
			ctx := context.Background()
			data := []byte("original event with private IP and path\nunknown partial suffix")
			s, live, body, originalBody := apacheCCArchiveFixture(t, data)
			before, _ := os.Lstat(live)
			id := core.ID()
			injected := errors.New("owned interrupted phase")
			entry, err := s.archiveApacheCCLogAt(ctx, id, func(stage string) error {
				if stage == failAt {
					return injected
				}
				return nil
			})
			if failAt == "" && (err != nil || entry.State != "completed" || !entry.Intent.TailIncomplete) || failAt != "" && !errors.Is(err, injected) {
				t.Fatal("phase outcome changed", failAt, entry, err)
			}
			rows, err := s.apacheCCArchiveInventory(ctx)
			if err != nil || len(rows) != 1 {
				t.Fatal("original intent lost", rows, err)
			}
			exchanged := failAt == "" || failAt == "names-exchanged" || failAt == "sealed-durable" || failAt == "completed-durable"
			originalPath := live
			if exchanged {
				originalPath = filepath.Join(s.apacheCCArchiveDirectory(), id, "next.log")
			}
			actual, _ := os.ReadFile(originalPath)
			identity, _ := os.Lstat(originalPath)
			if !bytes.Equal(actual, data) || !os.SameFile(before, identity) {
				t.Fatal("original inode or bytes were changed")
			}
			if raw, _ := os.ReadFile(body); !bytes.Equal(raw, originalBody) {
				t.Fatal("body log namespace was touched")
			}
			if exchanged {
				current, _ := os.Lstat(live)
				if os.SameFile(current, before) || current.Size() != 0 || current.Mode().Perm() != 0600 {
					t.Fatal("active name did not atomically select a private empty inode")
				}
			}
			completed := failAt == "" || failAt == "completed-durable"
			if (s.apacheCCArchiveReadFence(ctx) == nil) != completed {
				t.Fatal("unknown phase was treated as a completed archive")
			}
			originalTree := programQueueTree(t, s.Config.SystemRoot)
			calls := 0
			again, retryErr := s.archiveApacheCCLogAt(ctx, id, func(string) error { calls++; return nil })
			if calls != 0 || (retryErr == nil) != completed || completed && again.State != "completed" || !reflect.DeepEqual(originalTree, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("original operation was repeated or its evidence changed", retryErr, calls)
			}
			if !completed {
				if _, err := s.archiveApacheCCLogAt(ctx, core.ID(), nil); err == nil {
					t.Fatal("new request bypassed an original unknown result")
				}
				if !reflect.DeepEqual(originalTree, programQueueTree(t, s.Config.SystemRoot)) {
					t.Fatal("unknown refusal changed original data")
				}
			}
		})
	}
}

func TestApacheCCArchiveExclusionCapacityAndIndependentBodyNamespace(t *testing.T) {
	ctx := context.Background()
	s, live, body, originalBody := apacheCCArchiveFixture(t, []byte("one\n"))
	writer, err := os.OpenFile(live, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := syscall.Flock(int(writer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	before := programQueueTree(t, s.Config.SystemRoot)
	if _, err := s.archiveApacheCCLogAt(ctx, core.ID(), nil); err == nil || !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
		t.Fatal("busy writer created an intent or changed bytes", err)
	}
	if err := syscall.Flock(int(writer.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < apacheCCArchiveCount; i++ {
		data := []byte(strings.Repeat("event\n", i+1))
		if err := os.WriteFile(live, data, 0600); err != nil {
			t.Fatal(err)
		}
		entry, err := s.archiveApacheCCLogAt(ctx, core.ID(), nil)
		if err != nil || entry.State != "completed" || entry.Completed.Archive.SHA256 != core.Hash(string(data)) {
			t.Fatal("real exchange failed", entry, err)
		}
	}
	if err := os.WriteFile(live, []byte("capacity preserved\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before = programQueueTree(t, s.Config.SystemRoot)
	if _, err := s.archiveApacheCCLogAt(ctx, core.ID(), nil); err == nil || !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
		t.Fatal("capacity rejection removed history or active data", err)
	}
	if raw, _ := os.ReadFile(body); !bytes.Equal(raw, originalBody) {
		t.Fatal("CC archive changed original body data")
	}
}

func TestApacheCCArchiveRefusesForeignFilesAndCorruptReceiptsWithoutRepair(t *testing.T) {
	for _, kind := range []string{"empty", "symlink", "hardlink", "public", "oversize", "cancelled", "archive-tamper", "record-public", "partial-receipt", "unknown-file"} {
		t.Run(kind, func(t *testing.T) {
			s, live, _, _ := apacheCCArchiveFixture(t, []byte("original\n"))
			ctx := context.Background()
			id := core.ID()
			if kind == "archive-tamper" || kind == "record-public" || kind == "partial-receipt" || kind == "unknown-file" {
				if _, err := s.archiveApacheCCLogAt(ctx, id, nil); err != nil {
					t.Fatal(err)
				}
				dir := filepath.Join(s.apacheCCArchiveDirectory(), id)
				switch kind {
				case "archive-tamper":
					if err := os.WriteFile(filepath.Join(dir, "data.log"), []byte("forged\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "record-public":
					if err := os.Chmod(filepath.Join(dir, "completed.json"), 0644); err != nil {
						t.Fatal(err)
					}
				case "partial-receipt":
					if err := os.WriteFile(filepath.Join(dir, "completed.json"), []byte("{\"format\":"), 0600); err != nil {
						t.Fatal(err)
					}
				case "unknown-file":
					if err := os.WriteFile(filepath.Join(dir, "unowned"), []byte("original evidence"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				switch kind {
				case "empty":
					if err := os.Truncate(live, 0); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					other := live + ".old"
					if err := os.Rename(live, other); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(other, live); err != nil {
						t.Fatal(err)
					}
				case "hardlink":
					if err := os.Link(live, live+".alias"); err != nil {
						t.Fatal(err)
					}
				case "public":
					if err := os.Chmod(live, 0644); err != nil {
						t.Fatal(err)
					}
				case "oversize":
					if err := os.Truncate(live, apacheCCLogMaxBytes+1); err != nil {
						t.Fatal(err)
					}
				case "cancelled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
			}
			before := programQueueTree(t, s.Config.SystemRoot)
			if _, err := s.archiveApacheCCLogAt(ctx, core.ID(), nil); err == nil {
				t.Fatal("unsafe request was admitted")
			}
			if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("refusal repaired, removed or rewrote original evidence")
			}
		})
	}
}

func TestApacheCCArchiveOriginalRequestAndPartialTailNeedExplicitAuthority(t *testing.T) {
	s, _, _, _ := apacheCCArchiveFixture(t, []byte("original partial"))
	ctx := context.Background()
	in := core.ApacheCCArchiveRequest{RequestID: core.ID(), ExpectedRevision: 7}
	before := programQueueTree(t, s.Config.SystemRoot)
	if _, err := s.archiveApacheCCLogRequestAt(ctx, in, nil); err == nil || !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
		t.Fatal("partial tail was archived without explicit original option", err)
	}
	in.AllowIncomplete = true
	entry, err := s.archiveApacheCCLogRequestAt(ctx, in, nil)
	if err != nil || entry.State != "completed" || entry.Intent.Request != in {
		t.Fatal(entry, err)
	}
	before = programQueueTree(t, s.Config.SystemRoot)
	for _, changed := range []core.ApacheCCArchiveRequest{{RequestID: in.RequestID, ExpectedRevision: 8, AllowIncomplete: true}, {RequestID: in.RequestID, ExpectedRevision: 7, AllowIncomplete: false}} {
		if _, err := s.archiveApacheCCLogRequestAt(ctx, changed, nil); err == nil {
			t.Fatal("original request adopted different parameters")
		}
		if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
			t.Fatal("mismatched original request changed evidence")
		}
	}
}

func TestApacheCCArchiveProgrammeFencePreservesOriginalInterruptedEvidence(t *testing.T) {
	for _, stage := range []string{"", "prepared-durable", "names-exchanged", "sealed-durable"} {
		t.Run(stage, func(t *testing.T) {
			s, _, _, _ := apacheCCArchiveFixture(t, []byte("one\n"))
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			lock.Close()
			_, archiveErr := s.archiveApacheCCLogAt(context.Background(), core.ID(), func(at string) error {
				if at == stage {
					return errors.New("owned interruption")
				}
				return nil
			})
			if stage == "" && archiveErr != nil || stage != "" && archiveErr == nil {
				t.Fatal(archiveErr)
			}
			before := programQueueTree(t, s.Config.SystemRoot)
			if err := checkApacheNumericLogUpgrade(context.Background(), s.Config.SystemRoot); (err == nil) != (stage == "") {
				t.Fatal("upgrade crossed an unresolved archive", stage, err)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("programme fence changed original archive state")
			}
		})
	}
}
