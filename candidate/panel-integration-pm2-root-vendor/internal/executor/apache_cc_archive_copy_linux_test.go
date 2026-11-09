//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestApacheCCArchiveIndependentCopyRejectsUnsafeProvenanceWithoutRepair(t *testing.T) {
	for _, kind := range []string{"legacy-format", "missing-intent", "partial-intent", "same-source-inode", "copy-symlink", "copy-hardlink", "copy-public", "copy-foreign-owner"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _, _ := apacheCCArchiveFixture(t, []byte("original bytes\n"))
			ctx := context.Background()
			id := core.ID()
			entry, err := s.archiveApacheCCLogAt(ctx, id, nil)
			if err != nil {
				t.Fatal(err)
			}
			dir, _, err := s.apacheCCArchiveEntryDirectory(id)
			if err != nil {
				t.Fatal(err)
			}
			write := func(name string, v any) {
				t.Helper()
				raw, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "legacy-format":
				entry.Intent.Format = 1
				entry.Prepared.Format = 1
				entry.Completed.Format = 1
				write("intent.json", entry.Intent)
				write("prepared.json", entry.Prepared)
				write("completed.json", entry.Completed)
			case "missing-intent":
				if err := os.Rename(filepath.Join(dir, "intent.json"), filepath.Join(s.Config.SystemRoot, "preserved-intent.json")); err != nil {
					t.Fatal(err)
				}
			case "partial-intent":
				if err := os.WriteFile(filepath.Join(dir, "intent.json"), []byte("{\"format\":"), 0600); err != nil {
					t.Fatal(err)
				}
			case "same-source-inode":
				entry.Intent.Source.Inode = entry.Completed.Archive.Inode
				write("intent.json", entry.Intent)
			case "copy-symlink":
				if err := os.Rename(filepath.Join(dir, "data.log"), filepath.Join(s.Config.SystemRoot, "preserved-copy.log")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(dir, "next.log"), filepath.Join(dir, "data.log")); err != nil {
					t.Fatal(err)
				}
			case "copy-hardlink":
				if err := os.Link(filepath.Join(dir, "data.log"), filepath.Join(s.Config.SystemRoot, "retained-copy-alias.log")); err != nil {
					t.Fatal(err)
				}
			case "copy-public":
				if err := os.Chmod(filepath.Join(dir, "data.log"), 0644); err != nil {
					t.Fatal(err)
				}
			case "copy-foreign-owner":
				if os.Geteuid() != 0 {
					return
				} // Actual ownership case is mandatory in native Root suites.
				if err := os.Chown(filepath.Join(dir, "data.log"), 33, 33); err != nil {
					t.Fatal(err)
				}
			}
			before := programQueueTree(t, s.Config.SystemRoot)
			if got, err := s.readApacheCCArchive(ctx, id); err == nil && got.State == "completed" {
				t.Fatal("unsafe old/private-copy evidence admitted", kind)
			}
			if _, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil); err == nil {
				t.Fatal("unknown retention could relabel unsafe data as a Root copy", kind)
			}
			if _, err := s.apacheCCArchiveChunk(ctx, id, 0); err == nil {
				t.Fatal("unsafe copy exported", kind)
			}
			if err := s.apacheCCArchiveReadFence(ctx); err == nil {
				t.Fatal("unsafe copy qualified upgrade", kind)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("read-only rejection modified original evidence", kind)
			}
		})
	}
}
