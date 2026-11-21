//go:build linux

package executor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBuildCopyCommitsFileBytesBeforeNamespaceAndPreservesInternalLinks(t *testing.T) {
	root := t.TempDir()
	source, dest := filepath.Join(root, "source"), filepath.Join(root, "pending")
	if err := os.MkdirAll(filepath.Join(source, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("original executable bytes\n"), 8192)
	if err := os.WriteFile(filepath.Join(source, "bin/httpd"), body, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "empty"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("httpd", filepath.Join(source, "bin/alias")); err != nil {
		t.Fatal(err)
	}
	var committed []string
	err := copyBuildTreeWithSync(source, dest, func(f *os.File) error {
		name, err := filepath.Rel(root, f.Name())
		if err != nil {
			return err
		}
		committed = append(committed, name)
		return f.Sync()
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pending/bin/httpd", "pending/empty", "pending/bin", "pending", "."}
	if !reflect.DeepEqual(committed, want) {
		t.Fatal("file bytes and child directory must commit before the containing namespace", committed)
	}
	for _, path := range []string{filepath.Join(source, "bin/httpd"), filepath.Join(dest, "bin/httpd")} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatal("original or copied bytes changed", path, err)
		}
	}
	if link, err := os.Readlink(filepath.Join(dest, "bin/alias")); err != nil || link != "httpd" {
		t.Fatal("internal symlink was followed or changed", link, err)
	}
}

func TestBuildCopyNeverReportsSuccessAfterFileOrDirectorySyncFailure(t *testing.T) {
	fault := errors.New("owned fsync I/O failure")
	for _, failed := range []string{"pending/bin/httpd", "pending/bin", "pending", "."} {
		t.Run(failed, func(t *testing.T) {
			root := t.TempDir()
			source, dest := filepath.Join(root, "source"), filepath.Join(root, "pending")
			if err := os.MkdirAll(filepath.Join(source, "bin"), 0755); err != nil {
				t.Fatal(err)
			}
			original := []byte("preserved original artifact")
			if err := os.WriteFile(filepath.Join(source, "bin/httpd"), original, 0755); err != nil {
				t.Fatal(err)
			}
			seenFailure := false
			err := copyBuildTreeWithSync(source, dest, func(f *os.File) error {
				if seenFailure {
					t.Fatal("continued namespace publication after a failed durability operation")
				}
				rel, err := filepath.Rel(root, f.Name())
				if err != nil {
					return err
				}
				if rel == failed {
					seenFailure = true
					return fault
				}
				return f.Sync()
			})
			if !seenFailure || !errors.Is(err, fault) {
				t.Fatal("a failed fsync became a successful copy", seenFailure, err)
			}
			got, err := os.ReadFile(filepath.Join(source, "bin/httpd"))
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("failed publication modified source bytes", err)
			}
		})
	}
}
