//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupDownloadChecksContentOwnershipAndBoundaries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real root file ownership is tested in the dedicated Linux VM")
	}
	base := t.TempDir()
	os.Chmod(base, 0700)
	data := []byte("CREATE TABLE sample(id INT);\nINSERT INTO sample VALUES(7);\n")
	sum := sha256.Sum256(data)
	b := core.DatabaseBackup{ID: core.ID(), ServerID: core.ID(), DatabaseID: core.ID(), Version: "8.4.11", Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), CreatedAt: core.Now()}
	dir := filepath.Join(base, b.ServerID)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	if err := os.WriteFile(filepath.Join(dir, b.ID+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, b.ID+".sql")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	valid := func() {
		t.Helper()
		f, actual, err := openVerifiedBackup(context.Background(), base, b)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		got, err := io.ReadAll(f)
		if err != nil || string(got) != string(data) || actual != b {
			t.Fatal("verified descriptor was not rewound", err)
		}
	}
	rejected := func(expected core.DatabaseBackup) {
		t.Helper()
		f, _, err := openVerifiedBackup(context.Background(), base, expected)
		if f != nil {
			f.Close()
		}
		if err == nil {
			t.Fatal("invalid backup accepted")
		}
	}
	valid()
	wrong := b
	wrong.DatabaseID = core.ID()
	rejected(wrong)
	wrong = b
	wrong.ServerID = "../escape"
	rejected(wrong)
	os.Chmod(file, 0644)
	rejected(b)
	os.Chmod(file, 0600)
	modified := append([]byte{}, data...)
	modified[0] ^= 1
	os.WriteFile(file, modified, 0600)
	rejected(b)
	os.WriteFile(file, data, 0600)
	link := filepath.Join(dir, "linked.sql")
	os.Link(file, link)
	rejected(b)
	os.Remove(link)
	os.Rename(file, file+".original")
	os.Symlink(file+".original", file)
	rejected(b)
	os.Remove(file)
	os.Rename(file+".original", file)
	os.Chmod(dir, 0755)
	rejected(b)
	os.Chmod(dir, 0700)
	valid()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f, _, err := openVerifiedBackup(ctx, base, b)
	if f != nil {
		f.Close()
	}
	if err == nil {
		t.Fatal("cancelled request continued reading")
	}
}

func TestScheduledBackupDeletionIsVerifiedAndIdempotent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real root file ownership is tested in the dedicated Linux VM")
	}
	base := t.TempDir()
	os.Chmod(base, 0700)
	data := []byte("CREATE TABLE retention(id INT);\n")
	sum := sha256.Sum256(data)
	b := core.DatabaseBackup{ID: core.ID(), ServerID: core.ID(), DatabaseID: core.ID(), Version: "8.4.11", Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), CreatedAt: core.Now()}
	dir := filepath.Join(base, b.ServerID)
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(b)
	if e := os.WriteFile(filepath.Join(dir, b.ID+".json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, b.ID+".sql"), data, 0600); e != nil {
		t.Fatal(e)
	}
	wrong := b
	wrong.SHA256 = core.Hash("wrong")
	if e := deleteVerifiedBackup(context.Background(), base, wrong); e == nil {
		t.Fatal("mismatched retention cleanup accepted")
	}
	request := b
	request.CreatedAt = ""
	if e := deleteVerifiedBackup(context.Background(), base, request); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, b.ID+".sql")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("backup content still exists", e)
	}
	if e := deleteVerifiedBackup(context.Background(), base, request); e != nil {
		t.Fatal("completed cleanup was not idempotent", e)
	}
	var receipt backupDeletionReceipt
	if raw, e := os.ReadFile(filepath.Join(dir, ".deleted-"+b.ID+".json")); e != nil || json.Unmarshal(raw, &receipt) != nil || receipt.State != "deleted" || receipt.Backup != request {
		t.Fatal("durable deletion receipt missing", e)
	}
}
