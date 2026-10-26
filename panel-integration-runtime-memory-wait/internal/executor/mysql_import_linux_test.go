//go:build linux

package executor

import (
	"context"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLImportStagingAndBoundaries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership is checked in Linux VM")
	}
	base := t.TempDir()
	os.Chmod(base, 0700)
	body := "CREATE TABLE notes(id INT);\n"
	v := core.DatabaseImport{ID: core.ID(), ServerID: core.ID(), Name: "notes", Bytes: int64(len(body))}
	staged, e := stageSQLImport(context.Background(), base, v, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	f, e := openSQLImport(context.Background(), base, staged)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(f)
	f.Close()
	if e != nil || string(got) != body {
		t.Fatal("stream bytes", e)
	}
	if _, e = stageSQLImport(context.Background(), base, v, strings.NewReader(body)); e != nil {
		t.Fatal("same upload recovery", e)
	}
	if _, e = stageSQLImport(context.Background(), base, v, strings.NewReader(strings.Repeat("x", len(body)))); e == nil {
		t.Fatal("changed upload accepted")
	}
	wrong := staged
	wrong.ServerID = core.ID()
	if f, e = openSQLImport(context.Background(), base, wrong); e == nil {
		f.Close()
		t.Fatal("wrong instance accepted")
	}
	path := filepath.Join(base, v.ID+".sql")
	os.Chmod(path, 0644)
	if f, e = openSQLImport(context.Background(), base, staged); e == nil {
		f.Close()
		t.Fatal("public SQL accepted")
	}
	os.Chmod(path, 0600)
	os.Link(path, path+".link")
	if f, e = openSQLImport(context.Background(), base, staged); e == nil {
		f.Close()
		t.Fatal("hardlink accepted")
	}
	os.Remove(path + ".link")
	os.Rename(path, path+".original")
	os.Symlink(path+".original", path)
	if f, e = openSQLImport(context.Background(), base, staged); e == nil {
		f.Close()
		t.Fatal("symlink accepted")
	}
	os.Remove(path)
	os.Rename(path+".original", path)
	v.ID = core.ID()
	if _, e = stageSQLImport(context.Background(), base, v, strings.NewReader("short")); e == nil {
		t.Fatal("truncated upload accepted")
	}
	if _, e = os.Stat(filepath.Join(base, v.ID+".part")); !os.IsNotExist(e) {
		t.Fatal("partial upload not removed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = stageSQLImport(ctx, base, v, strings.NewReader(body)); e == nil {
		t.Fatal("canceled upload accepted")
	}
}
