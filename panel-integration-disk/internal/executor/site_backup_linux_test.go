//go:build linux

package executor

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestSiteBackupRejectsLinksAndVerifiesArchive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real root ownership is tested in the Linux VM")
	}
	original := siteBackups
	siteBackups = filepath.Join(t.TempDir(), "backups")
	defer func() { siteBackups = original }()
	sites := filepath.Join(t.TempDir(), "sites")
	siteID := core.ID()
	public := filepath.Join(sites, siteID, "public")
	if e := os.MkdirAll(filepath.Join(public, "assets"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(sites, siteID, ".panel-site.json"), []byte(`{"id":"`+siteID+`"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(public, "index.html"), []byte("site backup acceptance"), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(public, "assets", "app.css"), []byte("body{}"), 0644); e != nil {
		t.Fatal(e)
	}
	service := New(Config{SitesDir: sites})
	expected := core.SiteBackup{ID: core.ID(), SiteID: siteID}
	backupDir := filepath.Join(siteBackups, siteID)
	if e := os.MkdirAll(backupDir, 0700); e != nil {
		t.Fatal(e)
	}
	partial := filepath.Join(backupDir, expected.ID+".zip.part")
	if e := os.WriteFile(partial, []byte("interrupted archive"), 0600); e != nil {
		t.Fatal(e)
	}
	backup, e := service.createSiteBackup(context.Background(), expected)
	if e != nil || backup.Files != 3 || backup.Bytes <= 0 || backup.SourceBytes != int64(len("site backup acceptance")+len("body{}")) || len(backup.SHA256) != 64 {
		t.Fatal("site backup result", backup, e)
	}
	if _, e = os.Stat(partial); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("interrupted part not removed", e)
	}
	again, e := service.createSiteBackup(context.Background(), expected)
	if e != nil || again != backup {
		t.Fatal("site backup replay was not idempotent", again, e)
	}
	archive, e := zip.OpenReader(filepath.Join(siteBackups, siteID, expected.ID+".zip"))
	if e != nil {
		t.Fatal(e)
	}
	names := map[string]string{}
	for _, item := range archive.File {
		if item.FileInfo().IsDir() {
			continue
		}
		reader, e := item.Open()
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(reader)
		reader.Close()
		if e != nil {
			t.Fatal(e)
		}
		names[item.Name] = string(body)
	}
	archive.Close()
	if names["public/index.html"] != "site backup acceptance" || names["public/assets/app.css"] != "body{}" {
		t.Fatal("archive content mismatch", names)
	}
	if e := os.Symlink("index.html", filepath.Join(public, "linked.html")); e != nil {
		t.Fatal(e)
	}
	if _, e = service.createSiteBackup(context.Background(), core.SiteBackup{ID: core.ID(), SiteID: siteID}); e == nil {
		t.Fatal("site backup followed a symbolic link")
	}
	os.Remove(filepath.Join(public, "linked.html"))
	deleteTarget, e := service.createSiteBackup(context.Background(), core.SiteBackup{ID: core.ID(), SiteID: siteID})
	if e != nil {
		t.Fatal(e)
	}
	deleteRequest := deleteTarget
	deleteRequest.Format, deleteRequest.Files, deleteRequest.SourceBytes, deleteRequest.CreatedAt = "", 0, 0, ""
	if e = deleteVerifiedSiteBackup(context.Background(), deleteRequest); e != nil {
		t.Fatal(e)
	}
	if e = deleteVerifiedSiteBackup(context.Background(), deleteRequest); e != nil {
		t.Fatal("site backup deletion was not idempotent", e)
	}
	if _, e = os.Stat(filepath.Join(siteBackups, siteID, deleteTarget.ID+".zip")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("deleted site archive still exists", e)
	}
	path := filepath.Join(siteBackups, siteID, expected.ID+".zip")
	file, e := os.OpenFile(path, os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = file.WriteAt([]byte{0}, 0)
	file.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = verifySiteBackup(context.Background(), backup); e == nil || errors.Is(e, os.ErrNotExist) {
		t.Fatal("tampered site archive was accepted", e)
	}
}
