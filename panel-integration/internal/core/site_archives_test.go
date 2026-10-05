package core

import (
	"database/sql"
	"errors"
	"testing"
)

func TestSiteArchiveReleasesAppBindingAndDomainButKeepsAudit(t *testing.T) {
	s := testStore(t)
	project := ID()
	_, e := s.CreateAppProxySite("博客", "archive-blog", "archive.example.test", project, 18480, "create-archive", "admin")
	if e != nil {
		t.Fatal(e)
	}
	create, e := s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Finish(create, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueSiteArchive(create.SiteID, "wrong.example.test", "archive-one", "admin"); e == nil {
		t.Fatal("wrong confirmation accepted")
	}
	jobID, e := s.QueueSiteArchive(create.SiteID, "archive.example.test", "archive-one", "admin")
	if e != nil {
		t.Fatal(e)
	}
	same, e := s.QueueSiteArchive(create.SiteID, "archive.example.test", "archive-one", "admin")
	if e != nil || same != jobID {
		t.Fatal("archive idempotency failed", e)
	}
	if _, e = s.QueueSiteArchive(create.SiteID, "other.example.test", "archive-one", "admin"); e == nil {
		t.Fatal("changed archive reused key")
	}
	archive, e := s.NextJob()
	if e != nil || archive.ID != jobID {
		t.Fatal("wrong archive job", e)
	}
	if e = s.Finish(archive, "archived", "", nil); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Site(create.SiteID); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("archived site still directly accessible", e)
	}
	visible, e := s.Sites()
	if e != nil || len(visible) != 0 {
		t.Fatal("archived site remained in list", e)
	}
	if name, e := s.ProjectSiteReference(project); e != nil || name != "" {
		t.Fatal("project binding was not released", name, e)
	}
	var original string
	if e = s.DB.QueryRow(`SELECT original_domain FROM site_archives WHERE site_id=?`, create.SiteID).Scan(&original); e != nil || original != "archive.example.test" {
		t.Fatal("original domain not preserved", e)
	}
	if _, e = s.Job(jobID); e != nil {
		t.Fatal("archive job history lost", e)
	}
	if _, e = s.CreateSiteAtDomain("新博客", "archive-blog", "archive.example.test", "reuse-domain", "admin"); e != nil {
		t.Fatal("domain or slug remained reserved", e)
	}
}

func TestSiteArchiveBlocksDependentBackup(t *testing.T) {
	s := testStore(t)
	_, e := s.CreateSite("备份站", "backup-site", "create-backup", "admin")
	if e != nil {
		t.Fatal(e)
	}
	job, e := s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Finish(job, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	_, e = s.DB.Exec(`INSERT INTO site_backups(id,site_id,format,files,source_bytes,bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?,?)`, ID(), job.SiteID, "zip", 1, 100, 90, Hash("test"), Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueSiteArchive(job.SiteID, "backup-site.localhost", "archive-backup", "admin"); e == nil {
		t.Fatal("dependent backup was ignored")
	}
}
