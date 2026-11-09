package core

import (
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestRuntimeReferencesKeepStoppedBindingsAndPendingSwitches(t *testing.T) {
	s := testStore(t)
	for _, id := range []string{"php-8.4.25", "php-8.5.10"} {
		release, ok := runtimecatalog.Find(id)
		if !ok {
			t.Fatal(id)
		}
		if e := s.RecordInstallation(release, "arm64"); e != nil {
			t.Fatal(e)
		}
	}
	_, e := s.CreateSite("bound php", "bound-php", ID(), "admin", "php-8.4.25")
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Finish(j, "stopped", "", nil); e != nil {
		t.Fatal(e)
	}
	refs, e := s.RuntimeReferences("php-8.4.25")
	if e != nil || len(refs) != 1 || refs[0].Kind != "site" || refs[0].State != "stopped" {
		t.Fatal("stopped PHP binding not protected", refs, e)
	}
	if _, e = s.QueuePHP(j.SiteID, "php-8.5.10", "admin"); e != nil {
		t.Fatal(e)
	}
	refs, e = s.RuntimeReferences("php-8.5.10")
	if e != nil || len(refs) != 1 || refs[0].Kind != "site_job" {
		t.Fatal("pending PHP switch not protected", refs, e)
	}
	release, _ := runtimecatalog.Find("mysql-8.4.11")
	s.RecordInstallation(release, "arm64")
	_, e = s.QueueDatabase(DatabaseOperation{Action: "create_instance", Server: DatabaseServer{Name: "stopped mysql", ReleaseID: release.ID, Port: 13306}}, ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	s.DB.Exec(`UPDATE mysql_servers SET status='stopped'`)
	refs, e = s.RuntimeReferences(release.ID)
	if e != nil || len(refs) != 1 || refs[0].Kind != "mysql_instance" {
		t.Fatal("stopped MySQL instance not protected", refs, e)
	}
	if _, e = s.RuntimeReferences("../../unknown"); e == nil {
		t.Fatal("unmanaged version accepted")
	}
}
