package core

import "testing"

func TestAppProxySiteBindingIsAtomicAndIdempotent(t *testing.T) {
	s := testStore(t)
	project := ID()
	job, err := s.CreateAppProxySite("博客", "blog-site", "blog.example.test", project, 18480, "bind-one", "admin")
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.CreateAppProxySite("博客", "blog-site", "blog.example.test", project, 18480, "bind-one", "admin")
	if err != nil || same != job {
		t.Fatalf("idempotency: %q %v", same, err)
	}
	for _, change := range []struct {
		project string
		port    int
		domain  string
	}{
		{project, 18481, "blog.example.test"},
		{ID(), 18480, "blog.example.test"},
		{project, 18480, "other.example.test"},
	} {
		if _, err := s.CreateAppProxySite("博客", "blog-site", change.domain, change.project, change.port, "bind-one", "admin"); err == nil {
			t.Fatal("changed binding reused idempotency key")
		}
	}
	if _, err := s.CreateAppProxySite("另一站", "other-blog", "blog.example.test", ID(), 18481, "different-domain", "admin"); err == nil {
		t.Fatal("duplicate domain accepted")
	}
	if _, err := s.CreateAppProxySite("另一站", "other-blog", "other.example.test", project, 18481, "different-project", "admin"); err == nil {
		t.Fatal("duplicate project binding accepted")
	}
	if _, err := s.CreateAppProxySite("博客", "blog-site", "", ID(), 18482, "missing-domain", "admin"); err == nil {
		t.Fatal("blank domain accepted")
	}
	sites, err := s.Sites()
	if err != nil || len(sites) != 1 {
		t.Fatalf("failed binding left a site: %d %v", len(sites), err)
	}
	site := sites[0]
	if site.Settings.Mode != "proxy" || !site.Settings.ProxyPreserveHost || site.Settings.ProxyURL != "http://127.0.0.1:18480" {
		t.Fatal("initial proxy configuration was not persisted")
	}
	name, err := s.ProjectSiteReference(project)
	if err != nil || name != "博客" {
		t.Fatal("project reference missing", name, err)
	}
	claimed, err := s.NextJob()
	if err != nil || claimed.ID != job {
		t.Fatal("wrong create job", err)
	}
	if err := s.Finish(claimed, "running", "", nil); err != nil {
		t.Fatal(err)
	}
	settings := site.Settings
	settings.ProxyURL = "http://127.0.0.1:18481"
	configure, err := s.QueueSiteSettings(site.ID, settings, 0, Hash("current"), "detach-one", "admin")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = s.NextJob()
	if err != nil || claimed.ID != configure {
		t.Fatal("wrong configuration job", err)
	}
	if err := s.Finish(claimed, "needs_attention", "simulated failure", nil); err != nil {
		t.Fatal(err)
	}
	if name, err = s.ProjectSiteReference(project); err != nil || name != "博客" {
		t.Fatal("failed setting update detached live binding", name, err)
	}
	if err := s.Retry(configure, "admin"); err != nil {
		t.Fatal(err)
	}
	claimed, err = s.NextJob()
	if err != nil || claimed.ID != configure {
		t.Fatal("retry did not resume configuration", err)
	}
	if err := s.Finish(claimed, "running", "", nil); err != nil {
		t.Fatal(err)
	}
	if name, err = s.ProjectSiteReference(project); err != nil || name != "" {
		t.Fatal("updated proxy retained stale project reference", name, err)
	}
	if _, err := s.CreateAppProxySite("新博客", "new-blog", "new.example.test", project, 18480, "bind-new", "admin"); err != nil {
		t.Fatal("detached project cannot be rebound", err)
	}
}
