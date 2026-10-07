package core

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAppModuleDefinitions(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range AppModules() {
		if seen[d.ID] || len(d.Actions) == 0 {
			t.Fatal(d)
		}
		seen[d.ID] = true
		guide := ModuleGuidance(d.ID)
		if guide.Description == "" || len(guide.Workflow) == 0 || len(guide.Limitations) == 0 {
			t.Fatal("missing actual behavior and limitations", d.ID)
		}
		for _, a := range d.Actions {
			if !ValidAppModuleAction(d.ID, a) {
				t.Fatal(d.ID, a)
			}
		}
		if ValidAppModuleAction(d.ID, "shell") {
			t.Fatal("unreviewed action accepted")
		}
	}
	if len(seen) != 20 {
		t.Fatal(len(seen))
	}
}
func TestAnalyticsGuidanceMatchesImplementedBoundaries(t *testing.T) {
	guide := ModuleGuidance("website-analytics")
	if !strings.Contains(guide.Description, "INP") || !strings.Contains(guide.Description, "转化漏斗") {
		t.Fatal("implemented analytics capabilities missing from guidance")
	}
	limits := strings.Join(guide.Limitations, " ")
	for _, boundary := range []string{"会话录像", "地理数据库", "SPA 路由性能", "20000", "8 MiB", "业务审计"} {
		if !strings.Contains(limits, boundary) {
			t.Fatal("missing truthful analytics boundary", boundary)
		}
	}
	if strings.Contains(limits, "INP 或完整转化漏斗") {
		t.Fatal("stale guidance denies implemented features")
	}
}
func TestAppModuleRoles(t *testing.T) {
	s := testStore(t)
	a := &Server{Store: s}
	s.DB.Exec(`INSERT INTO users(id,username,password_hash,created_at)VALUES('admin','admin','x',? ),('viewer','viewer','x',?)`, Now(), Now())
	s.DB.Exec(`INSERT INTO app_user_roles VALUES('viewer','viewer','["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]')`)
	u := identity{ID: "viewer"}
	for _, test := range []struct {
		method, path string
		want         bool
	}{{"GET", "/api/sites", true}, {"GET", "/api/sites/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/files", true}, {"POST", "/api/sites/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/files", false}, {"GET", "/api/sites/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/files", false}, {"GET", "/api/system/files", false}, {"GET", "/api/software", false}, {"POST", "/api/account/password", true}} {
		if got := a.appRoleAllowed(u, httptest.NewRequest(test.method, test.path, nil)); got != test.want {
			t.Fatal(test, got)
		}
	}
	if _, e := a.manageAppUsers(identity{ID: "admin"}, "delete", AppModuleInput{Username: "admin"}); e == nil {
		t.Fatal("last admin deleted")
	}
}
func TestPlatformTokenLifecycle(t *testing.T) {
	s := testStore(t)
	a := &Server{Store: s}
	v, e := a.platformOperation(context.Background(), "issue-token", AppModuleInput{})
	if e != nil {
		t.Fatal(e)
	}
	token := v.(map[string]any)["token"].(string)
	if len(token) != 64 {
		t.Fatal("invalid token")
	}
	var hash string
	if e = s.DB.QueryRow(`SELECT token_hash FROM app_platform_tokens`).Scan(&hash); e != nil || hash == token || hash != Hash(token) {
		t.Fatal("token stored unsafely")
	}
	if _, e = a.platformOperation(context.Background(), "revoke-token", AppModuleInput{Token: token}); e != nil {
		t.Fatal(e)
	}
	if _, e = a.platformOperation(context.Background(), "add", AppModuleInput{ResourceID: "test", URL: "http://example.com", Token: strings.Repeat("a", 64)}); e == nil {
		t.Fatal("insecure remote accepted")
	}
}
