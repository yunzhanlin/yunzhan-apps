package core

import (
	"errors"
	"net/url"
	"testing"
)

func TestModuleHistoryStrictFiltersAndPersistentPagination(t *testing.T) {
	for _, raw := range []string{"limit=101", "offset=-1", "offset=100001", "limit=one", "site_id=../x", "resource_id=../x", "secret=1", "limit=10&limit=20", "from_time=invalid", "from_time=2026-10-06T00:00:00Z&to_time=2026-10-05T00:00:00Z"} {
		values, err := url.ParseQuery(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ParseModuleHistoryQuery(values); err == nil {
			t.Fatal("invalid filter accepted", raw)
		}
	}
	s := testStore(t)
	for i := 0; i < 130; i++ {
		action := "normal"
		if i%10 == 0 {
			action = "literal%_marker"
		}
		if err := s.recordAppModuleEvent("user-manager", action, "admin", errors.New("do-not-persist-error-secret")); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.appModuleHistory("user-manager", AppModuleInput{Limit: 20, Offset: 100})
	if err != nil || page.(map[string]any)["total"] != 130 || len(page.(map[string]any)["history"].([]map[string]any)) != 20 {
		t.Fatal(page, err)
	}
	filtered, err := s.appModuleHistory("user-manager", AppModuleInput{Search: "literal%_marker"})
	if err != nil || filtered.(map[string]any)["total"] != 13 {
		t.Fatal("wildcards were not treated literally", filtered, err)
	}
	if _, err := s.appModuleHistory("user-manager", AppModuleInput{SiteID: ID()}); err == nil {
		t.Fatal("unsupported site scope silently ignored")
	}
}
