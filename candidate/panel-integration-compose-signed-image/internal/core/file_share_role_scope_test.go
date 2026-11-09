package core

import (
	"net/http/httptest"
	"testing"
)

func TestFileShareRevokeUsesOnlyOriginalSiteWriteAuthority(t *testing.T) {
	s := testStore(t)
	a := &Server{Store: s}
	operator := accessUser(t, s, "share-revoke-operator", "operator", []string{"files"})
	viewer := accessUser(t, s, "share-revoke-viewer", "viewer", []string{"files"})
	other := accessUser(t, s, "share-revoke-unscoped", "operator", []string{"files"})
	site, foreign, share := ID(), ID(), ID()
	for _, actor := range []identity{operator, viewer} {
		if _, err := s.DB.Exec(`UPDATE app_user_roles SET site_ids=? WHERE user_id=?`, `["`+site+`"]`, actor.ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		actor   identity
		path    string
		allowed bool
	}{
		{operator, "/api/sites/" + site + "/files/shares/" + share, true},
		{viewer, "/api/sites/" + site + "/files/shares/" + share, false},
		{other, "/api/sites/" + site + "/files/shares/" + share, false},
		{operator, "/api/sites/" + foreign + "/files/shares/" + share, false},
		{operator, "/api/sites/" + site, false},
		{operator, "/api/sites/" + site + "/files/shares/not-an-id", false},
		{operator, "/api/sites/" + site + "/files/shares/" + share + "/extra", false},
		{operator, "/api/sites/" + site + "/files/action", false},
	} {
		if a.appRoleAllowed(tc.actor, httptest.NewRequest("DELETE", tc.path, nil)) != tc.allowed {
			t.Fatal(tc.actor.Username, tc.path, "role ceiling widened or own revocation unavailable")
		}
	}
}
