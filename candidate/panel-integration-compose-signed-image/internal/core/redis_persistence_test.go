package core

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRedisPersistenceSnapshotRequiresDatabaseAdminAndMatchingInstance(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	accessUser(t, s, "database-admin", "admin", []string{"databases"})
	adminCookie := login("database-admin")
	adminCSRF := wafBackupArchiveCoreCSRF(t, a, adminCookie)
	otherCookie := login("runtime-admin")
	otherCSRF := wafBackupArchiveCoreCSRF(t, a, otherCookie)
	id := strings.Repeat("a", 32)
	path := "/api/redis/instances/" + id + "/persistence"
	var calls int
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var input map[string]string
		if r.Method != http.MethodPost || r.URL.Path != "/v1/redis/instances/"+id+"/persistence" ||
			json.NewDecoder(r.Body).Decode(&input) != nil || len(input) != 1 || input["confirm_id"] != id {
			t.Fatal("wrong Redis persistence executor action")
		}
		out, _ := json.Marshal(map[string]string{"instance_id": id})
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(out)))}, nil
	})}}

	input := `{"confirm_id":"` + id + `"}`
	for _, tc := range []struct {
		body   string
		cookie *http.Cookie
		csrf   string
		want   int
	}{
		{input, nil, "", http.StatusUnauthorized},
		{input, otherCookie, otherCSRF, http.StatusForbidden},
		{input, adminCookie, "", http.StatusForbidden},
		{`{"confirm_id":"another-instance"}`, adminCookie, adminCSRF, http.StatusBadRequest},
	} {
		res := wafBackupArchiveCorePost(a, path, tc.body, tc.cookie, tc.csrf, a.Config.Origin)
		if res.Code != tc.want || calls != 0 {
			t.Fatalf("denied Redis snapshot returned %d, wanted %d; executor calls: %d", res.Code, tc.want, calls)
		}
	}
	res := wafBackupArchiveCorePost(a, path, input, adminCookie, adminCSRF, a.Config.Origin)
	if res.Code != http.StatusAccepted || calls != 1 || res.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Redis snapshot returned %d; executor calls: %d", res.Code, calls)
	}
	var audits int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action='redis.snapshot.start' AND target=? AND result IN ('requested','accepted')", id).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("Redis snapshot audit count %d: %v", audits, err)
	}
}
