package core

import (
	"net/http"
	"strings"
	"testing"
)

func TestHostDiskOriginalRequestLookupIsPrivateReadOnly(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "request-owner", "admin", nil)
	other := accessUser(t, s, "request-other", "admin", nil)
	limited := accessUser(t, s, "request-limited", "admin", []string{"system-tools", "runtimes"})
	key := ID()
	j, _, err := s.QueueHostDisk(t.Context(), hostSelectionFixture(), key, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, request, login := diskHostHTTPServer(t, s)
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("GET submitted native work", r.URL.Path)
		return nil, nil
	})}}
	cookie, _ := login(owner.Username)
	oc, _ := login(other.Username)
	lc, _ := login(limited.Username)
	url := "/api/software/disk-analysis/host/requests/" + key
	if w := request("GET", url, "", cookie, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"found":true`) || !strings.Contains(w.Body.String(), j.ID) {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, target := range []string{url, "/api/software/disk-analysis/host/requests/" + ID()} {
		if w := request("GET", target, "", oc, ""); w.Code != 200 || w.Body.String() != "{\"found\":false}\n" {
			t.Fatal("cross-owner key leaked existence", w.Code, w.Body.String())
		}
	}
	if w := request("GET", url, "", lc, ""); w.Code != 403 {
		t.Fatal("limited role key lookup", w.Code)
	}
	if w := request("GET", "/api/software/disk-analysis/host/requests/invalid", "", cookie, ""); w.Code != 403 {
		t.Fatal("invalid key accepted", w.Code)
	}
	current, err := s.HostDiskForActor(t.Context(), j.ID, owner.ID)
	if err != nil || current.State != "queued" || current.dispatchSHA != "" {
		t.Fatal("read-only lookup changed original intent", current, err)
	}
}
