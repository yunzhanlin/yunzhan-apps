package core

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"local/panel/internal/diskjob"
)

func TestHostDiskRecoveryHTTPMetadataOnlyAndCurrentOperatorIsServerBound(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "recovery-http-original", "admin", nil)
	op := accessUser(t, s, "recovery-http-operator", "admin", nil)
	limited := accessUser(t, s, "recovery-http-limited", "admin", []string{"runtimes", "system-tools"})
	j, _, err := s.QueueHostDisk(t.Context(), hostSelectionFixture(), ID(), owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	j, _, err = s.HostDiskDispatchBoundary(t.Context(), j.ID, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, request, login := diskHostHTTPServer(t, s)
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/v1/disk-host-jobs/recover" || r.Method != "POST" {
			t.Fatal("recovery reached an execution/other path", r.URL.Path)
		}
		var in diskjob.RecoveryRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Request != j.Request || in.Operator.ActorID != op.ID || in.Operator.AccessRevision != "1" {
			t.Fatal("operator/original request not server-bound")
		}
		c := diskjob.Closure{Format: 1, JobID: j.ID, RequestSHA: diskjob.RequestSHA(j.Request), OwnerID: owner.ID, Kind: "admission_closed", State: "canceled", At: time.Now().UTC().Format(time.RFC3339Nano), ScopeEmpty: true, AdmissionSealed: true}
		ack := diskjob.RecoveryAck{Format: 1, JobID: j.ID, RequestSHA: c.RequestSHA, State: c.State, Closure: &c}
		raw, _ := json.Marshal(ack)
		return &http.Response{StatusCode: 202, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	cookie, csrf := login(op.Username)
	lc, lcsrf := login(limited.Username)
	listURL := "/api/software/disk-analysis/host/recovery"
	url := "/api/software/disk-analysis/host/jobs/" + j.ID + "/recover"
	if w := request("GET", listURL, "", lc, ""); w.Code != 403 || calls != 0 {
		t.Fatal("limited role saw recovery metadata", w.Code)
	}
	if w := request("POST", url, "{}", cookie, ""); w.Code != 403 || calls != 0 {
		t.Fatal("missing CSRF reached recovery", w.Code)
	}
	if w := request("POST", url, "{}", lc, lcsrf); w.Code != 403 || calls != 0 {
		t.Fatal("limited role acquired orphan authority", w.Code)
	}
	w := request("GET", listURL, "", cookie, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "relative_directory") || strings.Contains(w.Body.String(), j.Request.Selection.Directory) && j.Request.Selection.Directory != "" {
		t.Fatal("maintenance list leaked original paths", w.Code, w.Body.String())
	}
	w = request("POST", url, `{"operator":{"actor_id":"untrusted"},"state":"complete"}`, cookie, csrf)
	if w.Code != 202 || calls != 1 || !strings.Contains(w.Body.String(), `"terminal_verified":true`) || strings.Contains(w.Body.String(), "request_sha256") || strings.Contains(w.Body.String(), "relative_directory") {
		t.Fatal("wrong actor/false success/private report response", w.Code, w.Body.String(), calls)
	}
	w = request("POST", url, "{}", cookie, csrf)
	if w.Code != 200 || calls != 1 {
		t.Fatal("closed recovery repeated native action", w.Code, calls)
	}
	if w := request("GET", "/api/software/disk-analysis/host/jobs/"+j.ID, "", cookie, ""); w.Code != 403 {
		t.Fatal("recovery operator adopted original history")
	}
}
