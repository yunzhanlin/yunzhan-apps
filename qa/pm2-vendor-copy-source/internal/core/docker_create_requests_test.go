package core

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDockerCreateIdentityBindsStableActorKeyAndChangedPayload(t *testing.T) {
	a := &Server{accountSecretKey: bytes.Repeat([]byte{73}, 32)}
	actor, key := ID(), ID()
	body := map[string]any{"name": "owned-fixture", "template_id": "nginx-static", "host_port": 23862}
	job, project, digest, err := a.dockerCreateIdentity(actor, key, body)
	if err != nil || !ValidID(job) || !ValidID(project) || !dockerRequestDigestPattern.MatchString(digest) || job == project || job == key || project == key {
		t.Fatal("invalid stable identity", err)
	}
	j, p, d, e := a.dockerCreateIdentity(actor, key, body)
	if e != nil || j != job || p != project || d != digest {
		t.Fatal("same request changed")
	}
	body["host_port"] = 23863
	j, p, d, e = a.dockerCreateIdentity(actor, key, body)
	if e != nil || j != job || p != project || d == digest {
		t.Fatal("changed payload did not retain conflict identity")
	}
	for _, change := range [][2]string{{ID(), key}, {actor, ID()}} {
		j, p, _, e = a.dockerCreateIdentity(change[0], change[1], nil)
		if e != nil || j == job || p == project {
			t.Fatal("cross actor/key identity adopted")
		}
	}
	for _, bad := range []string{"", "invalid", strings.Repeat("a", 31)} {
		if _, _, _, e = a.dockerCreateIdentity(actor, bad, body); e == nil {
			t.Fatal("invalid key accepted")
		}
	}
}

func TestDockerCreateRequestHTTPActorScopeAndOneOriginalIdentity(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "docker-create-owner", "admin", nil)
	other := accessUser(t, s, "docker-create-other", "admin", nil)
	a, request, login := diskHostHTTPServer(t, s)
	cookie, csrf := login(owner.Username)
	oc, ot := login(other.Username)
	original := DockerProjectRequest{}
	mutations := 0
	lookups := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var response any
		status := 200
		if r.Method == "POST" && r.URL.Path == "/v1/docker/projects/jobs" {
			var op DockerProjectRequest
			if json.NewDecoder(r.Body).Decode(&op) != nil || ValidateDockerProject(op) != nil || op.RequestSHA == "" {
				t.Fatal("unbound create dispatch")
			}
			if original.JobID == "" {
				original = op
				mutations++
			} else if op.JobID == original.JobID && op.RequestSHA != original.RequestSHA {
				status = 409
				response = map[string]string{"error": "original payload conflict"}
			} else if op.JobID != original.JobID || op.ProjectID != original.ProjectID {
				t.Fatal("same key created another identity")
			}
			if status == 200 {
				status = 202
				response = DockerJobResult{JobID: original.JobID, ProjectID: original.ProjectID, Kind: "compose", State: "queued"}
			}
		} else if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/docker/project-requests/") {
			lookups++
			id := strings.TrimPrefix(r.URL.Path, "/v1/docker/project-requests/")
			response = DockerCreateRequestStatus{Found: false}
			if id == original.JobID {
				job := DockerJobResult{JobID: original.JobID, ProjectID: original.ProjectID, Kind: "compose", State: "succeeded"}
				response = DockerCreateRequestStatus{Found: true, JobID: job.JobID, ProjectID: job.ProjectID, Job: &job}
			}
		} else {
			t.Fatal("unexpected dispatch", r.Method, r.URL.Path)
		}
		raw, _ := json.Marshal(response)
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	body := `{"name":"owned-create-fixture","template_id":"nginx-static","host_port":23862,"compose":""}`
	first := ""
	for i := 0; i < 2; i++ {
		w := request("POST", "/api/docker/projects", body, cookie, csrf)
		if w.Code != 202 {
			t.Fatal(w.Code, w.Body.String())
		}
		if i == 0 {
			first = w.Body.String()
		} else if first != w.Body.String() {
			t.Fatal("same request changed reply")
		}
	}
	if mutations != 1 {
		t.Fatal("more than one native intent", mutations)
	}
	if w := request("POST", "/api/docker/projects", strings.Replace(body, "23862", "23863", 1), cookie, csrf); w.Code != 409 {
		t.Fatal("changed payload accepted", w.Code, w.Body.String())
	}
	route := "/api/docker/project-requests/" + strings.Repeat("a", 32)
	if w := request("GET", route, "", cookie, csrf); w.Code != 200 || !strings.Contains(w.Body.String(), original.JobID) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("original lookup", w.Code, w.Body.String())
	}
	if w := request("GET", route, "", oc, ot); w.Code != 200 || w.Body.String() != "{\"found\":false}\n" {
		t.Fatal("another actor adopted original", w.Code, w.Body.String())
	}
	if mutations != 1 || lookups != 2 {
		t.Fatal("GET mutated or replayed", mutations, lookups)
	}
}

func TestDockerCreateStatusRejectsForeignUnknownAndFalseSuccess(t *testing.T) {
	job, project := ID(), ID()
	result := DockerJobResult{JobID: job, ProjectID: project, Kind: "compose", State: "succeeded"}
	ok := DockerCreateRequestStatus{Found: true, JobID: job, ProjectID: project, Job: &result}
	if !validComposeCreateStatus(ok, job) || !validComposeCreateStatus(DockerCreateRequestStatus{}, job) {
		t.Fatal("valid status refused")
	}
	for _, change := range []func(*DockerCreateRequestStatus){
		func(v *DockerCreateRequestStatus) { v.Found = false },
		func(v *DockerCreateRequestStatus) { v.JobID = ID() },
		func(v *DockerCreateRequestStatus) { v.Job = nil },
		func(v *DockerCreateRequestStatus) { v.Pending = true },
		func(v *DockerCreateRequestStatus) { v.Error = "foreign" },
	} {
		v := ok
		change(&v)
		if validComposeCreateStatus(v, job) {
			t.Fatal("invalid envelope accepted", v)
		}
	}
	for _, change := range []func(*DockerJobResult){
		func(v *DockerJobResult) { v.JobID = ID() }, func(v *DockerJobResult) { v.ProjectID = ID() }, func(v *DockerJobResult) { v.Kind = "foreign" },
		func(v *DockerJobResult) { v.State = "unknown" }, func(v *DockerJobResult) { v.Error = "failure" }, func(v *DockerJobResult) { v.Image = "foreign" },
	} {
		v := result
		change(&v)
		if validComposeCreateResult(v, job, project) {
			t.Fatal("invalid original job accepted", v)
		}
	}
}
func TestDockerCreateCanonicalUUIDHTTPMatchesActualFrontendContract(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "docker-uuid-owner", "admin", nil)
	a, _, login := diskHostHTTPServer(t, s)
	cookie, csrf := login(owner.Username)
	key := "e081af54-b8e5-4578-9c52-96cdad242f08"
	original := DockerProjectRequest{}
	attempts, created, reads := 0, 0, 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var response any
		if r.Method == "POST" {
			var op DockerProjectRequest
			if json.NewDecoder(r.Body).Decode(&op) != nil || op.RequestSHA == "" || ValidateDockerProject(op) != nil {
				t.Fatal("invalid UUID dispatch")
			}
			attempts++
			if original.JobID == "" {
				original = op
				created++
			} else if original.JobID != op.JobID || original.ProjectID != op.ProjectID || original.RequestSHA != op.RequestSHA {
				t.Fatal("same UUID became another request")
			}
			response = DockerJobResult{JobID: op.JobID, ProjectID: op.ProjectID, Kind: "compose", State: "queued"}
		} else {
			reads++
			if r.URL.Path != "/v1/docker/project-requests/"+original.JobID {
				t.Fatal("UUID lookup not same original actor identity")
			}
			result := DockerJobResult{JobID: original.JobID, ProjectID: original.ProjectID, Kind: "compose", State: "succeeded"}
			response = DockerCreateRequestStatus{Found: true, JobID: result.JobID, ProjectID: result.ProjectID, Job: &result}
		}
		raw, _ := json.Marshal(response)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	request := func(method, url, body, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	body := `{"name":"uuid-contract-fixture","template_id":"nginx-static","host_port":23863,"compose":""}`
	for i := 0; i < 2; i++ {
		if w := request("POST", "/api/docker/projects", body, key); w.Code != 202 {
			t.Fatal("real UUIDv4 refused", w.Code, w.Body.String())
		}
	}
	if attempts != 2 || created != 1 {
		t.Fatal("UUID identity duplicated", attempts, created)
	}
	if w := request("GET", "/api/docker/project-requests/"+key, "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), original.JobID) {
		t.Fatal("UUID original GET failed", w.Code, w.Body.String())
	}
	for _, bad := range []string{"", "e081af54-b8e5-3578-9c52-96cdad242f08", "e081af54-b8e5-4578-7c52-96cdad242f08"} {
		if w := request("POST", "/api/docker/projects", body, bad); w.Code != 400 || !strings.Contains(w.Body.String(), `"request_not_accepted":true`) {
			t.Fatal("invalid key not definitively rejected before dispatch", w.Code, w.Body.String())
		}
	}
	if attempts != 2 || created != 1 || reads != 1 {
		t.Fatal("invalid key reached original executor")
	}
}
