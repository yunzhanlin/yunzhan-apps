package core

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDockerJobObservationRejectsForeignAndImpossibleStates(t *testing.T) {
	id, project := ID(), ID()
	for _, state := range []string{"queued", "running", "succeeded", "failed"} {
		value := DockerJobResult{JobID: id, ProjectID: project, Kind: "compose", State: state}
		if !ValidDockerJobObservation(value, id) {
			t.Fatal("valid original observation refused", state)
		}
	}
	for _, change := range []func(*DockerJobResult){
		func(v *DockerJobResult) { v.JobID = ID() },
		func(v *DockerJobResult) { v.ProjectID = "foreign" },
		func(v *DockerJobResult) { v.Kind = "foreign" },
		func(v *DockerJobResult) { v.State = "unknown" },
		func(v *DockerJobResult) { v.Error = "worker failure" },
		func(v *DockerJobResult) { v.Image = "foreign-image" },
		func(v *DockerJobResult) { v.ContainerID = strings.Repeat("a", 64) },
		func(v *DockerJobResult) { v.Message = strings.Repeat("x", 4097) },
	} {
		value := DockerJobResult{JobID: id, ProjectID: project, Kind: "compose", State: "succeeded"}
		change(&value)
		if ValidDockerJobObservation(value, id) {
			t.Fatal("foreign or impossible success accepted", value)
		}
	}
}

func TestDockerJobObservationHTTPIsAuthenticatedReadOnlyAndNeverReconciles(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "docker-observe-owner", "admin", nil)
	viewer := accessUser(t, s, "docker-observe-viewer", "viewer", []string{"overview"})
	a, request, login := diskHostHTTPServer(t, s)
	cookie, csrf := login(owner.Username)
	vc, vs := login(viewer.Username)
	id := ID()
	value := DockerJobResult{JobID: id, ProjectID: ID(), Kind: "compose", State: "running"}
	reads := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/docker/job-observations/"+id || r.Body != nil {
			t.Fatal("observation reached mutation/reconciliation path", r.Method, r.URL.Path)
		}
		reads++
		raw, _ := json.Marshal(value)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	route := "/api/docker/job-observations/" + id
	for _, actor := range []struct {
		cookie *http.Cookie
		csrf   string
	}{{nil, ""}, {vc, vs}} {
		w := request("GET", route, "", actor.cookie, actor.csrf)
		if w.Code != 401 && w.Code != 403 {
			t.Fatal("unauthorized observation", w.Code)
		}
	}
	for _, state := range []string{"queued", "running", "succeeded"} {
		value.State = state
		w := request("GET", route, "", cookie, csrf)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"state":"`+state+`"`) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	value.JobID = ID()
	if w := request("GET", route, "", cookie, csrf); w.Code != 409 {
		t.Fatal("foreign response adopted", w.Code, w.Body.String())
	}
	if reads != 4 {
		t.Fatal("unexpected native reads", reads)
	}
}
