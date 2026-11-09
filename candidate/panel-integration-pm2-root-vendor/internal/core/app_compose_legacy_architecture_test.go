package core

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

func TestIsolatedLegacyPHPArchitecturePolicyCannotBorrowEmulationOrAlias(t *testing.T) {
	for id := range LegacyPHPImages {
		for _, arch := range []string{"amd64", "arm64", "386", "ppc64le", "AMD64", "x86_64", ""} {
			source, err := dockerTemplateOnArchitecture(id, 23000, arch)
			if (err == nil) != (arch == "amd64") || err != nil && source != "" {
				t.Fatal("legacy image received a borrowed architecture", id, arch, err)
			}
		}
		_, err := dockerTemplate(id, 23000)
		if (err == nil) != (runtime.GOARCH == "amd64") {
			t.Fatal("production renderer did not use compiled host architecture", id, err)
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if _, err := dockerTemplateOnArchitecture("nginx-static", 23000, arch); err != nil {
			t.Fatal("multiarchitecture Nginx template was incorrectly removed", arch, err)
		}
	}
}

// Authenticated real Core HTTP, explicit synthetic executor. No image pull,
// Docker command, app installation or container emulation is performed here.
func TestIsolatedLegacyPHPDirectHTTPEnforcesSameArchitectureBeforeRootDispatch(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "legacy-template-owner", "admin", nil)
	a, request, login := diskHostHTTPServer(t, s)
	cookie, csrf := login(owner.Username)
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if runtime.GOARCH != "amd64" || r.Method != "POST" || r.URL.Path != "/v1/docker/projects/jobs" {
			t.Fatal("unsupported host or metadata read reached executor", r.Method, r.URL.Path)
		}
		var op DockerProjectRequest
		if json.NewDecoder(r.Body).Decode(&op) != nil || op.TemplateID != "php-legacy-52" || ValidateDockerProject(op) != nil {
			t.Fatal("approved template request identity changed")
		}
		raw, _ := json.Marshal(DockerJobResult{JobID: op.JobID, ProjectID: op.ProjectID, Kind: "compose", State: "queued"})
		return &http.Response{StatusCode: 202, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	w := request("GET", "/api/docker/templates", "", cookie, csrf)
	var page struct {
		Templates []struct {
			ID string `json:"id"`
		} `json:"templates"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || calls != 0 {
		t.Fatal("template metadata read performed a native operation", w.Code)
	}
	legacy := 0
	for _, row := range page.Templates {
		if _, found := LegacyPHPImages[row.ID]; found {
			legacy++
		}
	}
	if runtime.GOARCH == "amd64" && legacy != 12 || runtime.GOARCH != "amd64" && legacy != 0 {
		t.Fatal("quick template list advertised unsupported legacy images", runtime.GOARCH, legacy)
	}
	w = request("POST", "/api/docker/projects", `{"name":"legacy-template-fixture","template_id":"php-legacy-52","host_port":23000,"compose":""}`, cookie, csrf)
	if runtime.GOARCH == "amd64" {
		if w.Code != 202 || calls != 1 {
			t.Fatal("reviewed AMD64 template no longer dispatches once", w.Code, calls, w.Body.String())
		}
	} else if w.Code != 400 || calls != 0 || !strings.Contains(w.Body.String(), `"request_not_accepted":true`) {
		t.Fatal("unsupported host could bypass store via direct Docker endpoint", w.Code, calls, w.Body.String())
	}
	if runtime.GOARCH != "amd64" {
		body := `{"name":"legacy-template-fixture","template_id":"php-legacy-52","host_port":23000,"compose":"","architecture":"amd64"}`
		if w := request("POST", "/api/docker/projects", body, cookie, csrf); w.Code != 400 || calls != 0 {
			t.Fatal("caller architecture field overrode compiled host identity", w.Code, calls)
		}
	}
}
