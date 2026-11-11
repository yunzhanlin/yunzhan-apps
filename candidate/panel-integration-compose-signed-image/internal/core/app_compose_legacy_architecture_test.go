package core

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"slices"
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

func TestFinalLegacyPHPTemplatesUseReviewedNativeImages(t *testing.T) {
	for _, release := range finalLegacyPHPReleases {
		id := release.template
		image, ok := LegacyPHPImage(id)
		if !ok || !strings.Contains(image, "@sha256:") {
			t.Fatalf("missing pinned image for %s", id)
		}
		for _, architecture := range []string{"amd64", "arm64"} {
			config, err := dockerTemplateOnArchitecture(id, 23000, architecture)
			if err != nil || !strings.Contains(config, image) ||
				!strings.Contains(config, "127.0.0.1:23000:8080") {
				t.Fatalf("invalid native template %s on %s: %v", id, architecture, err)
			}
		}
		if _, err := dockerTemplateOnArchitecture(id, 23000, "ppc64le"); err == nil {
			t.Fatalf("template %s accepted an unreviewed platform", id)
		}
	}
}

func TestLegacyPHP52BookwormUsesOnlyTheReviewedFastCGIWorker(t *testing.T) {
	cgi := LegacyPHPBootstrapForTemplate(legacyPHP52BookwormTemplate)
	if !strings.HasSuffix(cgi, "exec /usr/local/bin/yunzhan-start-php-cgi\n") ||
		strings.Contains(cgi, "exec /usr/local/sbin/php-fpm") {
		t.Fatal("PHP 5.2 needs its fixed FastCGI startup")
	}
	for _, id := range []string{"php-legacy-52", "php-legacy-53-bookworm", LegacyPHP81BookwormTemplate} {
		if LegacyPHPBootstrapForTemplate(id) != LegacyPHPBootstrap {
			t.Fatalf("template %s lost its established PHP-FPM startup", id)
		}
	}
}

func TestPatchedPHPTemplatesRetainBothOlderDeploymentIdentities(t *testing.T) {
	for template, earlier := range map[string][]string{
		legacyPHP81BookwormCompat2Template: {LegacyPHP81BookwormTemplate, "php-legacy-81"},
		legacyPHP80BullseyeCompat2Template: {legacyPHP80BullseyeTemplate, "php-legacy-80"},
		legacyPHP74BullseyeCompat3Template: {legacyPHP74BullseyeTemplate, "php-legacy-74"},
	} {
		release, ok := findFinalLegacyPHPRelease(template)
		if !ok || !slices.Equal(previousLegacyPHPTemplates(release), earlier) {
			t.Fatalf("%s omitted an existing template from the update path", template)
		}
		if !LegacyPHPArchitectureSupported(template, "arm64") ||
			!LegacyPHPArchitectureSupported(earlier[0], "arm64") ||
			LegacyPHPArchitectureSupported(earlier[1], "arm64") {
			t.Fatalf("%s changed an existing architecture boundary", template)
		}
	}
}
