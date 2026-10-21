package core

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestNginxStaticTemplatePinsOfficialIndexHealthAndNamedVolume(t *testing.T) {
	body, err := dockerTemplate("nginx-static", 23862)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"image: " + dockerNginxStaticImage,
		"mem_limit: 256m", "restart: unless-stopped",
		"127.0.0.1:23862:80", "site-data:/usr/share/nginx/html",
		"volumes:\n  site-data: {}", "healthcheck:", `test: ["CMD", "curl", "--fail", "--silent", "--max-time", "2", "--output", "/dev/null", "http://127.0.0.1/"]`,
		"interval: 10s", "timeout: 3s", "retries: 6", "start_period: 10s",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if !regexp.MustCompile(`^nginx:1\.30\.6-alpine@sha256:[a-f0-9]{64}$`).MatchString(dockerNginxStaticImage) {
		t.Fatal("image not content-addressed")
	}
	images := regexp.MustCompile(`(?m)^    image: (.+)$`).FindAllStringSubmatch(body, -1)
	if len(images) != 1 || images[0][1] != dockerNginxStaticImage {
		t.Fatal("not one exact image")
	}
	for _, forbidden := range []string{"0.0.0.0", "latest", "privileged:", "/var/run/docker.sock", "type: bind", "external:", "container_name:"} {
		if strings.Contains(body, forbidden) {
			t.Fatal("template broadened authority", forbidden)
		}
	}
	for _, port := range []int{-1, 80, 1023, 65536} {
		if _, err := dockerTemplate("nginx-static", port); err == nil {
			t.Fatal("invalid host port", port)
		}
	}
}

func TestDockerSiteBindingOnlyRecognizedFullyHealthyTemplates(t *testing.T) {
	for _, template := range []string{"nginx-static", "wordpress-blog", "openlitespeed", "php-legacy-52", "php-legacy-81"} {
		if !dockerProjectSiteBindingAllowed(template, "running", 1, 1, 1, 23862) {
			t.Fatal("known healthy refused", template)
		}
		for _, state := range []string{"", "stopped", "empty", "unknown"} {
			if dockerProjectSiteBindingAllowed(template, state, 1, 1, 1, 23862) {
				t.Fatal("non-running accepted", state)
			}
		}
	}
	for _, template := range []string{"", "nginx-static-unknown", "php-legacy-99", "redis-cache", "memcached-cache", "custom"} {
		if dockerProjectSiteBindingAllowed(template, "running", 1, 1, 1, 23862) {
			t.Fatal("unknown template", template)
		}
	}
	for _, v := range [][4]int{{0, 0, 0, 23862}, {-1, -1, -1, 23862}, {1, 1, 0, 23862}, {2, 1, 2, 23862}, {2, 2, 1, 23862}, {1, 1, 2, 23862}, {1, 1, 1, 1023}, {1, 1, 1, 65536}} {
		if dockerProjectSiteBindingAllowed("nginx-static", "running", v[0], v[1], v[2], v[3]) {
			t.Fatal("unhealthy/partial/invalid port accepted", v)
		}
	}
}

func TestDockerNginxBindingHTTPReReadsHealthAndQueuesExactlyOneSite(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "docker-bind-owner", "admin", nil)
	limited := accessUser(t, s, "docker-bind-limited", "admin", []string{"runtimes"})
	a, request, login := diskHostHTTPServer(t, s)
	cookie, csrf := login(owner.Username)
	lc, lt := login(limited.Username)
	id := ID()
	healthy, template, reads := 1, "nginx-static", 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/docker/projects" {
			t.Fatal("binding submitted executor mutation", r.Method, r.URL.Path)
		}
		reads++
		raw, _ := json.Marshal(map[string]any{"projects": []map[string]any{{"id": id, "template_id": template, "host_port": 23862, "state": "running", "services": 1, "running": 1, "healthy": healthy}}})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	route := "/api/docker/projects/" + id + "/sites"
	body := `{"name":"Nginx binding fixture","slug":"nginx-bind-fixture","domain":"nginx-bind.example.test"}`
	original := ""
	for i := 0; i < 2; i++ {
		w := request("POST", route, body, cookie, csrf)
		if w.Code != 202 {
			t.Fatal("healthy binding", w.Code, w.Body.String())
		}
		var out map[string]string
		if json.Unmarshal(w.Body.Bytes(), &out) != nil || !ValidID(out["job_id"]) {
			t.Fatal("invalid original job")
		}
		if i == 0 {
			original = out["job_id"]
		} else if out["job_id"] != original {
			t.Fatal("original request duplicated a job")
		}
	}
	for _, state := range []struct {
		template string
		healthy  int
	}{{"nginx-static", 0}, {"nginx-static", 2}, {"custom", 1}, {"php-legacy-99", 1}} {
		healthy, template = state.healthy, state.template
		w := request("POST", route, body, cookie, csrf)
		if w.Code != 409 {
			t.Fatal("unhealthy/unknown binding accepted", w.Code, w.Body.String())
		}
	}
	before := reads
	if w := request("POST", route, body, lc, lt); w.Code != 403 {
		t.Fatal("unauthorized binding", w.Code)
	}
	if w := request("POST", route, body, cookie, ""); w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	if reads != before {
		t.Fatal("unauthorized request read privileged project state")
	}
	var sites, jobs int
	if s.DB.QueryRow("SELECT count(*) FROM sites").Scan(&sites) != nil || s.DB.QueryRow("SELECT count(*) FROM jobs").Scan(&jobs) != nil || sites != 1 || jobs != 1 {
		t.Fatal("denied/replayed requests changed original site/job", sites, jobs)
	}
}
