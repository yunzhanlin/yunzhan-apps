package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"local/panel/internal/appcatalog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRabbitMQQueueVHostAcceptsOneLiteralName(t *testing.T) {
	for _, name := range []string{"/", "运营/队列+通知", "--name-with-leading-dashes", "staff?department=ops"} {
		raw := url.Values{"vhost": {name}}.Encode()
		if actual, err := RabbitMQQueueVHost(raw); err != nil || actual != name {
			t.Fatalf("name %q: got %q, %v", name, actual, err)
		}
	}
	for _, raw := range []string{"vhost=", "vhost=/&vhost=x", "vhost=/&filter=y", "vhost=%ff", "vhost=%0A", "vhost=" + strings.Repeat("x", 256)} {
		if _, err := RabbitMQQueueVHost(raw); err == nil {
			t.Fatalf("unexpectedly accepted %q", raw)
		}
	}
}

func TestRabbitMQQueueHTTPRejectsUnauthorizedAndForeignReports(t *testing.T) {
	store := testStore(t)
	admin := accessUser(t, store, "rabbitmq-workspace-admin", "admin", nil)
	viewer := accessUser(t, store, "rabbitmq-workspace-viewer", "viewer", []string{"overview"})
	a, request, login := diskHostHTTPServer(t, store)
	cookie, csrf := login(admin.Username)
	viewerCookie, viewerCSRF := login(viewer.Username)
	project := ID()
	route := "/api/docker/projects/" + project + "/rabbitmq-queues"
	report := RabbitMQQueueReport{ProjectID: project, ObservedAt: Now(), VHosts: []string{"/"}, VHost: "/", Queues: []RabbitMQQueueRow{}}
	reads := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/docker/projects/"+project+"/rabbitmq-queues" || req.URL.Query().Get("vhost") != "/" || req.Body != nil {
			t.Fatal("unexpected request to executor", req.Method, req.URL)
		}
		reads++
		raw, _ := json.Marshal(report)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	if w := request("GET", route, "", nil, ""); w.Code != 401 {
		t.Fatal("anonymous read allowed", w.Code)
	}
	if w := request("GET", route, "", viewerCookie, viewerCSRF); w.Code != 403 {
		t.Fatal("viewer read allowed", w.Code)
	}
	if w := request("GET", route+"?vhost=%2F&vhost=other", "", cookie, csrf); w.Code != 400 {
		t.Fatal("ambiguous vhost accepted", w.Code)
	}
	if w := request("GET", route, "", cookie, csrf); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated observation failed", w.Code, w.Body.String())
	}
	report.ProjectID = ID()
	if w := request("GET", route, "", cookie, csrf); w.Code != 502 {
		t.Fatal("foreign report accepted", w.Code, w.Body.String())
	}
	if reads != 2 {
		t.Fatal("unexpected native reads", reads)
	}
}

func TestRabbitMQ440RequiresFixedSignedRecipe(t *testing.T) {
	manifest := appcatalog.Manifest{ID: "rabbitmq", Version: rabbitMQ440AppVersion, Risk: "maintained",
		Delivery: appcatalog.Delivery{Provider: "compose", Target: RabbitMQ440Template,
			Image: dockerRabbitMQ440Image, ManageRoute: "docker"}}
	if err := validateRegistryComposeDelivery(manifest); err != nil {
		t.Fatal(err)
	}
	password := strings.Repeat("a", 64)
	compose := rabbitMQCompose(RabbitMQ440Template, 15672, password)
	if !RabbitMQ440ComposeMatches(compose, 15672, password) ||
		!strings.Contains(compose, "    image: "+manifest.Delivery.Image+"\n") {
		t.Fatal("store template does not use the signed image")
	}
	for _, altered := range []string{
		strings.Replace(compose, dockerRabbitMQ440Image, dockerRabbitMQImage, 1),
		strings.Replace(compose, "127.0.0.1:", "0.0.0.0:", 1),
		strings.Replace(compose, "data:/var/lib/rabbitmq", "earlier_data:/var/lib/rabbitmq", 1),
	} {
		if RabbitMQ440ComposeMatches(altered, 15672, password) {
			t.Fatal("accepted an altered installation recipe")
		}
	}
	manifest.Delivery.Image = dockerRabbitMQImage
	if validateRegistryComposeDelivery(manifest) == nil ||
		MatchesPanelRabbitMQImage(RabbitMQ440Template, dockerRabbitMQImage) ||
		MatchesPanelRabbitMQImage(RabbitMQLegacyTemplate, dockerRabbitMQ440Image) {
		t.Fatal("matched the wrong broker image to the template")
	}
	manifest.Delivery.Image, manifest.Version = dockerRabbitMQ440Image, "4.1-compat1"
	if validateRegistryComposeDelivery(manifest) == nil {
		t.Fatal("accepted an earlier application version with the new image")
	}
}

func TestRabbitMQRegistryKeepsOldInstanceVisibleAlongside440(t *testing.T) {
	old, current := ID(), ID()
	executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runtimes":
			_, _ = w.Write([]byte(`{"installed":[]}`))
		case "/v1/software":
			_, _ = w.Write([]byte(`[]`))
		case "/v1/docker/projects":
			_ = json.NewEncoder(w).Encode(map[string]any{"projects": []map[string]any{
				{"id": old, "template_id": RabbitMQLegacyTemplate, "state": "running",
					"services": 1, "running": 1, "healthy": 1, "images": []string{dockerRabbitMQImage}},
				{"id": current, "template_id": RabbitMQ440Template, "state": "running",
					"services": 1, "running": 1, "healthy": 1, "images": []string{dockerRabbitMQ440Image}},
			}})
		default:
			w.WriteHeader(404)
		}
	})
	server := &Server{Executor: executor, Store: testStore(t)}
	rows := server.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{
		{ID: "rabbitmq", Version: rabbitMQ440AppVersion, Provider: "compose", Target: RabbitMQ440Template, Stage: "ready"},
	}})
	got := rows[0]
	if !got.Installed || !got.Healthy || !got.UpdateAvailable || got.UpdateSupported || got.UpdateKind != "compose-review" {
		t.Fatal("missing old instance migration notice", got)
	}
	if len(got.Instances) != 2 || got.Instances[0].ID != old ||
		got.Instances[0].Version != "4.1.4" || !got.Instances[0].UpdateAvailable ||
		got.Instances[1].ID != current || got.Instances[1].Version != "4.4.0" || got.Instances[1].UpdateAvailable {
		t.Fatal("mixed the old and new broker versions", got.Instances)
	}
}

func TestRabbitMQMigrationComposeBindsOriginalEndpointAndExistingVolume(t *testing.T) {
	password, job := strings.Repeat("3", 64), strings.Repeat("7", 32)
	original := rabbitMQCompose(RabbitMQLegacyTemplate, 25672, password)
	got, err := RabbitMQMigratedCompose(original, 25672, job)
	want := strings.Replace(original, dockerRabbitMQImage, dockerRabbitMQ440Image, 1)
	want = strings.Replace(want, "  data: {}\n", "  data:\n    external: true\n    name: panel_rabbitmq_"+job+"\n", 1)
	if err != nil || got != want || RabbitMQ440ComposeMatches(got, 25672, password) {
		t.Fatal("migrated Compose did not bind the original ports, hostname, credentials, and exact copied volume")
	}
	if _, err := RabbitMQMigratedCompose(original, 25673, job); err == nil {
		t.Fatal("accepted different endpoint")
	}
	if _, err := RabbitMQMigratedCompose(original, 25672, "../different-volume"); err == nil {
		t.Fatal("accepted an external volume override")
	}
}
