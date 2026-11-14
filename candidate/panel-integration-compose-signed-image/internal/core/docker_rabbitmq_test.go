package core

import (
	"bytes"
	"encoding/json"
	"io"
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
