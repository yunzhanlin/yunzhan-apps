package core

import (
	"context"
	"encoding/json"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeBuildDoesNotBlockSitesOrStartSecondBuild(t *testing.T) {
	s := testStore(t)
	first, err := s.QueueInstall(runtimecatalog.PHP[0].ID, ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.QueueInstall(runtimecatalog.PHP[1].ID, ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan string, 4)
	var finishFirst atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/runtimes/install":
			var in struct {
				JobID string `json:"job_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			started <- in.JobID
			_ = json.NewEncoder(w).Encode(map[string]string{"state": "running"})
		case strings.HasPrefix(r.URL.Path, "/v1/runtimes/jobs/"):
			state := "running"
			if strings.HasSuffix(r.URL.Path, first) && finishFirst.Load() {
				state = "succeeded"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"state": state, "architecture": "amd64"})
		case r.URL.Path == "/v1/sites/apply":
			_ = json.NewEncoder(w).Encode(ApplyResult{Status: "running"})
		default:
			http.Error(w, `{"error":"not part of this test"}`, 404)
		}
	}))
	defer server.Close()
	// Rewrite the executor's fixed host to this real HTTP test server.
	client := &ExecutorClient{Client: server.Client()}
	client.Client.Transport = rewriteExecutorTransport{base: http.DefaultTransport, url: server.URL}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RunWorker(ctx, s, client); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case id := <-started:
		if id != first {
			t.Fatalf("first build: %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("build did not start")
	}
	jobID, err := s.CreateSite("during build", "during-build", ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var state string
		if err := s.DB.QueryRow(`SELECT state FROM jobs WHERE id=?`, jobID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("website blocked by unfinished build: %s", state)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case id := <-started:
		t.Fatalf("second build started before first completed: %s", id)
	default:
	}
	finishFirst.Store(true)
	select {
	case id := <-started:
		if id != second {
			t.Fatalf("next build: %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second build did not start after first completed")
	}
}

type rewriteExecutorTransport struct {
	base http.RoundTripper
	url  string
}

func (r rewriteExecutorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := req.Clone(req.Context())
	copy.URL.Host = strings.TrimPrefix(r.url, "http://")
	return r.base.RoundTrip(copy)
}

func TestRuntimeInstallWorkerLeavesGlobalActionsOnSiteWorker(t *testing.T) {
	s := testStore(t)
	if err := s.RecordInstallation(runtimecatalog.PHP[0], "amd64"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordInstallation(runtimecatalog.Nginx[0], "amd64"); err != nil {
		t.Fatal(err)
	}
	controlID, extensionID := ID(), ID()
	for _, j := range []struct{ id, kind string }{{controlID, "switch_nginx"}, {extensionID, "install_php_extension"}} {
		target := runtimecatalog.PHP[0].ID
		if j.kind == "switch_nginx" {
			target = runtimecatalog.Nginx[0].ID
		}
		if _, err := s.DB.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,?,?,'queued',?,?,?)`, j.id, target, j.kind, ID(), Now(), Now()); err != nil {
			t.Fatal(err)
		}
	}
	install, err := s.nextRuntimeInstallJob()
	if err != nil || install.ID != extensionID {
		t.Fatalf("install claimed global action: %+v %v", install, err)
	}
	control, err := s.nextRuntimeControlJob()
	if err != nil || control.ID != controlID {
		t.Fatalf("global action dispatch: %+v %v", control, err)
	}
	if _, err := s.nextRuntimeInstallJob(); err == nil {
		t.Fatal("claimed running installation twice")
	}
}

func TestRuntimeInstallShutdownPreservesJobForRecovery(t *testing.T) {
	s := testStore(t)
	id, err := s.QueueInstall(runtimecatalog.PHP[0].ID, ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() { close(release); server.Close() }()
	client := &ExecutorClient{Client: &http.Client{Transport: rewriteExecutorTransport{base: http.DefaultTransport, url: server.URL}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { RunRuntimeInstallWorker(ctx, s, client); close(done) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("installation not requested")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
	var state string
	if err := s.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, id).Scan(&state); err != nil || state != "running" {
		t.Fatalf("shutdown falsely marked installation failed: %s %v", state, err)
	}
	if err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	j, err := s.nextRuntimeInstallJob()
	if err != nil || j.ID != id {
		t.Fatalf("restart did not resume original installation: %+v %v", j, err)
	}
}
