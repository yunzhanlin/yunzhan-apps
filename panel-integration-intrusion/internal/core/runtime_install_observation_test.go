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

// Synthetic executor responses exercise the Core persistence contract only;
// genuine native unit observations are a separate isolated Linux acceptance.
func TestRuntimeWorkerUncertainOrInvalidCompletionCannotPublish(t *testing.T) {
	for _, row := range []struct{ name, observed, detail, want string }{
		{"uncertain", "needs_attention", "actual unit exited without completion", "needs_attention"},
		{"uncertain_no_message", "needs_attention", "", "needs_attention"},
		{"unknown", "invented-ready", "", "needs_attention"},
		{"contradictory_success", "succeeded", "missing native proof", "needs_attention"},
		{"empty_failure", "failed", "", "failed"},
	} {
		t.Run(row.name, func(t *testing.T) {
			store := testStore(t)
			id, err := store.QueueInstall(runtimecatalog.Apache[0].ID, ID(), "admin")
			if err != nil {
				t.Fatal(err)
			}
			job, err := store.nextRuntimeInstallJob()
			if err != nil || job.ID != id {
				t.Fatal(err)
			}
			var starts, polls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "POST" && r.URL.Path == "/v1/runtimes/install" {
					starts.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"state": "queued"})
					return
				}
				if r.Method == "GET" && r.URL.Path == "/v1/runtimes/jobs/"+id {
					polls.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"state": row.observed, "error": row.detail, "architecture": "amd64", "steps": []Step{{Time: Now(), Message: "retained native step"}}})
					return
				}
				http.Error(w, "unexpected operation", 400)
			}))
			defer server.Close()
			client := &ExecutorClient{Client: &http.Client{Transport: rewriteExecutorTransport{base: http.DefaultTransport, url: server.URL}}}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			runRuntimeJob(ctx, store, client, job)
			var state, detail, steps string
			if err := store.DB.QueryRow("SELECT state,error,steps FROM runtime_jobs WHERE id=?", id).Scan(&state, &detail, &steps); err != nil {
				t.Fatal(err)
			}
			if state != row.want || detail == "" || !strings.Contains(steps, "retained native step") || starts.Load() != 1 || polls.Load() != 1 {
				t.Fatal("unknown result relabelled, retried or lost evidence", state, detail, steps, starts.Load(), polls.Load())
			}
			var installations int
			if err := store.DB.QueryRow("SELECT count(*) FROM runtime_installations WHERE id=?", job.TargetID).Scan(&installations); err != nil || installations != 0 {
				t.Fatal("uncertain observation published runtime", installations, err)
			}
		})
	}
}
