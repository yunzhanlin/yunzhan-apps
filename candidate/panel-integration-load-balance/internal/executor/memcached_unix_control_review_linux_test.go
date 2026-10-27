//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestMemcachedUnixControlReviewUnboundTransportNeverInitializesOrAdoptsNativeState(t *testing.T) {
	project, request, actor := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	op := core.MemcachedUnixControlOperation{Format: 1, RequestID: request, ProjectID: project, ActorID: actor, Input: core.MemcachedUnixControlInput{Action: "stop", ExpectedRuntimeSHA256: strings.Repeat("d", 64), AcknowledgeCacheLoss: true}}
	in := core.MemcachedUnixControlReviewRequest{Format: 1, Operation: op, ReviewerID: strings.Repeat("e", 32)}
	raw, _ := json.Marshal(in)
	for _, kind := range []string{"unsigned-preview", "unsigned-confirmation", "query", "foreign-project", "foreign-request", "bad-reviewer", "extra-command", "alias", "duplicate", "null-input", "bad-ack", "trailing", "overflow"} {
		t.Run(kind, func(t *testing.T) {
			path := "/v1/memcached-unix/projects/" + project + "/controls/" + request + "/review"
			body := append([]byte(nil), raw...)
			value := in
			want := http.StatusBadRequest
			switch kind {
			case "unsigned-preview":
				want = http.StatusConflict
			case "unsigned-confirmation":
				value.Input = &core.MemcachedUnixControlReviewInput{ExpectedRuntimeSHA256: strings.Repeat("d", 64), AcknowledgeOriginalUnknown: true}
				body, _ = json.Marshal(value)
				want = http.StatusConflict
			case "query":
				path += "?retry=true"
				want = http.StatusNotFound
			case "foreign-project":
				value.Operation.ProjectID = strings.Repeat("f", 32)
				body, _ = json.Marshal(value)
			case "foreign-request":
				value.Operation.RequestID = strings.Repeat("f", 32)
				body, _ = json.Marshal(value)
			case "bad-reviewer":
				value.ReviewerID = "root"
				body, _ = json.Marshal(value)
			case "extra-command":
				body = append([]byte("{\"command\":\"restart\","), body[1:]...)
			case "alias":
				body = []byte(strings.Replace(string(body), "\"reviewer_id\"", "\"Reviewer_ID\"", 1))
			case "duplicate":
				body = append([]byte("{\"format\":1,"), body[1:]...)
			case "null-input":
				body = append(body[:len(body)-1], []byte(",\"input\":null}")...)
			case "bad-ack":
				value.Input = &core.MemcachedUnixControlReviewInput{ExpectedRuntimeSHA256: strings.Repeat("d", 64)}
				body, _ = json.Marshal(value)
			case "trailing":
				body = append(body, '\n')
			case "overflow":
				body = []byte(strings.Repeat(" ", core.MaxMemcachedUnixControlReviewBytes+1))
			}
			paths := []string{memcachedUnixControlsRoot, memcachedUnixInstallJobsRoot, "/var/lib/panel-executor/memcached-accounts", "/var/lib/panel-executor/docker-jobs/compose.lock"}
			before := map[string]os.FileInfo{}
			for _, name := range paths {
				info, err := os.Lstat(name)
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				before[name] = info
			}
			mux := http.NewServeMux()
			New(Config{}).memcachedUnixControlReviewRoutes(mux)
			out := httptest.NewRecorder()
			mux.ServeHTTP(out, httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body))))
			if out.Code != want {
				t.Fatal(kind, out.Code, out.Body.String())
			}
			for _, name := range paths {
				after, err := os.Lstat(name)
				if before[name] == nil {
					if !os.IsNotExist(err) {
						t.Fatal("review initialized a production namespace", name, err)
					}
				} else if err != nil || !geoStoreStableInfo(before[name], after) {
					t.Fatal("review altered existing native state", name, err)
				}
			}
		})
	}
	if _, err := runMemcachedUnixControlReview(nil, in); err == nil {
		t.Fatal("nil review context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := runMemcachedUnixControlReview(ctx, in); err == nil {
		t.Fatal("cancelled review context accepted")
	}
}
