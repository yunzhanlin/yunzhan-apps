package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestElasticsearchRestoreWaitsForSearchablePrimaryShards(t *testing.T) {
	const index = "restored-records-12345678901234567890123456789012"
	const healthy = `{"status":"green","indices":{"` + index + `":{"status":"yellow","number_of_shards":2}}}`
	const queryRoute = "/" + index + "/_search?allow_partial_search_results=false&size=1&_source=false&track_total_hits=false&terminate_after=1"
	for _, test := range []struct {
		name         string
		health       string
		searchStatus int
		searchBody   string
		state        string
	}{
		{"allocated but search returns 503", healthy, http.StatusServiceUnavailable, "", "running"},
		{"allocated but search returns 429", healthy, http.StatusTooManyRequests, "", "running"},
		{"all shards readable", healthy, http.StatusOK, `{"timed_out":false,"_shards":{"total":2,"successful":2,"failed":0}}`, "complete"},
		{"only one shard searched", healthy, http.StatusOK, `{"timed_out":false,"_shards":{"total":1,"successful":1,"failed":0}}`, "running"},
		{"one shard failed", healthy, http.StatusOK, `{"timed_out":false,"_shards":{"total":2,"successful":1,"failed":1}}`, "running"},
		{"search timed out", healthy, http.StatusOK, `{"timed_out":true,"_shards":{"total":2,"successful":2,"failed":0}}`, "running"},
		{"invalid response", healthy, http.StatusOK, `{"_shards":{"total":2,"successful":2}}`, ""},
		{"index deleted after health observation", healthy, http.StatusNotFound, "", "missing"},
		{"unassigned primary", strings.Replace(healthy, "yellow", "red", 1), 0, "", "running"},
		{"target absent", `{"status":"green","indices":{}}`, 0, "", "missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			searches := 0
			call := func(_ context.Context, method, route string, in, out any) (int, error) {
				if method != http.MethodGet || in != nil {
					t.Fatalf("expected read-only request, got %s %v", method, in)
				}
				switch route {
				case "/_cluster/health/" + index + "?level=indices&timeout=4s":
					return http.StatusOK, json.Unmarshal([]byte(test.health), out)
				case queryRoute:
					searches++
					if test.searchStatus == 0 {
						t.Fatal("searched before the target index was ready")
					}
					if test.searchBody != "" {
						return test.searchStatus, json.Unmarshal([]byte(test.searchBody), out)
					}
					return test.searchStatus, nil
				default:
					t.Fatalf("unexpected request URL %s", route)
					return 0, nil
				}
			}
			state, err := observeElasticsearchRestore(context.Background(), call, index)
			if state != test.state || (err != nil) != (test.state == "") {
				t.Fatalf("state = %q, err = %v; want %q", state, err, test.state)
			}
			if test.searchStatus != 0 && searches != 1 {
				t.Fatalf("search requests = %d; want one", searches)
			}
		})
	}
}
