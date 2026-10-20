package core

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMonitorProcessesActualAuthPreservesAvailabilityIdentityAndSamplingBounds(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	accessUser(t, s, "monitor-admin", "admin", []string{"monitor"})
	calls := 0
	reply := `{"processes":[{"pid":42,"name":"fixture","start_time":12345,"cpu_percent":0,"cpu_available":true,"io_available":false,"read_rate":0,"write_rate":0,"memory":4096,"state":"S"}],"tcp_connections":null,"partial":true,"display_limited":true,"sample_limit":2000,"display_limit":500,"sampled_processes":501,"displayed_processes":1}`
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/monitor/processes" {
			t.Fatal("unrelated mutation during monitor read", r.Method, r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(reply))}, nil
	})}}
	if w := wafTaskTestRead(a, "/api/monitor/processes", nil); w.Code != 401 || calls != 0 {
		t.Fatal("unauthenticated monitor dispatched", w.Code, calls)
	}
	cookie := login("monitor-admin")
	w := wafTaskTestRead(a, "/api/monitor/processes", cookie)
	var out map[string]any
	if w.Code != 200 || calls != 1 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out["tcp_connections"] != nil || out["partial"] != true || out["display_limited"] != true || out["sample_limit"] != float64(2000) || out["display_limit"] != float64(500) || out["sampled_processes"] != float64(501) || out["displayed_processes"] != float64(1) {
		t.Fatal("actual Core lost snapshot scope or unknown TCP", w.Code)
	}
	row := out["processes"].([]any)[0].(map[string]any)
	if row["cpu_available"] != true || row["io_available"] != false || row["start_time"] != float64(12345) || row["cpu_percent"] != float64(0) {
		t.Fatal("actual Core lost known-zero or unknown-I/O identity", row)
	}
	reply = `{"processes":[{"pid":42,"name":"old-fixture","cpu_percent":0,"read_rate":0,"write_rate":0}]}`
	w = wafTaskTestRead(a, "/api/monitor/processes", cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatal("legacy monitor response fixture", w.Code)
	}
	row = out["processes"].([]any)[0].(map[string]any)
	if row["cpu_available"] != false || row["io_available"] != false || row["start_time"] != float64(0) || out["sample_limit"] != float64(0) {
		t.Fatal("legacy missing provenance invented a valid sample", row)
	}
	t.Log("Actual Core auth/JSON forwarding with closed executor fixtures, not native kernel telemetry")
}
