//go:build linux

package executor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestDockerStatsUsesActualCounterDeltasAndCacheFields(t *testing.T) {
	const raw = `{
		"id": "fixture",
		"read": "2026-11-12T00:10:00Z",
		"cpu_stats": {"cpu_usage": {"total_usage": 1600}, "system_cpu_usage": 4000, "online_cpus": 4},
		"precpu_stats": {"cpu_usage": {"total_usage": 1500}, "system_cpu_usage": 3000},
		"memory_stats": {"usage": 4096, "limit": 8192, "stats": {"inactive_file": 1024}},
		"pids_stats": {"current": 7},
		"networks": {"eth0": {"rx_bytes": 12, "tx_bytes": 20}, "eth1": {"rx_bytes": 8, "tx_bytes": 6}},
		"blkio_stats": {"io_service_bytes_recursive": [{"op":"read","value":10},{"op":"Read","value":4},{"op":"Write","value":9}]}
	}`
	for _, cache := range []string{"inactive_file", "total_inactive_file", "cache"} {
		var source dockerStatsResponse
		if err := json.Unmarshal([]byte(strings.Replace(raw, "inactive_file", cache, 1)), &source); err != nil {
			t.Fatal(err)
		}
		got, err := dockerStatsMetrics(source, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		if got.CPUPercent == nil || *got.CPUPercent != 40 {
			t.Fatalf("wrong CPU result: %+v", got)
		}
		for label, field := range map[string]struct {
			value *uint64
			want  uint64
		}{
			"memory": {got.MemoryBytes, 3072}, "limit": {got.MemoryLimit, 8192},
			"rx": {got.NetworkRX, 20}, "tx": {got.NetworkTX, 26},
			"block-read": {got.BlockRead, 14}, "block-write": {got.BlockWritten, 9},
			"pids": {got.PIDs, 7},
		} {
			if field.value == nil || *field.value != field.want {
				t.Errorf("%s/%s wrong counter: %v", cache, label, field.value)
			}
		}
		source.Previous = dockerCPUStats{}
		source.Networks = nil
		got, err = dockerStatsMetrics(source, "fixture")
		if err != nil || got.CPUPercent != nil || got.NetworkRX != nil || got.NetworkTX != nil {
			t.Fatalf("missing counters became measured zero: %+v %v", got, err)
		}
		if _, err = dockerStatsMetrics(source, "different"); err == nil {
			t.Fatal("sample from a different container was accepted")
		}
	}
}

func TestDockerContainerStatsReadsNativeEngine(t *testing.T) {
	id := os.Getenv("PANEL_DOCKER_STATS_NATIVE_ID")
	if id == "" {
		t.Skip("running container on an owned Docker host required")
	}
	if !core.ValidDockerContainerID(id) {
		t.Fatal("a full container ID is required")
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/docker/containers/"+id+"/stats", nil)
	request.SetPathValue("id", id)
	out := httptest.NewRecorder()
	dockerContainerStats(out, request)
	if out.Code != http.StatusOK {
		t.Fatal(out.Code, out.Body.String())
	}
	var sample dockerStatsSample
	if err := json.Unmarshal(out.Body.Bytes(), &sample); err != nil {
		t.Fatal(err)
	}
	if sample.ID != id || sample.ObservedAt.IsZero() || sample.CPUPercent == nil ||
		sample.MemoryBytes == nil || sample.MemoryLimit == nil || sample.PIDs == nil || *sample.PIDs == 0 {
		t.Fatalf("native Engine omitted core metrics: %s", out.Body)
	}
}
