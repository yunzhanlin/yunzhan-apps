package executor

import (
	"bytes"
	"strings"
	"testing"
)

func TestStatisticsHealthConfigPreservesAndRotatesOnlyManagedProbe(t *testing.T) {
	socket := "/run/panel-nginx/statistics-log-health.sock"
	nonce := strings.Repeat("a", 32)
	original := statisticsNginxTestConfig(statisticsNginxLegacyFormat)
	candidate, err := statisticsNginxHealthConfig(original, socket, nonce)
	if err != nil {
		t.Fatal(err)
	}
	got, err := statisticsHealthConfigNonce(candidate, socket)
	if err != nil || got != nonce {
		t.Fatal(got, err)
	}
	next, err := statisticsNginxHealthConfig(candidate, socket, strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(next, []byte(statisticsHealthBegin)) != 1 || bytes.Contains(next, []byte("yunzhan-statistics-log-v2:"+nonce)) {
		t.Fatal("probe duplicated instead of rotated")
	}
	if _, changed, err := statisticsRequestIDNginxConfig(next); err != nil || changed {
		t.Fatal("health plan changed managed request format", err)
	}
}
func TestStatisticsHealthConfigRejectsAmbiguousOrExternalProbeChanges(t *testing.T) {
	socket := "/run/panel-nginx/statistics-log-health.sock"
	candidate, err := statisticsNginxHealthConfig(statisticsNginxTestConfig(statisticsNginxLegacyFormat), socket, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range [][]byte{append(bytes.Clone(candidate), []byte(statisticsHealthBegin)...), bytes.Replace(candidate, []byte("access_log off"), []byte("access_log /tmp/custom"), 1), bytes.Replace(candidate, []byte(socket), []byte("/tmp/foreign.sock"), 1)} {
		if _, err := statisticsNginxHealthConfig(source, socket, strings.Repeat("b", 32)); err == nil {
			t.Fatal("external probe source was overwritten")
		}
	}
	for _, path := range []string{"/tmp/a;bad", "relative", "/run/../tmp/x.sock"} {
		if _, err := statisticsHealthBlock(path, strings.Repeat("a", 32)); err == nil {
			t.Fatal("unsafe socket admitted")
		}
	}
	block, _ := statisticsHealthBlock(socket, strings.Repeat("a", 32))
	for _, source := range [][]byte{block, append(statisticsNginxTestConfig(statisticsNginxLegacyFormat), block...), []byte("http { server {\n" + string(block) + "} }"), []byte("http { set $quoted '" + string(block) + "'; }")} {
		if _, err := statisticsHealthConfigNonce(source, socket); err == nil {
			t.Fatal("non-top-level or quoted health listener accepted")
		}
	}
	original := statisticsNginxTestConfig(statisticsNginxLegacyFormat)
	nearBudget := append([]byte("# "+strings.Repeat("x", (1<<20)-len(original)-3)+"\n"), original...)
	if len(nearBudget) != 1<<20 {
		t.Fatal("owned size fixture")
	}
	if _, err := statisticsNginxHealthConfig(nearBudget, socket, strings.Repeat("a", 32)); err == nil {
		t.Fatal("generated candidate exceeded its recoverable backup budget")
	}
}
