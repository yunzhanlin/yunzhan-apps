//go:build linux

package executor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemcachedUnixControlFingerprintBindsStableRuntimeNotHealthLogClock(t *testing.T) {
	raw := []byte("{\"Id\":\"" + strings.Repeat("a", 64) + "\",\"Image\":\"sha256:" + strings.Repeat("b", 64) + "\",\"State\":{\"Pid\":123,\"Running\":true,\"StartedAt\":\"2026-10-24T00:00:00.000000001Z\",\"FinishedAt\":\"0001-01-01T00:00:00Z\",\"Health\":{\"Status\":\"healthy\",\"Log\":[\"first clock\"]}}}")
	first, err := memcachedUnixRuntimeFingerprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	other := []byte(strings.Replace(string(raw), "first clock", "later healthy clock", 1))
	if actual, err := memcachedUnixRuntimeFingerprint(other); err != nil || actual != first {
		t.Fatal("health clock invalidated deliberate action precondition", err)
	}
	for _, kind := range []string{"pid", "start", "image", "id", "stopped", "ambiguous"} {
		t.Run(kind, func(t *testing.T) {
			b := string(raw)
			switch kind {
			case "pid":
				b = strings.Replace(b, "\"Pid\":123", "\"Pid\":124", 1)
			case "start":
				b = strings.Replace(b, ".000000001Z", ".000000002Z", 1)
			case "image":
				b = strings.Replace(b, strings.Repeat("b", 64), strings.Repeat("c", 64), 1)
			case "id":
				b = strings.Replace(b, strings.Repeat("a", 64), strings.Repeat("c", 64), 1)
			case "stopped":
				b = strings.Replace(b, "\"Running\":true", "\"Running\":false", 1)
				b = strings.Replace(b, "\"Pid\":123", "\"Pid\":0", 1)
			case "ambiguous":
				b = strings.Replace(b, "\"Pid\":123", "\"Pid\":123,\"pid\":123", 1)
			}
			next, err := memcachedUnixRuntimeFingerprint(json.RawMessage(b))
			if kind == "ambiguous" {
				if err == nil {
					t.Fatal("alias accepted")
				}
				return
			}
			if err != nil || next == first {
				t.Fatal("changed process or image borrowed prior confirmation", err)
			}
		})
	}
}
