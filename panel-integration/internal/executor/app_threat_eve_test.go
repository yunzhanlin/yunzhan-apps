package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func threatEVEFixture(at string, severity int, id int) string {
	return fmt.Sprintf(`{"timestamp":%q,"event_type":"alert","src_ip":"::ffff:192.0.2.10","dest_ip":"2001:db8::20","src_port":44300,"dest_port":80,"proto":"TCP","alert":{"signature_id":%d,"signature":"CloudStack traversal attempt","category":"Web application attack","severity":%d,"action":"allowed"},"payload":"NEVER_RETURN_PAYLOAD","http":{"url":"/secret?token=NEVER_RETURN_TOKEN","request_headers":{"Authorization":"NEVER_RETURN_AUTH"}}}`, at, id, severity)
}
func TestThreatEVEMetadataPrivacyAndExactLargeCounters(t *testing.T) {
	input := threatEVEFixture("2026-10-09T09:00:01.123456789+0800", 1, 9000001)
	input += "\n" + `{"timestamp":"2026-10-09T01:00:02Z","event_type":"stats","stats":{"capture":{"kernel_packets":9007199254740993,"kernel_drops":0},"decoder":{"pkts":9007199254740995}}}`
	out, err := readThreatEVE(context.Background(), strings.NewReader(input), threatEVEFilter{}, false)
	if err != nil || out.Partial || out.ScannedRecords != 2 || out.MatchingAlerts != 1 || out.Stats == nil || *out.Stats.KernelPackets != 9007199254740993 || *out.Stats.DecodedPackets != 9007199254740995 || *out.Stats.KernelDrops != 0 {
		t.Fatal(out, err)
	}
	if out.Alerts[0].Timestamp != "2026-10-09T01:00:01.123456789Z" || out.Alerts[0].SourceIP != "192.0.2.10" {
		t.Fatal(out.Alerts)
	}
	encoded, _ := json.Marshal(out)
	if !strings.Contains(string(encoded), `"kernel_packets":"9007199254740993"`) || !strings.Contains(string(encoded), `"decoded_packets":"9007199254740995"`) {
		t.Fatal("browser wire counters lost exact uint64", string(encoded))
	}
	for _, secret := range []string{"NEVER_RETURN", "payload", "Authorization", "http", "token=", "src_ip", "request_headers"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("event privacy leakage:", secret)
		}
	}
}
func TestThreatEVEOrderFiltersAndPagination(t *testing.T) {
	at := time.Date(2026, 10, 9, 1, 0, 0, 0, time.UTC)
	input := ""
	for i := 0; i < 10; i++ {
		input += threatEVEFixture(at.Add(time.Duration(i)*time.Second).Format(time.RFC3339), i%3+1, 9000000+i) + "\n"
	}
	out, err := readThreatEVE(context.Background(), strings.NewReader(input), threatEVEFilter{From: at.Add(2 * time.Second), To: at.Add(8 * time.Second), Severity: 1, Search: "TRAVERSAL", Limit: 1, Offset: 1}, true)
	if err != nil || !out.Partial || !out.PageLimited || out.MatchingAlerts != 2 || len(out.Alerts) != 1 || out.Alerts[0].SignatureID != 9000003 || out.SeverityCounts[1] != 2 {
		t.Fatal(out, err)
	}
	out, err = readThreatEVE(context.Background(), strings.NewReader(input), threatEVEFilter{Offset: 100}, false)
	if err != nil || len(out.Alerts) != 0 || !out.PageLimited || out.MatchingAlerts != 10 {
		t.Fatal(out, err)
	}
	for _, filter := range []threatEVEFilter{{Limit: 201}, {Offset: -1}, {Offset: 20001}, {Severity: 5}, {Severity: -1}, {Search: "bad\ninput"}, {Search: strings.Repeat("x", 129)}, {From: at.Add(time.Second), To: at}} {
		if _, err := readThreatEVE(context.Background(), strings.NewReader(input), filter, false); err == nil {
			t.Fatal("invalid filter accepted", filter)
		}
	}
}
func TestThreatEVEMalformedIsExplicitPartialAndNoInventedStats(t *testing.T) {
	valid := threatEVEFixture("2026-10-09T01:00:01Z", 1, 9000001)
	cases := []string{"{", valid + " {}", strings.Replace(valid, "192.0.2.10", "not-ip", 1), strings.Replace(valid, "2001:db8::20", "::", 1), strings.Replace(valid, "2001:db8::20", "fe80::1%eth0", 1), strings.Replace(valid, "44300", "65536", 1), strings.Replace(valid, "9000001", "4294967296", 1), strings.Replace(valid, "\"severity\":1", "\"severity\":0", 1), strings.Replace(valid, "allowed", "unknown", 1), strings.Replace(valid, "TCP", "SHELL", 1), strings.Replace(valid, "traversal attempt", "bad\\u000aoutput", 1), strings.Replace(valid, "2026-10-09T01:00:01Z", "invalid-time", 1), `{"timestamp":"2026-10-09T01:00:01Z","event_type":"stats","stats":{}}`, `{"timestamp":"2026-10-09T01:00:01Z","event_type":"stats","stats":{"capture":{"kernel_packets":-1}}}`, `{"timestamp":"2026-10-09T01:00:01Z","event_type":"stats","stats":{"capture":{"kernel_packets":1.5}}}`}
	for _, input := range cases {
		out, err := readThreatEVE(context.Background(), strings.NewReader(input), threatEVEFilter{}, false)
		if err != nil || !out.Partial || out.InvalidRecords != 1 || out.MatchingAlerts != 0 || out.Stats != nil {
			t.Fatalf("malformed record accepted: %q %#v %v", input, out, err)
		}
	}
	out, err := readThreatEVE(context.Background(), strings.NewReader(""), threatEVEFilter{}, false)
	if err != nil || out.Stats != nil || len(out.Alerts) != 0 {
		t.Fatal("empty log invented counters", out, err)
	}
}
func TestThreatEVEBoundsCancellationAndLatestStats(t *testing.T) {
	line := threatEVEFixture("2026-10-09T01:00:01Z", 1, 9000001)
	out, err := readThreatEVE(context.Background(), strings.NewReader(strings.Repeat(`{"event_type":"flow"}`+"\n", threatEVERecordLimit+1)), threatEVEFilter{Limit: 200}, false)
	if err != nil || !out.Partial || out.ScannedRecords != threatEVERecordLimit || len(out.Alerts) != 0 {
		t.Fatal(out.ScannedRecords, len(out.Alerts), out.Partial, err)
	}
	out, err = readThreatEVE(context.Background(), strings.NewReader(strings.Repeat(line+"\n", threatEVERecordLimit+1)), threatEVEFilter{Limit: 200}, false)
	if err != nil || !out.Partial || out.ScannedRecords <= 0 || out.ScannedRecords >= threatEVERecordLimit || len(out.Alerts) != 200 {
		t.Fatal("byte budget did not stop before record budget", out.ScannedRecords, len(out.Alerts), out.Partial, err)
	}
	if _, err := readThreatEVE(context.Background(), strings.NewReader(strings.Repeat("x", threatEVELineLimit+1)), threatEVEFilter{}, false); err == nil {
		t.Fatal("oversized event accepted")
	}
	out, err = readThreatEVE(context.Background(), strings.NewReader(strings.Repeat(" \n", threatEVEByteLimit)), threatEVEFilter{}, false)
	if err != nil || !out.Partial {
		t.Fatal("byte bound ignored", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readThreatEVE(ctx, strings.NewReader(line), threatEVEFilter{}, false); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel ignored", err)
	}
	stats := `{"timestamp":"2026-10-09T01:00:02Z","event_type":"stats","stats":{"decoder":{"pkts":0}}}` + "\n" + `{"timestamp":"2026-10-09T01:00:01Z","event_type":"stats","stats":{"decoder":{"pkts":100}}}`
	out, err = readThreatEVE(context.Background(), strings.NewReader(stats), threatEVEFilter{}, false)
	if err != nil || out.Stats == nil || *out.Stats.DecodedPackets != 0 || out.Stats.KernelPackets != nil || out.Stats.KernelDrops != nil {
		t.Fatal("old/missing counter misreported", out, err)
	}
	if _, err = readThreatEVE(context.Background(), threatEVEBrokenReader{}, threatEVEFilter{}, false); err == nil {
		t.Fatal("read error ignored")
	}
}

type threatEVEBrokenReader struct{}

func (threatEVEBrokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestThreatEVERealTimestampsMissingKindAndCaptureFreshness(t *testing.T) {
	for _, at := range []string{"2026-10-09T09:00:00.123456+0800", "2026-10-09T09:00:00.123456+08:00", "2026-10-09T01:00:00.123456Z"} {
		value, err := parseThreatEVETime(at)
		if err != nil || value.UTC().Format(time.RFC3339Nano) != "2026-10-09T01:00:00.123456Z" {
			t.Fatal(value, err)
		}
	}
	for _, at := range []string{"2026-10-09T09:00:00", "2026-10-09T09:00:00+99:99", "invalid", "1999-01-01T00:00:00Z"} {
		if _, err := parseThreatEVETime(at); err == nil {
			t.Fatal("ambiguous time accepted", at)
		}
	}
	for _, raw := range []string{`{}`, `null`, `{"event_type":""}`, `{"event_type":"bad\nkind"}`} {
		out, err := readThreatEVE(context.Background(), strings.NewReader(raw), threatEVEFilter{}, false)
		if err != nil || !out.Partial || out.InvalidRecords != 1 {
			t.Fatal(out, err)
		}
	}
	now := time.Date(2026, 10, 9, 1, 0, 30, 0, time.UTC)
	started := now.Add(-time.Minute)
	zero := uint64(0)
	stats := &threatEVEStats{Timestamp: now.Add(-5 * time.Second).Format(time.RFC3339Nano), KernelPackets: &zero, KernelDrops: &zero, DecodedPackets: &zero, InvalidTCPChecksums: &zero, ReassemblyGaps: &zero, StreamMemcapDrops: &zero, AlertQueueOverflow: &zero}
	if threatIDSCaptureState(stats, now, started, true) != "observing" {
		t.Fatal("actual zero samples were unknown")
	}
	if threatIDSCaptureState(stats, now, started, false) != "not-running" || threatIDSCaptureState(nil, now, started, true) != "unknown" {
		t.Fatal("missing process/stats false health")
	}
	stats.Timestamp = now.Add(-26 * time.Second).Format(time.RFC3339Nano)
	if threatIDSCaptureState(stats, now, started, true) != "stale" {
		t.Fatal("stale capture reported healthy")
	}
	stats.Timestamp = now.Add(3 * time.Second).Format(time.RFC3339Nano)
	if threatIDSCaptureState(stats, now, started, true) != "unknown" {
		t.Fatal("future counters reported healthy")
	}
	stats.Timestamp = started.Add(-time.Second).Format(time.RFC3339Nano)
	if threatIDSCaptureState(stats, now, started, true) != "unknown" {
		t.Fatal("previous process counters reused")
	}
	stats.Timestamp = now.Format(time.RFC3339Nano)
	dropped := uint64(1)
	for _, problem := range []struct {
		ptr   **uint64
		state string
	}{{&stats.InvalidTCPChecksums, "capture-checksum-errors"}, {&stats.ReassemblyGaps, "capture-incomplete"}, {&stats.StreamMemcapDrops, "capture-incomplete"}, {&stats.AlertQueueOverflow, "alert-overflow"}} {
		*problem.ptr = &dropped
		if threatIDSCaptureState(stats, now, started, true) != problem.state {
			t.Fatal("actual packet processing loss hidden", problem.state)
		}
		*problem.ptr = &zero
	}
	stats.KernelDrops = &dropped
	if threatIDSCaptureState(stats, now, started, true) != "capture-drops" {
		t.Fatal("capture drops hidden")
	}
	stats.KernelPackets = nil
	if threatIDSCaptureState(stats, now, started, true) != "unknown" {
		t.Fatal("missing kernel counter invented")
	}
	b, err := json.Marshal(stats)
	if err != nil || !strings.Contains(string(b), `"kernel_packets":null`) {
		t.Fatal("missing wire counter lost", string(b), err)
	}
}
