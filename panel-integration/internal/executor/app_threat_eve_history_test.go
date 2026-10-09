package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestThreatEVEHistoryMergesAndPagesWithoutReusingArchiveCounters(t *testing.T) {
	stats := func(at string, n int) string {
		return fmt.Sprintf(`{"event_type":"stats","timestamp":%q,"stats":{"decoder":{"pkts":%d}}}`, at, n)
	}
	sources := []threatEVESource{
		{Reader: strings.NewReader(threatEVEFixture("2026-10-09T02:00:00Z", 1, 101) + "\n" + stats("2026-10-09T02:00:00Z", 7)), Live: true},
		{Reader: strings.NewReader(threatEVEFixture("2026-10-09T01:00:00Z", 2, 102) + "\n" + stats("2026-10-09T03:00:00Z", 999))},
		{Reader: strings.NewReader(threatEVEFixture("2026-10-09T00:00:00Z", 1, 103))},
	}
	out, err := readThreatEVESources(context.Background(), sources, threatEVEFilter{Limit: 1, Offset: 1}, false)
	if err != nil || out.MatchingAlerts != 3 || len(out.Alerts) != 1 || out.Alerts[0].SignatureID != 102 || out.Stats == nil || *out.Stats.DecodedPackets != 7 || out.Partial || !out.PageLimited || out.ScannedRecords != 5 || out.SeverityCounts[1] != 2 {
		t.Fatal("history/counter source/paging contract", out, err)
	}
	b, _ := json.Marshal(out)
	for _, forbidden := range []string{"NEVER_RETURN", "payload", "request_headers", "http_body"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatal("private history fields escaped")
		}
	}
	out, err = readThreatEVESources(context.Background(), []threatEVESource{{Reader: strings.NewReader(""), Live: true}, {Reader: strings.NewReader(stats("2026-10-09T03:00:00Z", 999))}}, threatEVEFilter{}, false)
	if err != nil || out.Stats != nil {
		t.Fatal("archive alone fabricated current capture", out, err)
	}
}

func TestThreatEVEHistoryHasOneGlobalScanBudgetAndClosedSources(t *testing.T) {
	line := `{"event_type":"flow"}` + "\n"
	sources := []threatEVESource{{Reader: strings.NewReader(strings.Repeat(line, threatEVERecordLimit-1)), Live: true}, {Reader: strings.NewReader(line + line)}}
	out, err := readThreatEVESources(context.Background(), sources, threatEVEFilter{}, false)
	if err != nil || !out.Partial || out.ScannedRecords != threatEVERecordLimit {
		t.Fatal("per-file rather than global record quota", out, err)
	}
	for _, sources := range [][]threatEVESource{nil, {{Reader: strings.NewReader("")}}, {{Live: true}}, {{Reader: strings.NewReader(""), Live: true}, {Reader: strings.NewReader(""), Live: true}}, make([]threatEVESource, 6)} {
		if _, err := readThreatEVESources(context.Background(), sources, threatEVEFilter{}, false); err == nil {
			t.Fatal("unknown source list accepted")
		}
	}
	if _, err := readThreatEVESources(context.Background(), []threatEVESource{{Reader: strings.NewReader(""), Live: true}, {Reader: threatEVEBrokenReader{}}}, threatEVEFilter{}, false); err == nil {
		t.Fatal("history reader failure hidden")
	}
}
