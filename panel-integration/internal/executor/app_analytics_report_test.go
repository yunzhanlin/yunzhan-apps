package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"strconv"
	"strings"
	"testing"
	"time"
)

func analyticsFixture() string {
	return `{"time":"2026-10-05T10:00:10Z","remote":"192.0.2.1","method":"GET","path":"/home?password=secret","status":200,"bytes":100,"seconds":0.2,"agent":"Mozilla Chrome/123 Mobile","referer":"https://user:secret@example.test/source?token=secret#secret"}
{"time":"2026-10-05T10:00:20Z","remote":"192.0.2.2","method":"POST","path":"/slow","status":503,"bytes":20,"seconds":2.5,"agent":"Examplebot/1.0"}
{"time":"2026-10-05T09:00:00Z","remote":"192.0.2.1","method":"GET","path":"/old","status":404,"bytes":10,"seconds":0.1,"agent":"Mozilla Firefox/1.0"}
bad-line
`
}

func TestAnalyticsReportStaysBelowExecutorResponseLimit(t *testing.T) {
	var input strings.Builder
	for i := 0; i < 1500; i++ {
		row := analyticsAccess{Time: "2026-10-05T10:00:20Z", Remote: "192.0.2.1", Method: "GET", Path: "/" + strings.Repeat("x", 4096) + strconv.Itoa(i), Status: 500, Seconds: 3}
		raw, _ := json.Marshal(row)
		input.Write(raw)
		input.WriteByte('\n')
	}
	r, e := buildAnalyticsReport(context.Background(), strings.NewReader(input.String()), "site", core.AppModuleInput{}, false, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(r)
	if len(raw) >= 1<<20 || r["partial"] != true || r["requests"] != 1500 {
		t.Fatal("unbounded or misleading report", len(raw), r["requests"])
	}
}

func TestAnalyticsReportUsesRealTimeAndRequestFilters(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-10-05T10:00:30Z")
	r, e := buildAnalyticsReport(context.Background(), strings.NewReader(analyticsFixture()), "site", core.AppModuleInput{FromTime: "2026-10-05T10:00:00Z", ToTime: "2026-10-05T10:01:00Z"}, false, now)
	if e != nil {
		t.Fatal(e)
	}
	if r["requests"] != 2 || r["unique_ips"] != 2 || r["bots"] != 1 || r["errors"] != 1 || r["slow_count"] != 1 || r["average_seconds"] != 1.35 || r["qps_last_minute"] != float64(2)/60 {
		t.Fatal(r)
	}
	if r["paths"].(map[string]int)["/home"] != 1 || r["referers"].(map[string]int)["https://example.test/source"] != 1 || len(r["visitors"].([]analyticsVisitor)) != 2 {
		t.Fatal(r)
	}
	for _, in := range []core.AppModuleInput{{OnlyBots: true}, {StatusCode: 503}, {Search: "/slow"}, {Search: "192.0.2.2"}} {
		r, e = buildAnalyticsReport(context.Background(), strings.NewReader(analyticsFixture()), "site", in, false, now)
		if e != nil || r["requests"] != 1 {
			t.Fatal(in, r, e)
		}
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "secret") {
		t.Fatal("report leaked credentials/query parameters")
	}
}

func TestAnalyticsValidationEmptyLogAndSampleBounds(t *testing.T) {
	for _, in := range []core.AppModuleInput{{FromTime: "wrong"}, {ToTime: "wrong"}, {StatusCode: 600}, {MinSeconds: -1}, {Search: strings.Repeat("x", 257)}, {FromTime: "2026-10-05T10:00:00Z", ToTime: "2026-10-05T09:00:00Z"}} {
		if _, _, e := analyticsWindow(in); e == nil {
			t.Fatal("invalid filter accepted", in)
		}
	}
	r, e := buildAnalyticsReport(context.Background(), strings.NewReader(""), "site", core.AppModuleInput{}, false, time.Now())
	if e != nil || r["requests"] != 0 || r["average_seconds"] != float64(0) {
		t.Fatal(r, e)
	}
	line := `{"time":"2026-10-05T10:00:20Z","remote":"192.0.2.2","method":"GET","path":"/slow","status":500,"bytes":20,"seconds":2}` + "\n"
	r, e = buildAnalyticsReport(context.Background(), strings.NewReader(strings.Repeat(line, 250)), "site", core.AppModuleInput{}, true, time.Now())
	if e != nil || r["requests"] != 250 || len(r["slow_requests"].([]map[string]any)) != 100 || len(r["error_requests"].([]map[string]any)) != 100 || r["partial"] != true {
		t.Fatal(r, e)
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = buildAnalyticsReport(c, strings.NewReader(line), "site", core.AppModuleInput{}, false, time.Now()); e == nil {
		t.Fatal("cancel ignored")
	}
}
