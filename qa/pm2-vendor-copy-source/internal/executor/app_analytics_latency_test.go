package executor

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestAnalyticsReportExactLatencyRanksAndHistogramEdges(t *testing.T) {
	a := analyticsLatencyAccumulator{}
	for i := 100; i >= 1; i-- {
		a.add(float64(i) / 100)
	}
	r, err := a.report(context.Background(), false)
	if err != nil || !r.QuantilesAvailable || r.Samples != 100 || *r.P50 != .5 || *r.P90 != .9 || *r.P95 != .95 || *r.P99 != .99 {
		t.Fatal(r, err)
	}
	edges := analyticsLatencyAccumulator{}
	for _, n := range []float64{0, .05, .050001, .1, .100001, .25, .250001, .5, .500001, 1, 1.000001, 2, 2.000001, 5, 5.000001, 10, 10.000001, 86400} {
		edges.add(n)
	}
	r, err = edges.report(context.Background(), true)
	if err != nil || !r.PopulationPartial || !r.QuantilesAvailable || r.Requests != 18 || *r.P99 != 86400 {
		t.Fatal(r, err)
	}
	total := 0
	for i, b := range r.Histogram {
		total += b.Requests
		if b.Requests != 2 || math.Abs(b.Percent-100.0/9) > 1e-12 || b.Range != analyticsLatencyLabels[i] || i < 8 && (b.UpperSeconds == nil || *b.UpperSeconds != analyticsLatencyBounds[i]) || i == 8 && b.UpperSeconds != nil {
			t.Fatal("histogram boundary or unbounded tail changed", i, b)
		}
	}
	if total != r.Requests {
		t.Fatal("histogram does not cover the whole population")
	}
}

func TestAnalyticsReportLatencyHasNoFakeEmptyOrBiasedQuantiles(t *testing.T) {
	a := analyticsLatencyAccumulator{}
	empty, err := a.report(context.Background(), false)
	if err != nil || empty.QuantilesAvailable || empty.P50 != nil || empty.P99 != nil || empty.Requests != 0 {
		t.Fatal(empty, err)
	}
	raw, _ := json.Marshal(empty)
	if !strings.Contains(string(raw), `"p50_seconds":null`) {
		t.Fatal("empty population became a zero latency")
	}
	for i := 0; i < analyticsLatencySampleLimit; i++ {
		a.add(0)
	}
	at, err := a.report(context.Background(), false)
	if err != nil || !at.QuantilesAvailable || at.SampleLimited || at.Samples != analyticsLatencySampleLimit || *at.P99 != 0 || cap(a.samples) > analyticsLatencySampleLimit {
		t.Fatal("exact bounded population rejected or capacity widened", at, err)
	}
	a.add(86400)
	over, err := a.report(context.Background(), false)
	if err != nil || over.QuantilesAvailable || !over.SampleLimited || over.Samples != 0 || over.P50 != nil || over.P99 != nil || over.Requests != analyticsLatencySampleLimit+1 || over.Histogram[8].Requests != 1 || a.samples != nil {
		t.Fatal("discarded tail would have produced biased quantiles", over, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.report(ctx, false); err == nil {
		t.Fatal("cancelled latency report accepted")
	}
}

func TestAnalyticsReportLatencySharesTrafficFiltersAndSlowThreshold(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-10-05T10:00:30Z")
	for _, tc := range []struct {
		in       core.AppModuleInput
		requests int
		p50      float64
		p99      float64
		slow     int
	}{
		{core.AppModuleInput{}, 3, .2, 2.5, 1},
		{core.AppModuleInput{MinSeconds: 3}, 3, .2, 2.5, 0},
		{core.AppModuleInput{OnlyBots: true}, 1, 2.5, 2.5, 1},
		{core.AppModuleInput{StatusCode: 404}, 1, .1, .1, 0},
		{core.AppModuleInput{Search: "/home"}, 1, .2, .2, 0},
		{core.AppModuleInput{FromTime: "2026-10-05T10:00:00Z"}, 2, .2, 2.5, 1},
	} {
		out, err := buildAnalyticsReport(context.Background(), strings.NewReader(analyticsFixture()), "site", tc.in, false, now)
		if err != nil {
			t.Fatal(err)
		}
		r := out["latency"].(analyticsLatencyReport)
		if out["requests"] != tc.requests || out["slow_count"] != tc.slow || r.Requests != tc.requests || r.Samples != tc.requests || !r.QuantilesAvailable || *r.P50 != tc.p50 || *r.P99 != tc.p99 {
			t.Fatal("latency and traffic population differ", tc, out)
		}
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "192.0.2") || strings.Contains(string(raw), "/home") {
			t.Fatal("aggregate latency retained request identity")
		}
	}
}
