package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func routeMillis(n float64) *float64 { return &n }

func TestAnalyticsRouteTimingBoundsAndSeparation(t *testing.T) {
	base := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "route-performance", Path: "/route", RouteReadyMillis: routeMillis(125), PerformanceSeq: 2}
	for _, n := range []float64{0, .5, 300000} {
		v := base
		v.RouteReadyMillis = routeMillis(n)
		if err := validateAnalyticsEvent(&v, false); err != nil || v.RouteReadyMillis == nil || *v.RouteReadyMillis != n {
			t.Fatal(n, v, err)
		}
	}
	for _, change := range []func(*AnalyticsEvent){
		func(v *AnalyticsEvent) { v.RouteReadyMillis = nil },
		func(v *AnalyticsEvent) { v.RouteReadyMillis = routeMillis(-1) },
		func(v *AnalyticsEvent) { v.RouteReadyMillis = routeMillis(300000.1) },
		func(v *AnalyticsEvent) { v.RouteReadyMillis = routeMillis(math.NaN()) },
		func(v *AnalyticsEvent) { v.RouteReadyMillis = routeMillis(math.Inf(1)) },
		func(v *AnalyticsEvent) { v.PerformanceSeq = 0 },
		func(v *AnalyticsEvent) { v.PerformanceSeq = 241 },
	} {
		v := base
		change(&v)
		if validateAnalyticsEvent(&v, false) == nil {
			t.Fatal("invalid route measurement accepted", v)
		}
	}
	v := base
	v.TTFB, v.FCP, v.LCP, v.INP, v.CLS = 1, 2, 3, 4, .5
	v.INPAvailable, v.CLSAvailable = true, true
	if err := validateAnalyticsEvent(&v, false); err != nil || v.TTFB != 0 || v.FCP != 0 || v.LCP != 0 || v.INP != 0 || v.CLS != 0 || v.INPAvailable || v.CLSAvailable || v.PerformanceSeq != 2 {
		t.Fatal("route borrowed document metrics", v, err)
	}
	for _, kind := range []string{"performance", "pageview", "engagement", "click"} {
		v := base
		v.Kind = kind
		if err := validateAnalyticsEvent(&v, true); err != nil || v.RouteReadyMillis != nil {
			t.Fatal("route timing leaked into other kind", v, err)
		}
	}
}

func TestAnalyticsRouteReportDeduplicatesWithoutChangingJourneyOrDocument(t *testing.T) {
	a, _, c := analyticsFixture(t, true)
	visitor, session, doc, first, second := ID(), ID(), ID(), ID(), ID()
	events := []AnalyticsEvent{
		{ID: ID(), PageID: doc, Visitor: visitor, Session: session, Kind: "pageview", Path: "/document"},
		{ID: ID(), PageID: doc, Visitor: visitor, Session: session, Kind: "performance", Path: "/document", INP: 100, INPAvailable: true, PerformanceSeq: 2},
		{ID: ID(), PageID: first, Visitor: visitor, Session: session, Kind: "pageview", Path: "/catalog"},
		{ID: ID(), PageID: first, Visitor: visitor, Session: session, Kind: "route-performance", Path: "/catalog", RouteReadyMillis: routeMillis(500), PerformanceSeq: 3},
		{ID: ID(), PageID: first, Visitor: visitor, Session: session, Kind: "route-performance", Path: "/catalog?token=never-retain#secret", RouteReadyMillis: routeMillis(200), PerformanceSeq: 9},
		// Earlier sequence deliberately arrives last. Arrival order is not completion.
		{ID: ID(), PageID: first, Visitor: visitor, Session: session, Kind: "route-performance", Path: "/catalog", RouteReadyMillis: routeMillis(900), PerformanceSeq: 4},
		{ID: ID(), PageID: second, Visitor: visitor, Session: session, Kind: "pageview", Path: "/checkout"},
		{ID: ID(), PageID: second, Visitor: visitor, Session: session, Kind: "route-performance", Path: "/checkout", RouteReadyMillis: routeMillis(0), PerformanceSeq: 10},
		{ID: ID(), PageID: doc, Visitor: visitor, Session: session, Kind: "performance", Path: "/document", INP: 80, INPAvailable: true, PerformanceSeq: 15},
		{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "route-performance", Path: "/passive-only", RouteReadyMillis: routeMillis(300), PerformanceSeq: 1},
	}
	for _, event := range events {
		if w := analyticsRequest(a, c, event, "https://analytics.example"); w.Code != 204 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	report, err := a.Store.analyticsReport(context.Background(), c.SiteID, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	counts := report["overview"].(map[string]any)
	for _, key := range []string{"sessions", "uv", "active_visitors"} {
		if counts[key] != 1 {
			t.Fatal("passive timing invented activity", counts)
		}
	}
	if counts["pv"] != 3 {
		t.Fatal(counts)
	}
	journeys := report["sessions"].([]*analyticsSession)
	if len(journeys) != 1 || len(journeys[0].Journey) != 3 || journeys[0].Exit != "/checkout" {
		t.Fatal(journeys)
	}
	inp := report["performance"].(map[string]any)["inp"].(map[string]any)
	if inp["samples"] != 1 || inp["p75"] != float64(80) {
		t.Fatal("SPA changed document INP", inp)
	}
	pages := report["performance_pages"].(analyticsPerformancePages)
	if pages.Partial || pages.SampledVisits != 4 || len(pages.Rows) != 4 {
		t.Fatal(pages)
	}
	for _, row := range pages.Rows {
		if row.Navigations != 1 {
			t.Fatal("duplicate route score", row)
		}
		if row.Kind == "document" {
			if row.Path != "/document" || row.Metrics["inp"]["p75"] != float64(80) {
				t.Fatal(row)
			}
			if _, found := row.Metrics["route_ready_ms"]; found {
				t.Fatal(row)
			}
		} else {
			want := map[string]float64{"/catalog": 200, "/checkout": 0, "/passive-only": 300}[row.Path]
			if len(row.Metrics) != 1 || row.Metrics["route_ready_ms"]["samples"] != 1 || row.Metrics["route_ready_ms"]["p75"] != want {
				t.Fatal(row)
			}
		}
	}
	var leaked int
	if err := a.Store.DB.QueryRow(`SELECT count(*) FROM analytics_events WHERE data LIKE '%never-retain%' OR data LIKE '%192.0.2.8%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("route telemetry privacy", leaked, err)
	}
	if w := analyticsRequest(a, c, events[3], "https://other-site.example"); w.Code != 403 {
		t.Fatal("new kind bypassed site origin", w.Code)
	}
	other, err := a.Store.CreateSiteAtDomain("Other", "other-analytics", "other.example", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	isolated, err := a.Store.analyticsReport(context.Background(), other, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(isolated["performance_pages"].(analyticsPerformancePages).Rows) != 0 {
		t.Fatal("route samples crossed site boundary")
	}
}

func TestAnalyticsRouteReportGroupAndVisitLimitsAreVisible(t *testing.T) {
	events := []AnalyticsEvent{}
	for i := 0; i < 101; i++ {
		events = append(events, AnalyticsEvent{Kind: "route-performance", Path: fmt.Sprintf("/%03d", i), RouteReadyMillis: routeMillis(float64(i))})
	}
	pages := analyticsPerformanceByPage(events, false)
	if !pages.Partial || len(pages.Rows) != 100 || pages.Rows[0].Path != "/000" || pages.Rows[99].Path != "/099" || pages.SampledVisits != 101 {
		t.Fatal(pages)
	}
	if v := analyticsPerformanceByPage(nil, true); !v.Partial || v.Rows == nil || len(v.Rows) != 0 {
		t.Fatal(v)
	}
	a, _, c := analyticsFixture(t, true)
	tx, err := a.Store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stamp := time.Now().Unix()
	for i := 0; i < 5001; i++ {
		v := AnalyticsEvent{ID: fmt.Sprintf("%032x", i+1), PageID: fmt.Sprintf("%032x", i+1), Visitor: strings.Repeat("a", 64), Session: strings.Repeat("b", 64), Kind: "route-performance", Path: "/many", RouteReadyMillis: routeMillis(float64(i)), PerformanceSeq: 1, Received: stamp}
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(`INSERT INTO analytics_events(site_id,id,received,visitor,session,kind,path,ip_hash,data) VALUES(?,?,?,?,?,?,?,?,?)`, c.SiteID, v.ID, stamp, v.Visitor, v.Session, v.Kind, v.Path, "own-fixture", string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	report, err := a.Store.analyticsReport(context.Background(), c.SiteID, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pages = report["performance_pages"].(analyticsPerformancePages)
	if !pages.Partial || pages.SampledVisits != 5000 || len(pages.Rows) != 1 || pages.Rows[0].Navigations != 5000 {
		t.Fatal(pages)
	}
	if report["overview"].(map[string]any)["pv"] != 0 {
		t.Fatal("performance-only rows invented pageviews")
	}
}
