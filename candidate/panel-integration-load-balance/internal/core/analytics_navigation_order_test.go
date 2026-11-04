package core

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestAnalyticsNavigationSequenceBoundsAndPassiveSeparation(t *testing.T) {
	base := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: "/"}
	for _, n := range []int64{0, 1, analyticsNavigationSequenceLimit} {
		v := base
		v.NavigationSeq = n
		if err := validateAnalyticsEvent(&v, false); err != nil || v.NavigationSeq != n {
			t.Fatal(n, v, err)
		}
	}
	for _, n := range []int64{-1, analyticsNavigationSequenceLimit + 1} {
		v := base
		v.NavigationSeq = n
		if err := validateAnalyticsEvent(&v, false); err == nil {
			t.Fatal("invalid navigation sequence accepted", n)
		}
	}
	for _, kind := range []string{"performance", "route-performance", "click", "engagement"} {
		v := base
		v.Kind, v.NavigationSeq = kind, 42
		if kind == "route-performance" {
			v.RouteReadyMillis, v.PerformanceSeq = routeMillis(10), 1
		}
		if err := validateAnalyticsEvent(&v, true); err != nil || v.NavigationSeq != 0 {
			t.Fatal("passive/interaction event claimed a new navigation", v, err)
		}
	}
	for _, value := range []string{"1.25", "1000000000000000000000000", `"1"`} {
		var v AnalyticsEvent
		if json.Unmarshal([]byte(`{"navigation_seq":`+value+`}`), &v) == nil {
			t.Fatal("non-integer or overflowing sequence decoded", value)
		}
	}
}

func TestAnalyticsNavigationOrderingConflictLegacyAndScope(t *testing.T) {
	visitor, session := ID(), ID()
	first := AnalyticsEvent{Kind: "pageview", Visitor: visitor, Session: session, PageID: ID(), Path: "/first", NavigationSeq: 1, Received: 10}
	second := AnalyticsEvent{Kind: "pageview", Visitor: visitor, Session: session, PageID: ID(), Path: "/second", NavigationSeq: 2, Received: 10}
	arrival := []AnalyticsEvent{second, first}
	unchanged := append([]AnalyticsEvent(nil), arrival...)
	ordered := analyticsOrderedPageviews(arrival)
	if ordered.Uncertain || !ordered.ReceivedOrdered || ordered.Source != "browser-navigation-sequence" || ordered.Events[0].Path != "/first" || !reflect.DeepEqual(arrival, unchanged) {
		t.Fatal(ordered, arrival)
	}
	for _, tc := range []struct {
		name string
		edit func(*AnalyticsEvent)
	}{
		{"legacy", func(v *AnalyticsEvent) { v.NavigationSeq = 0 }},
		{"negative", func(v *AnalyticsEvent) { v.NavigationSeq = -1 }},
		{"overflow", func(v *AnalyticsEvent) { v.NavigationSeq = analyticsNavigationSequenceLimit + 1 }},
		{"duplicate-sequence", func(v *AnalyticsEvent) { v.NavigationSeq = first.NavigationSeq }},
		{"page-reused-with-new-sequence", func(v *AnalyticsEvent) { v.PageID = first.PageID }},
		{"another-visitor", func(v *AnalyticsEvent) { v.Visitor = ID() }},
		{"another-session", func(v *AnalyticsEvent) { v.Session = ID() }},
		{"invalid-page", func(v *AnalyticsEvent) { v.PageID = "" }},
		{"passive-event", func(v *AnalyticsEvent) { v.Kind = "performance" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := second
			tc.edit(&v)
			raw := []AnalyticsEvent{v, first}
			out := analyticsOrderedPageviews(raw)
			if !out.Uncertain || out.Source != "server-receive-order" || !reflect.DeepEqual(out.Events, raw) {
				t.Fatal("uncertain input silently reordered", out)
			}
		})
	}
	late := first
	late.Received = 12
	ordered = analyticsOrderedPageviews([]AnalyticsEvent{second, late})
	if ordered.Uncertain || ordered.ReceivedOrdered || ordered.Events[0].Path != "/first" {
		t.Fatal("browser order fabricated a monotonic server clock", ordered)
	}
}

func TestAnalyticsNavigationSameSecondRealSQLReportAndFunnel(t *testing.T) {
	a, _, config := analyticsFixture(t, true)
	visitor, session := ID(), ID()
	stamp := time.Now().Unix() - 2
	paths := []string{"/qa/start", "/c59-ready", "/c59-stale", "/c59-current"}
	pages := []string{ID(), ID(), ID(), ID()}
	// Exact installed-browser failure: current reaches Nginx/Core before stale.
	for _, index := range []int{0, 1, 3, 2} {
		v := AnalyticsEvent{ID: ID(), PageID: pages[index], Visitor: visitor, Session: session, Kind: "pageview", Path: paths[index], NavigationSeq: int64(index + 1), Received: stamp}
		if err := a.Store.storeAnalyticsEvent(context.Background(), config.SiteID, 30, v); err != nil {
			t.Fatal(err)
		}
	}
	passive := AnalyticsEvent{ID: ID(), PageID: pages[0], Visitor: visitor, Session: session, Kind: "performance", Path: paths[0], Received: stamp + 1, INP: 248, INPAvailable: true, PerformanceSeq: 2}
	if err := a.Store.storeAnalyticsEvent(context.Background(), config.SiteID, 30, passive); err != nil {
		t.Fatal(err)
	}
	readOriginal := func() []string {
		t.Helper()
		rows, err := a.Store.DB.Query(`SELECT data FROM analytics_events WHERE site_id=? ORDER BY rowid`, config.SiteID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			out = append(out, raw)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := readOriginal()
	report, err := a.Store.analyticsReport(context.Background(), config.SiteID, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sessions := report["sessions"].([]*analyticsSession)
	counts := report["overview"].(map[string]any)
	if len(sessions) != 1 || !reflect.DeepEqual(sessions[0].Journey, paths) || sessions[0].Exit != "/c59-current" || sessions[0].Entry != "/qa/start" || sessions[0].PageOrderUncertain || sessions[0].PageOrderSource != "browser-navigation-sequence" || sessions[0].Last != stamp || counts["pv"] != 4 || counts["sessions"] != 1 || report["ordering_uncertain_sessions"] != 0 {
		t.Fatal(sessions, counts, report["ordering_uncertain_sessions"])
	}
	funnel, err := a.Store.analyticsFunnelReport(context.Background(), config.SiteID, []string{"/qa/start", "/c59-stale", "/c59-current"}, "", "", 30, time.Now())
	if err != nil || funnel.CompletedSessions != 1 || funnel.OrderingUncertainSessions != 0 || funnel.UniquePageviews != 4 {
		t.Fatal("same-second legitimate conversion lost to arrival order", funnel, err)
	}
	if !reflect.DeepEqual(before, readOriginal()) {
		t.Fatal("report rewrote original historical evidence")
	}
}

func TestAnalyticsNavigationLegacyAndDelayedFunnelDisclosesUncertainty(t *testing.T) {
	a, _, config := analyticsFixture(t, true)
	stamp := time.Now().Unix() - 10
	add := func(visitor, session, path string, sequence, received int64) {
		t.Helper()
		v := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: visitor, Session: session, Kind: "pageview", Path: path, NavigationSeq: sequence, Received: received}
		if err := a.Store.storeAnalyticsEvent(context.Background(), config.SiteID, 30, v); err != nil {
			t.Fatal(err)
		}
	}
	visitor, legacy := ID(), ID()
	add(visitor, legacy, "/entry", 0, stamp)
	add(visitor, legacy, "/done", 0, stamp+1)
	visitor, delayed := ID(), ID()
	add(visitor, delayed, "/done", 2, stamp+2)
	add(visitor, delayed, "/entry", 1, stamp+3)
	visitor, ordinary := ID(), ID()
	add(visitor, ordinary, "/entry", 1, stamp+4)
	add(visitor, ordinary, "/done", 2, stamp+5)
	funnel, err := a.Store.analyticsFunnelReport(context.Background(), config.SiteID, []string{"/entry", "/done"}, "", "", 30, time.Now())
	if err != nil || funnel.Partial || funnel.CompletedSessions != 2 || funnel.OrderingUncertainSessions != 2 || funnel.Duration["average"] != 1 {
		t.Fatal("uncertain receipt timing was hidden or fabricated", funnel, err)
	}
	report, err := a.Store.analyticsReport(context.Background(), config.SiteID, "", "", time.Now())
	if err != nil || report["ordering_uncertain_sessions"] != 1 {
		t.Fatal(report, err)
	}
	for _, session := range report["sessions"].([]*analyticsSession) {
		switch session.ID {
		case legacy:
			if !session.PageOrderUncertain || session.PageOrderSource != "server-receive-order" || session.Exit != "/done" {
				t.Fatal("legacy record was assigned invented sequence metadata", session)
			}
		case delayed:
			if session.PageOrderUncertain || session.PageOrderSource != "browser-navigation-sequence" || !reflect.DeepEqual(session.Journey, []string{"/entry", "/done"}) || session.First != stamp+2 || session.Last != stamp+3 {
				t.Fatal("browser order changed server receipt timestamps", session)
			}
		}
	}
}
