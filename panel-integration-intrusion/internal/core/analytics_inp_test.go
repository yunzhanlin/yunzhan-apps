package core

import (
	"context"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnalyticsINPNumericBoundsAndUnknown(t *testing.T) {
	base := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "performance", Path: "/", INP: 0, INPAvailable: true, PerformanceSeq: 240}
	if err := validateAnalyticsEvent(&base, false); err != nil || !base.INPAvailable || base.INP != 0 {
		t.Fatal(base, err)
	}
	for _, value := range []float64{-1, 300001, math.NaN(), math.Inf(1)} {
		v := base
		v.INP = value
		if validateAnalyticsEvent(&v, false) == nil {
			t.Fatal("unsafe INP", value)
		}
	}
	for _, value := range []int{-1, 241} {
		v := base
		v.PerformanceSeq = value
		if validateAnalyticsEvent(&v, false) == nil {
			t.Fatal("unsafe sequence", value)
		}
	}
	unknown := base
	unknown.INP = 500
	unknown.INPAvailable = false
	if err := validateAnalyticsEvent(&unknown, false); err != nil || unknown.INP != 0 {
		t.Fatal(unknown, err)
	}
	page := base
	page.Kind = "pageview"
	page.INP = 500
	if err := validateAnalyticsEvent(&page, false); err != nil || page.INP != 0 || page.INPAvailable || page.PerformanceSeq != 0 {
		t.Fatal(page, err)
	}
}

func TestAnalyticsINPFinalSequenceDeduplicationAndNoInventedZero(t *testing.T) {
	a, _, c := analyticsFixture(t, true)
	visitor, session, page := ID(), ID(), ID()
	// A long-visit INP outlier can be removed: the final score is smaller. The
	// earlier request intentionally reaches the server after the final beacon.
	for _, v := range []AnalyticsEvent{
		{ID: ID(), PageID: page, Visitor: visitor, Session: session, Kind: "performance", Path: "/", INP: 200, INPAvailable: true, PerformanceSeq: 8},
		{ID: ID(), PageID: page, Visitor: visitor, Session: session, Kind: "performance", Path: "/", INP: 800, INPAvailable: true, PerformanceSeq: 3},
		{ID: ID(), PageID: ID(), Visitor: visitor, Session: session, Kind: "performance", Path: "/", INPAvailable: false, PerformanceSeq: 9},
		{ID: ID(), PageID: ID(), Visitor: visitor, Session: session, Kind: "performance", Path: "/", INPAvailable: true, INP: 0, PerformanceSeq: 9},
	} {
		if w := analyticsRequest(a, c, v, "https://analytics.example"); w.Code != 204 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	report, err := a.Store.analyticsReport(context.Background(), c.SiteID, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inp := report["performance"].(map[string]any)["inp"].(map[string]any)
	if inp["samples"] != 2 || inp["p75"] != float64(200) {
		t.Fatal(inp)
	}
}

func TestAnalyticsTrackerBundlesPinnedLibraryAndCompleteLicense(t *testing.T) {
	a, _, c := analyticsFixture(t, true)
	request := httptest.NewRequest("GET", "/collect/analytics/tracker.js?site="+c.SiteID+"&key="+c.Key, nil)
	result := httptest.NewRecorder()
	a.ServeHTTP(result, request)
	body := result.Body.String()
	if result.Code != 200 || !strings.Contains(body, analyticsWebVitals) || !strings.Contains(body, analyticsWebVitalsLicense) || !strings.Contains(body, "Copyright 2020 Google LLC") {
		t.Fatal("missing pinned local code or complete license", result.Code)
	}
	privacy := strings.Index(body, "navigator.doNotTrack")
	library := strings.Index(body, "var webVitals=")
	if privacy < 0 || library < privacy || strings.Contains(body, "https://unpkg.com") {
		t.Fatal("privacy guard or first-party library scope")
	}
}
