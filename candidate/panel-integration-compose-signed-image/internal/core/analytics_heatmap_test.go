package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnalyticsHeatmapGroupsPreserveLegacyAndRequireSignedReceipt(t *testing.T) {
	a, _, cfg := analyticsFixture(t, true)
	tracker := func() string {
		req := httptest.NewRequest("GET", "/collect/analytics/tracker.js?site="+cfg.SiteID+"&key="+cfg.Key, nil)
		out := httptest.NewRecorder()
		a.ServeHTTP(out, req)
		if out.Code != http.StatusOK {
			t.Fatal(out.Code)
		}
		return out.Body.String()
	}
	if !strings.Contains(tracker(), `"clickViewport":false`) {
		t.Fatal("unsigned tracker enabled layout capture")
	}
	submit := func(kind, viewport string, expected int) {
		t.Helper()
		event := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: kind,
			Path: "/products", X: 10, Y: 25, ClickViewport: viewport}
		if out := analyticsRequest(a, cfg, event, "https://analytics.example"); out.Code != expected {
			t.Fatal(out.Code, out.Body.String())
		}
	}
	submit("click", "wide", http.StatusNoContent)
	if _, err := a.Store.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,target,version,sha256,updated_at)
		VALUES('website-analytics','website-analytics','website-analytics',?,?,?)`,
		AnalyticsLayoutHeatmapAppVersion, strings.Repeat("a", 64), Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tracker(), `"clickViewport":true`) {
		t.Fatal("the exact signed install did not enable layout capture")
	}
	submit("click", "", http.StatusNoContent)
	submit("click", "wide", http.StatusNoContent)
	submit("click", "narrow", http.StatusNoContent)
	submit("click", "narrow", http.StatusNoContent)
	submit("click", "390", http.StatusBadRequest)
	submit("pageview", "wide", http.StatusBadRequest)
	now := time.Now().Add(time.Second)
	from := now.Add(-time.Hour).UTC().Format(time.RFC3339)
	to := now.UTC().Format(time.RFC3339)
	report, err := a.Store.analyticsReport(context.Background(), cfg.SiteID, from, to, now)
	if err != nil {
		t.Fatal(err)
	}
	points := report["heatmap"].([]*analyticsHeatPoint)
	layouts := report["heatmap_layouts"].(map[string]any)
	cells := layouts["points"].([]analyticsHeatLayoutPoint)
	if len(points) != 1 || points[0].Count != 5 || layouts["partial"] != false || len(cells) != 3 {
		t.Fatal(points, layouts)
	}
	for i, want := range []struct {
		viewport string
		count    int
	}{{"narrow", 2}, {"unknown", 2}, {"wide", 1}} {
		cell := cells[i]
		if cell.Viewport != want.viewport || cell.Count != want.count || cell.Path != "/products" || cell.X != 10 || cell.Y != 25 {
			t.Fatal(i, cell)
		}
	}
}

func TestAnalyticsHeatmapBoundsExtraResponseWithoutDroppingExistingCells(t *testing.T) {
	var layouts analyticsHeatLayouts
	first := AnalyticsEvent{Path: "/retained", ClickViewport: "narrow"}
	layouts.observe(first, 10, 20)
	long := AnalyticsEvent{Path: "/" + strings.Repeat("x", 2047), ClickViewport: "wide"}
	for i := 0; i < 400; i++ {
		layouts.observe(long, i%20*5, i/20*5)
	}
	layouts.observe(first, 10, 20)
	report := layouts.report(false)
	if report["partial"] != true || layouts.bytes > 1<<20 {
		t.Fatal("layout report exceeded its byte bound")
	}
	cells := report["points"].([]analyticsHeatLayoutPoint)
	if len(cells) < 2 || cells[0].Path != first.Path || cells[0].Count != 2 {
		t.Fatal("existing cells must continue to count after the bound is reached")
	}
}
