package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// These are private fixture timestamps, not an actual hour-long installed run.
// A passive document flush is valid performance data, not a resumed journey.
func TestAnalyticsSessionReportDoesNotExtendJourneysOrActiveVisitorsFromPassivePerformance(t *testing.T) {
	a, _, config := analyticsFixture(t, true)
	now := time.Now()
	visitor, oldSession, newSession, originalPage := ID(), ID(), ID(), ID()
	oldAt, currentAt := now.Add(-time.Hour).Unix(), now.Add(-30*time.Second).Unix()
	for _, item := range []struct {
		event AnalyticsEvent
		at    int64
	}{
		{AnalyticsEvent{ID: ID(), PageID: originalPage, Visitor: visitor, Session: oldSession, Kind: "pageview", Path: "/old"}, oldAt},
		{AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: visitor, Session: newSession, Kind: "pageview", Path: "/resumed"}, currentAt},
		{AnalyticsEvent{ID: ID(), PageID: originalPage, Visitor: visitor, Session: oldSession, Kind: "performance", Path: "/old", INP: 80, INPAvailable: true, PerformanceSeq: 2}, now.Unix()},
		{AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "performance", Path: "/passive-only", INP: 120, INPAvailable: true, PerformanceSeq: 2}, now.Unix()},
	} {
		if response := analyticsRequest(a, config, item.event, "https://analytics.example"); response.Code != 204 {
			t.Fatal("actual collection fixture rejected", response.Code)
		}
		var raw string
		if err := a.Store.DB.QueryRow(`SELECT data FROM analytics_events WHERE site_id=? AND id=?`, config.SiteID, item.event.ID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var stored AnalyticsEvent
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			t.Fatal(err)
		}
		stored.Received = item.at
		encoded, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Store.DB.Exec(`UPDATE analytics_events SET received=?,data=? WHERE site_id=? AND id=?`, item.at, string(encoded), config.SiteID, item.event.ID); err != nil {
			t.Fatal(err)
		}
	}
	report, err := a.Store.analyticsReport(context.Background(), config.SiteID, "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	overview := report["overview"].(map[string]any)
	if overview["active_visitors"] != 1 || overview["sessions"] != 2 || overview["pv"] != 2 {
		t.Fatal("passive beacons invented active visitors or visits", overview)
	}
	for _, session := range report["sessions"].([]*analyticsSession) {
		if session.Entry == "/old" && session.Last != oldAt {
			t.Fatal("original ended session extended by performance", session)
		}
		if session.Entry == "/resumed" && session.Last != currentAt {
			t.Fatal("new visit lost its actual activity time", session)
		}
	}
	inp := report["performance"].(map[string]any)["inp"].(map[string]any)
	if inp["samples"] != 2 || inp["p75"] != float64(120) {
		t.Fatal("legitimate document performance was dropped instead of separately aggregated", inp)
	}
}

func TestAnalyticsSessionPatchPreservesOnlyExactKnownHTMLVersions(t *testing.T) {
	for _, version := range []string{"2.3.0", AnalyticsSessionAppVersion} {
		if !AnalyticsHTMLAppVersionSupported(version) {
			t.Fatal("existing explicit HTML behavior lost", version)
		}
		if err := ValidateSoftwareUpdate("website-analytics", version); err != nil {
			t.Fatal("known signed application version refused", version, err)
		}
	}
	for _, version := range []string{"", "2.2.0", "2.3", "02.3.1", "2.3.1-compat1", "2.3.1+build", "2.3.2", "2.4.0", "../2.3.1"} {
		if AnalyticsHTMLAppVersionSupported(version) {
			t.Fatal("unknown application version silently enabled HTML", version)
		}
	}
	for _, version := range []string{"", "02.3.1", "2.3.1-compat1", "2.3.1+build", "2.3.2", "2.4.0", "../2.3.1"} {
		if ValidateSoftwareUpdate("website-analytics", version) == nil {
			t.Fatal("direct update path accepted unreviewed session revision", version)
		}
	}
	for _, item := range moduleSoftwareCatalog() {
		if item.ID == "website-analytics" {
			if item.Version != AnalyticsSessionAppVersion {
				t.Fatal("application update metadata did not advance with actual handler")
			}
			return
		}
	}
	t.Fatal("website analytics missing from actual catalog")
}
