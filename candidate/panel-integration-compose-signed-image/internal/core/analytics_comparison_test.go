package core

import (
	"context"
	"testing"
	"time"
)

func TestAnalyticsComparisonUsesAdjacentSiteScopedPeriods(t *testing.T) {
	a, site, config := analyticsFixture(t, true)
	if _, err := a.Store.CreateSiteAtDomain("Other analytics", "other-analytics", "other.example", "", "admin"); err != nil {
		t.Fatal(err)
	}
	var otherID string
	if err := a.Store.DB.QueryRow("SELECT id FROM sites WHERE domain='other.example'").Scan(&otherID); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	from := now.Add(-time.Hour)
	previous := from.Add(-time.Hour)
	insert := func(id, kind, visitor, session string, at time.Time) {
		t.Helper()
		if _, err := a.Store.DB.Exec("INSERT INTO analytics_events VALUES(?,?,?,?,?,?,?,?,?)",
			id, ID(), at.Unix(), visitor, session, kind, "/", "private-peer", "{}"); err != nil {
			t.Fatal(err)
		}
	}
	visitor, visit := ID(), ID()
	insert(site.ID, "pageview", visitor, visit, previous)
	insert(site.ID, "pageview", visitor, visit, from.Add(-time.Second))
	insert(site.ID, "pageview", visitor, visit, from)
	insert(site.ID, "pageview", ID(), ID(), from.Add(time.Second))
	insert(site.ID, "click", ID(), ID(), now.Add(-time.Second))
	insert(site.ID, "performance", ID(), ID(), now.Add(-time.Second))
	insert(site.ID, "pageview", ID(), ID(), now)
	insert(site.ID, "pageview", ID(), ID(), previous.Add(-time.Second))
	insert(otherID, "pageview", ID(), ID(), from)

	got, err := a.Store.analyticsCompare(context.Background(), site.ID, from.Format(time.RFC3339), now.Format(time.RFC3339), now)
	if err != nil {
		t.Fatal(err)
	}
	wantPrevious := analyticsComparisonPeriod{From: previous, To: from, PV: 2, UV: 1, Visits: 1}
	wantCurrent := analyticsComparisonPeriod{From: from, To: now, PV: 2, UV: 2, Visits: 2, Clicks: 1}
	if got.Previous != wantPrevious || got.Current != wantCurrent || !got.WithinRetention {
		t.Fatalf("wrong equal-window results: %+v", got)
	}
	empty, err := a.Store.analyticsCompare(context.Background(), otherID, from.Format(time.RFC3339), now.Format(time.RFC3339), now)
	if err != nil || empty.Current.PV != 1 || empty.Previous.PV != 0 || empty.Previous.Visits != 0 {
		t.Fatalf("empty site period was populated from other data: %+v, %v", empty, err)
	}
	config.Retention = 1
	if _, err := a.Store.saveAnalyticsConfig(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	outside, err := a.Store.analyticsCompare(context.Background(), site.ID, now.Add(-13*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339), now)
	if err != nil || outside.WithinRetention || outside.RetentionDays != 1 {
		t.Fatalf("comparison over unretained history was treated as complete: %+v, %v", outside, err)
	}
	for _, bad := range []struct{ start, end string }{
		{"", now.Format(time.RFC3339)},
		{from.Format(time.RFC3339), now.Add(2 * time.Second).Format(time.RFC3339)},
		{from.Add(time.Millisecond).Format(time.RFC3339Nano), now.Format(time.RFC3339)},
		{now.Add(-32 * 24 * time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)},
	} {
		if _, err := a.Store.analyticsCompare(context.Background(), site.ID, bad.start, bad.end, now); err == nil {
			t.Errorf("invalid range admitted: %+v", bad)
		}
	}
}
