package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/geodata"
)

func TestAnalyticsGeographyUsesTrustedAddressAndPreservesOptOut(t *testing.T) {
	a, site, config := analyticsFixture(t, true)
	original := AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: "/first"}
	origin := "https://analytics.example"
	if reply := analyticsRequest(a, config, original, origin); reply.Code != http.StatusNoContent {
		t.Fatal(reply.Code, reply.Body.String())
	}
	if _, err := a.Store.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,target,version,sha256,updated_at)
		VALUES('website-analytics','website-analytics','website-analytics',?,?,?)`,
		appcatalog.AnalyticsGeographyVersion, strings.Repeat("a", 64), Now()); err != nil {
		t.Fatal(err)
	}
	setGeography := func(enabled bool) {
		t.Helper()
		site.Settings.AnalyticsGeography = enabled
		site.Settings.AnalyticsEndpoint = "127.0.0.1:19100"
		site.Settings.AnalyticsProxyIdentity = strings.Repeat("a", 64)
		raw, err := json.Marshal(site.Settings)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Store.DB.Exec(`UPDATE sites SET settings_json=? WHERE id=?`, string(raw), site.ID); err != nil {
			t.Fatal(err)
		}
	}
	setGeography(true)
	calls := 0
	disableDuringLookup := false
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var data map[string]string
		if r.URL.Path != AnalyticsGeographyRPC || r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&data) != nil ||
			!reflect.DeepEqual(data, map[string]string{"site_id": site.ID, "address": "192.0.2.8"}) {
			t.Fatal("unexpected geography request", r.URL.Path, data)
		}
		if disableDuringLookup {
			setGeography(false)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(
			`{"status":"located","country_code":"JP","release":"2026-10"}`))}, nil
	})}}
	for i := 0; i < 3; i++ {
		v := original
		v.ID, v.PageID = ID(), ID()
		v.Geography = &AnalyticsGeography{Status: "located", Country: "GB", Release: "2026-09"}
		if i == 1 {
			disableDuringLookup = true
		}
		if reply := analyticsRequest(a, config, v, origin); reply.Code != http.StatusNoContent {
			t.Fatal(reply.Code, reply.Body.String())
		}
		var stored string
		if err := a.Store.DB.QueryRow(`SELECT data FROM analytics_events WHERE site_id=? AND id=?`, site.ID, v.ID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(stored, "192.0.2.8") || strings.Contains(stored, `"GB"`) ||
			(strings.Contains(stored, `"country_code":"JP"`) != (i == 0)) {
			t.Fatal("untrusted geography or late opt-out reached persistent data", stored)
		}
	}
	if calls != 2 {
		t.Fatal("disabled site contacted lookup worker", calls)
	}
	now := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	report, err := a.Store.analyticsReport(context.Background(), site.ID, now.Add(-time.Hour).Format(time.RFC3339), now.Format(time.RFC3339), now)
	if err != nil {
		t.Fatal(err)
	}
	geo := report["geography"].(map[string]any)
	if !reflect.DeepEqual(geo["countries"], []analyticsDimension{{"JP", 1}}) ||
		!reflect.DeepEqual(geo["statuses"], []analyticsDimension{{"not_collected", 3}, {"located", 1}}) ||
		!reflect.DeepEqual(geo["data_releases"], []analyticsDimension{{"2026-10", 1}}) ||
		geo["attribution_url"] != geodata.AttributionURL {
		t.Fatal("old events or countries changed in the original report", geo)
	}
}
