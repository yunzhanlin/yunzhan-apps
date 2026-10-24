package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

// These are synthetic aggregation fixtures, not native requests or proof of
// any IP's true location. Real provider bytes have a separate opt-in test.
type geoReportFixture struct{ calls int }

func (f *geoReportFixture) Lookup(ip string) geodata.Location {
	f.calls++
	if ip == "8.8.8.8" {
		return geodata.Location{Status: "located", CountryCode: "US", Country: "United States", Region: "California", City: "Test A"}
	}
	if ip == "1.1.1.1" {
		return geodata.Location{Status: "located", CountryCode: "AU", Country: "Australia", Region: "New South Wales", City: "Test B"}
	}
	if strings.HasPrefix(ip, "synthetic-") {
		return geodata.Location{Status: "located", CountryCode: "US", Country: "United States", City: ip}
	}
	if ip == "empty-city" {
		return geodata.Location{Status: "located", CountryCode: "US", Country: "United States"}
	}
	if ip == "bad-provider" {
		return geodata.Location{Status: "download_succeeded"}
	}
	return geodata.Location{Status: "non_public"}
}
func (*geoReportFixture) Metadata(time.Time) geodata.Metadata {
	return geodata.Metadata{Available: true, Release: "2026-10", BuildEpoch: 1790818881, ManifestSHA256: strings.Repeat("a", 64), SHA256: strings.Repeat("b", 64), Attribution: geodata.Attribution, AttributionURL: geodata.AttributionURL, License: geodata.LicenseURL}
}
func assertGeoPartition(t *testing.T, g analyticsGeoReport) {
	t.Helper()
	total := 0
	for _, count := range g.Counts {
		total += count
	}
	countries, cities := 0, 0
	for _, row := range g.Countries {
		countries += row.Requests
	}
	for _, row := range g.Cities {
		cities += row.Requests
	}
	if total != g.Requests || countries != g.Counts["located"] || cities+g.CityOtherRequests+g.CityUnknownRequests != countries {
		t.Fatalf("geography population mismatch: %+v", g)
	}
}
func TestAnalyticsGeographySharesAllFiltersAndNoImplicitEnable(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-10-05T10:00:30Z")
	input := strings.NewReplacer("192.0.2.1", "8.8.8.8", "192.0.2.2", "1.1.1.1").Replace(analyticsFixture())
	for _, in := range []core.AppModuleInput{{}, {OnlyBots: true}, {StatusCode: 503}, {Search: "/home"}, {FromTime: "2026-10-05T10:00:00Z"}, {ToTime: "2026-10-05T10:00:00Z"}, {MinSeconds: 10}, {Search: "no-match"}} {
		fixture := &geoReportFixture{}
		out, err := buildAnalyticsReport(context.Background(), strings.NewReader(input), "site", in, false, now, fixture)
		if err != nil {
			t.Fatal(err)
		}
		g := out["geography"].(analyticsGeoReport)
		if g.Requests != out["requests"] || g.PopulationPartial != out["partial"] || g.Lookups != fixture.calls {
			t.Fatal(in, g)
		}
		assertGeoPartition(t, g)
		raw, _ := json.Marshal(g)
		for _, private := range []string{"8.8.8.8", "1.1.1.1", "/home", "secret", "Examplebot"} {
			if strings.Contains(string(raw), private) {
				t.Fatal("geography aggregates leaked request identity", private)
			}
		}
	}
	out, err := buildAnalyticsReport(context.Background(), strings.NewReader(input), "site", core.AppModuleInput{}, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out["geography"]; ok {
		t.Fatal("old app implicitly enabled new data feature")
	}
}
func TestAnalyticsGeographyMissingDatasetDoesNotLosePopulation(t *testing.T) {
	a := newAnalyticsGeo(nil, time.Now())
	for _, ip := range []string{"8.8.8.8", "8.8.8.8", "127.0.0.1", "192.0.2.1", "", "not-an-ip"} {
		a.add(ip)
	}
	g := a.result(true)
	assertGeoPartition(t, g)
	if g.Counts["unavailable"] != 2 || g.Counts["non_public"] != 2 || g.Counts["missing_ip"] != 1 || g.Counts["invalid_ip"] != 1 || g.Metadata.Available || !g.PopulationPartial || len(g.Countries) != 0 {
		t.Fatal(g)
	}
	first := a.result(true)
	first.Counts["unavailable"] = 999
	if a.result(true).Counts["unavailable"] != 2 {
		t.Fatal("report aliases mutable accumulator")
	}
}
func TestAnalyticsGeographyBoundedCacheCityRanksAndExplicitOther(t *testing.T) {
	lookup := &geoReportFixture{}
	a := newAnalyticsGeo(lookup, time.Now())
	a.add("empty-city")
	a.add("bad-provider")
	for i := 0; i < analyticsGeoLookupLimit-2; i++ {
		a.add(fmt.Sprintf("synthetic-%04d", i))
	}
	for range 500 {
		a.add("synthetic-0000")
	}
	a.add("synthetic-over-budget")
	g := a.result(false)
	assertGeoPartition(t, g)
	if lookup.calls != analyticsGeoLookupLimit || len(a.cache) != analyticsGeoLookupLimit || len(a.cities) != analyticsGeoCityLimit || len(g.Cities) != analyticsGeoDisplayLimit || g.Counts["lookup_limited"] != 1 || g.Counts["lookup_error"] != 1 || g.CityUnknownRequests != 1 || g.Cities[0].City != "synthetic-0000" || g.Cities[0].Requests != 501 {
		t.Fatal("bounded ranks or cache changed", g)
	}
	if g.CityOtherRequests != analyticsGeoLookupLimit-2-analyticsGeoDisplayLimit {
		t.Fatal("hidden city rows missing from other", g.CityOtherRequests)
	}
	before := a.result(false)
	after := a.result(false)
	b, _ := json.Marshal(before)
	c, _ := json.Marshal(after)
	if string(b) != string(c) {
		t.Fatal("repeated report inflated other count")
	}
	if len(b) > 150<<10 {
		t.Fatal("geography report exceeded bounded response budget", len(b))
	}
}
