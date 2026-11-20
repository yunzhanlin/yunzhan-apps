package core

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/geodata"
)

const AnalyticsGeographyRPC = "/v1/software/website-analytics/geography"

var analyticsGeographyRelease = regexp.MustCompile(`^20[2-9][0-9]-(0[1-9]|1[0-2])$`)

type AnalyticsGeography struct {
	Status  string `json:"status"`
	Country string `json:"country_code,omitempty"`
	Release string `json:"release,omitempty"`
}

func (g AnalyticsGeography) Valid() bool {
	switch g.Status {
	case "located":
		return len(g.Country) == 2 && g.Country != "ZZ" &&
			g.Country[0] >= 'A' && g.Country[0] <= 'Z' && g.Country[1] >= 'A' && g.Country[1] <= 'Z' &&
			analyticsGeographyRelease.MatchString(g.Release)
	case "non_public", "unverified", "unavailable", "not_found":
		return g.Country == "" && g.Release == ""
	default:
		return false
	}
}

func (s *Store) analyticsGeographyInstalled(ctx context.Context) bool {
	return s.analyticsHasReceipt(ctx, appcatalog.AnalyticsGeographyVersion, appcatalog.AnalyticsSessionActivityVersion)
}

func (a *Server) analyticsPageGeography(ctx context.Context, siteID, address string) *AnalyticsGeography {
	if !a.Store.analyticsGeographyInstalled(ctx) {
		return nil
	}
	if address == "" {
		return &AnalyticsGeography{Status: "unverified"}
	}
	if a.Executor == nil {
		return &AnalyticsGeography{Status: "unavailable"}
	}
	ctx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()
	var g AnalyticsGeography
	request := struct {
		SiteID  string `json:"site_id"`
		Address string `json:"address"`
	}{siteID, address}
	if err := a.Executor.Call(ctx, http.MethodPost, AnalyticsGeographyRPC, request, &g); err != nil || !g.Valid() {
		return &AnalyticsGeography{Status: "unavailable"}
	}
	return &g
}

type analyticsGeographyReport struct {
	countries map[string]int
	statuses  map[string]int
	releases  map[string]int
}

func (r *analyticsGeographyReport) observe(g *AnalyticsGeography) {
	if r.statuses == nil {
		r.countries = make(map[string]int)
		r.releases = make(map[string]int)
		r.statuses = make(map[string]int)
	}
	if g == nil || !g.Valid() {
		r.statuses["not_collected"]++
		return
	}
	r.statuses[g.Status]++
	if g.Status == "located" {
		r.countries[g.Country]++
		r.releases[g.Release]++
	}
}

func (r *analyticsGeographyReport) result(partial bool) map[string]any {
	result := map[string]any{
		"countries":     analyticsDimensions(r.countries),
		"statuses":      analyticsDimensions(r.statuses),
		"data_releases": analyticsDimensions(r.releases),
		"partial":       partial,
	}
	if len(r.releases) != 0 {
		result["attribution"] = geodata.Attribution
		result["attribution_url"] = geodata.AttributionURL
		result["license_url"] = geodata.LicenseURL
	}
	return result
}
