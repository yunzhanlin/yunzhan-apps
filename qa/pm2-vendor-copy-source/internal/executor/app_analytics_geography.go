package executor

import (
	"local/panel/internal/geodata"
	"sort"
	"time"
)

const analyticsGeoLookupLimit = 5000
const analyticsGeoCityLimit = 1000
const analyticsGeoDisplayLimit = 100

type analyticsGeoLookup interface {
	Lookup(string) geodata.Location
	Metadata(time.Time) geodata.Metadata
}
type analyticsGeoRank struct {
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
	Requests    int    `json:"requests"`
}
type analyticsGeoReport struct {
	Format              int                `json:"format"`
	Method              string             `json:"method"`
	Metadata            geodata.Metadata   `json:"metadata"`
	Requests            int                `json:"requests"`
	Counts              map[string]int     `json:"counts"`
	Countries           []analyticsGeoRank `json:"countries"`
	Cities              []analyticsGeoRank `json:"cities"`
	CityUnknownRequests int                `json:"city_unknown_requests"`
	CityOtherRequests   int                `json:"city_other_requests"`
	Lookups             int                `json:"lookups"`
	LookupLimit         int                `json:"lookup_limit"`
	PopulationPartial   bool               `json:"population_partial"`
}
type analyticsGeoKey struct{ country, region, city string }
type analyticsGeoAccumulator struct {
	lookup    analyticsGeoLookup
	cache     map[string]geodata.Location
	countries map[string]*analyticsGeoRank
	cities    map[analyticsGeoKey]*analyticsGeoRank
	report    analyticsGeoReport
}

func newAnalyticsGeo(lookup analyticsGeoLookup, now time.Time) *analyticsGeoAccumulator {
	var metadata geodata.Metadata
	if lookup != nil {
		metadata = lookup.Metadata(now)
	}
	return &analyticsGeoAccumulator{lookup: lookup, cache: map[string]geodata.Location{}, countries: map[string]*analyticsGeoRank{}, cities: map[analyticsGeoKey]*analyticsGeoRank{}, report: analyticsGeoReport{Format: 1, Method: "offline_ip_network", Metadata: metadata, Counts: map[string]int{"located": 0, "non_public": 0, "missing_ip": 0, "invalid_ip": 0, "unavailable": 0, "not_found": 0, "lookup_error": 0, "lookup_limited": 0}, Countries: []analyticsGeoRank{}, Cities: []analyticsGeoRank{}, LookupLimit: analyticsGeoLookupLimit}}
}
func (a *analyticsGeoAccumulator) add(ip string) {
	a.report.Requests++
	if ip == "" {
		a.report.Counts["missing_ip"]++
		return
	}
	location, ok := a.cache[ip]
	if !ok {
		if len(a.cache) >= analyticsGeoLookupLimit {
			a.report.Counts["lookup_limited"]++
			return
		}
		if a.lookup == nil {
			var absent *geodata.Snapshot
			location = absent.Lookup(ip)
		} else {
			location = a.lookup.Lookup(ip)
		}
		a.report.Lookups++
		a.cache[ip] = location
	}
	if _, ok := a.report.Counts[location.Status]; !ok || location.Status == "located" && (len(location.CountryCode) != 2 || location.CountryCode[0] < 'A' || location.CountryCode[0] > 'Z' || location.CountryCode[1] < 'A' || location.CountryCode[1] > 'Z') {
		location = geodata.Location{Status: "lookup_error"}
	}
	a.report.Counts[location.Status]++
	if location.Status != "located" {
		return
	}
	country := a.countries[location.CountryCode]
	if country == nil {
		country = &analyticsGeoRank{CountryCode: location.CountryCode, Country: location.Country}
		a.countries[location.CountryCode] = country
	}
	country.Requests++
	if location.City == "" {
		a.report.CityUnknownRequests++
		return
	}
	key := analyticsGeoKey{location.CountryCode, location.Region, location.City}
	city := a.cities[key]
	if city == nil {
		if len(a.cities) >= analyticsGeoCityLimit {
			a.report.CityOtherRequests++
			return
		}
		city = &analyticsGeoRank{CountryCode: location.CountryCode, Country: location.Country, Region: location.Region, City: location.City}
		a.cities[key] = city
	}
	city.Requests++
}
func geoRankLess(a, b analyticsGeoRank) bool {
	if a.Requests != b.Requests {
		return a.Requests > b.Requests
	}
	if a.CountryCode != b.CountryCode {
		return a.CountryCode < b.CountryCode
	}
	if a.Region != b.Region {
		return a.Region < b.Region
	}
	return a.City < b.City
}
func (a *analyticsGeoAccumulator) result(partial bool) analyticsGeoReport {
	// Detached results: repeated serialization never mutates the accumulator.
	out := a.report
	out.Counts = map[string]int{}
	for key, count := range a.report.Counts {
		out.Counts[key] = count
	}
	out.Countries = make([]analyticsGeoRank, 0, len(a.countries))
	out.Cities = make([]analyticsGeoRank, 0, min(len(a.cities), analyticsGeoDisplayLimit))
	for _, row := range a.countries {
		out.Countries = append(out.Countries, *row)
	}
	all := make([]analyticsGeoRank, 0, len(a.cities))
	for _, row := range a.cities {
		all = append(all, *row)
	}
	sort.Slice(out.Countries, func(i, j int) bool { return geoRankLess(out.Countries[i], out.Countries[j]) })
	sort.Slice(all, func(i, j int) bool { return geoRankLess(all[i], all[j]) })
	for i, row := range all {
		if i < analyticsGeoDisplayLimit {
			out.Cities = append(out.Cities, row)
		} else {
			out.CityOtherRequests += row.Requests
		}
	}
	out.PopulationPartial = partial
	return out
}
