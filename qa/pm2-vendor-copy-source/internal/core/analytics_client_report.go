package core

import "strings"

type analyticsClientAddressReport struct {
	UniqueAddresses  int                  `json:"unique_addresses"`
	KnownPageviews   int                  `json:"known_pageviews"`
	UnknownPageviews int                  `json:"unknown_pageviews"`
	LegacyPageviews  int                  `json:"legacy_pageviews"`
	Sources          []analyticsDimension `json:"sources"`
}

type analyticsClientAddresses struct {
	addresses              map[string]bool
	sources                map[string]int
	known, unknown, legacy int
}

func newAnalyticsClientAddresses() *analyticsClientAddresses {
	return &analyticsClientAddresses{addresses: map[string]bool{}, sources: map[string]int{}}
}

func (a *analyticsClientAddresses) Observe(v AnalyticsEvent) {
	source := v.ClientAddressSource
	switch source {
	case "direct", "managed_proxy":
		if len(v.ClientAddressHash) == 64 && strings.Trim(v.ClientAddressHash, "0123456789abcdef") == "" {
			a.addresses[v.ClientAddressHash] = true
			a.known++
			break
		}
		source = "invalid_record"
		a.unknown++
	case "unknown_proxy":
		a.unknown++
	case "":
		source = "legacy"
		a.legacy++
		a.unknown++
	default:
		source = "invalid_record"
		a.unknown++
	}
	a.sources[source]++
}

func (a *analyticsClientAddresses) Report() analyticsClientAddressReport {
	return analyticsClientAddressReport{UniqueAddresses: len(a.addresses), KnownPageviews: a.known, UnknownPageviews: a.unknown, LegacyPageviews: a.legacy, Sources: analyticsDimensions(a.sources)}
}
