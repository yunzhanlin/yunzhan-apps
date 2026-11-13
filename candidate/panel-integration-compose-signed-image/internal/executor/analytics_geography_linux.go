//go:build linux

package executor

import (
	"net/http"
	"net/netip"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

func (s *Service) analyticsGeographyRoutes(m *http.ServeMux) {
	m.HandleFunc("POST "+core.AnalyticsGeographyRPC, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			SiteID  string `json:"site_id"`
			Address string `json:"address"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		address, err := netip.ParseAddr(in.Address)
		if r.URL.RawQuery != "" || !core.ValidID(in.SiteID) || err != nil ||
			address.Zone() != "" || address.Is4In6() || address.String() != in.Address {
			respond(w, http.StatusBadRequest, map[string]string{"error": "地理查找的网站或客户端地址无效"})
			return
		}
		record, err := s.moduleInstalledRecord("website-analytics")
		version, _ := record["version"].(string)
		if err != nil || !appcatalog.AnalyticsVersionSupportsGeography(version) {
			respond(w, http.StatusConflict, map[string]string{"error": "网站分析地理分布未安装"})
			return
		}
		respond(w, http.StatusOK, s.analyticsCountry(in.Address))
	})
}

func (s *Service) analyticsCountry(address string) core.AnalyticsGeography {
	lookup, release, _, _ := s.statisticsGeoSnapshotLease()
	defer release()

	var location geodata.Location
	if lookup == nil {
		var unavailable *geodata.Snapshot
		location = unavailable.Lookup(address)
	} else {
		location = lookup.Lookup(address)
	}
	switch location.Status {
	case "non_public", "not_found":
		return core.AnalyticsGeography{Status: location.Status}
	case "located":
		metadata := lookup.Metadata(time.Now())
		if metadata.Available {
			result := core.AnalyticsGeography{Status: "located", Country: location.CountryCode, Release: metadata.Release}
			if result.Valid() {
				return result
			}
		}
	}
	return core.AnalyticsGeography{Status: "unavailable"}
}
