package core

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func analyticsClientFixture(t *testing.T) (*Server, Site, AnalyticsConfig, string) {
	t.Helper()
	a, site, cfg := analyticsFixture(t, true)
	site.Settings = DefaultSiteSettings(site.Settings)
	site.Settings.AnalyticsEndpoint = a.Config.Listen
	var err error
	site.Settings.AnalyticsProxyIdentity, err = AnalyticsProxyIdentity(a.accountSecretKey, site.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(site.Settings)
	if _, err := a.Store.DB.Exec(`UPDATE sites SET settings_json=? WHERE id=?`, string(raw), site.ID); err != nil {
		t.Fatal(err)
	}
	token, err := AnalyticsProxyToken(a.accountSecretKey, site.ID)
	if err != nil {
		t.Fatal(err)
	}
	return a, site, cfg, token
}

func analyticsClientRequest(a *Server, cfg AnalyticsConfig, peer string, event AnalyticsEvent, headers map[string][]string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(event)
	r := httptest.NewRequest("POST", "/collect/analytics/event?site="+cfg.SiteID+"&key="+cfg.Key, strings.NewReader(string(raw)))
	r.RemoteAddr = peer
	r.Header.Set("Origin", "https://analytics.example")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/123.0")
	for name, values := range headers {
		for _, value := range values {
			r.Header.Add(name, value)
		}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func analyticsClientEvent() AnalyticsEvent {
	return AnalyticsEvent{ID: ID(), PageID: ID(), Visitor: ID(), Session: ID(), Kind: "pageview", Path: "/owned-fixture"}
}

func TestAnalyticsManagedClientAddressesStaySeparateAndPrivate(t *testing.T) {
	a, _, cfg, token := analyticsClientFixture(t)
	for _, address := range []string{"192.0.2.21", "2001:db8::22"} {
		event := analyticsClientEvent()
		event.ClientAddressHash = strings.Repeat("b", 64)
		event.ClientAddressSource = "direct"
		w := analyticsClientRequest(a, cfg, "127.0.0.1:54321", event, map[string][]string{
			AnalyticsProxyTokenHeader: {token}, AnalyticsProxyClientHeader: {address},
			"X-Forwarded-For": {"203.0.113.200"}, "X-Real-IP": {"203.0.113.201"},
		})
		if w.Code != 204 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	rows, err := a.Store.DB.Query(`SELECT data,ip_hash FROM analytics_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	addresses, peers := map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var raw, peer string
		var event AnalyticsEvent
		if err := rows.Scan(&raw, &peer); err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal([]byte(raw), &event) != nil || event.ClientAddressSource != "managed_proxy" || len(event.ClientAddressHash) != 64 || event.ClientAddressHash == strings.Repeat("b", 64) {
			t.Fatal("Untrusted client body identity was retained")
		}
		for _, secret := range []string{token, "192.0.2.21", "2001:db8::22", "203.0.113.200", "203.0.113.201"} {
			if strings.Contains(raw, secret) {
				t.Fatal("Raw address or private proxy token leaked into event storage")
			}
		}
		addresses[event.ClientAddressHash], peers[peer] = true, true
	}
	if err := rows.Err(); err != nil || len(addresses) != 2 || len(peers) != 1 || len(a.analyticsRates) != 2 {
		t.Fatal("Managed clients collapsed into their connection peer", err)
	}
	report, err := a.Store.analyticsReport(context.Background(), cfg.SiteID, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	measured := report["client_addresses"].(analyticsClientAddressReport)
	if measured.UniqueAddresses != 2 || measured.KnownPageviews != 2 || measured.UnknownPageviews != 0 || report["overview"].(map[string]any)["unique_network_peers"] != 1 {
		t.Fatal("Client and peer measurements were conflated", measured)
	}
}

func TestAnalyticsManagedClientRejectsForgedAndAmbiguousIdentity(t *testing.T) {
	for _, name := range []string{"wrong_token", "wrong_site_token", "missing_token", "missing_client", "duplicate_token", "duplicate_client", "address_chain", "address_port", "address_zone", "invalid_address", "unspecified", "multicast", "nonloopback_peer", "legacy_configuration", "wrong_include_identity"} {
		t.Run(name, func(t *testing.T) {
			a, site, cfg, token := analyticsClientFixture(t)
			peer := "127.0.0.1:54321"
			headers := map[string][]string{AnalyticsProxyTokenHeader: {token}, AnalyticsProxyClientHeader: {"192.0.2.21"}}
			switch name {
			case "wrong_token":
				headers[AnalyticsProxyTokenHeader] = []string{strings.Repeat("0", 64)}
			case "wrong_site_token":
				wrong, _ := AnalyticsProxyToken(a.accountSecretKey, ID())
				headers[AnalyticsProxyTokenHeader] = []string{wrong}
			case "missing_token":
				delete(headers, AnalyticsProxyTokenHeader)
			case "missing_client":
				delete(headers, AnalyticsProxyClientHeader)
			case "duplicate_token":
				headers[AnalyticsProxyTokenHeader] = []string{token, token}
			case "duplicate_client":
				headers[AnalyticsProxyClientHeader] = []string{"192.0.2.21", "192.0.2.22"}
			case "address_chain":
				headers[AnalyticsProxyClientHeader] = []string{"192.0.2.21, 192.0.2.22"}
			case "address_port":
				headers[AnalyticsProxyClientHeader] = []string{"192.0.2.21:80"}
			case "address_zone":
				headers[AnalyticsProxyClientHeader] = []string{"fe80::21%eth0"}
			case "invalid_address":
				headers[AnalyticsProxyClientHeader] = []string{"not-an-address"}
			case "unspecified":
				headers[AnalyticsProxyClientHeader] = []string{"::"}
			case "multicast":
				headers[AnalyticsProxyClientHeader] = []string{"ff02::1"}
			case "nonloopback_peer":
				peer = "198.51.100.5:54321"
			case "legacy_configuration", "wrong_include_identity":
				site.Settings.AnalyticsProxyIdentity = ""
				if name == "wrong_include_identity" {
					site.Settings.AnalyticsProxyIdentity = strings.Repeat("a", 64)
				}
				raw, _ := json.Marshal(site.Settings)
				if _, err := a.Store.DB.Exec(`UPDATE sites SET settings_json=? WHERE id=?`, string(raw), site.ID); err != nil {
					t.Fatal(err)
				}
			}
			if w := analyticsClientRequest(a, cfg, peer, analyticsClientEvent(), headers); w.Code != 403 {
				t.Fatal("Ambiguous proxy identity accepted", w.Code, w.Body.String())
			}
			var n int
			if err := a.Store.DB.QueryRow(`SELECT count(*) FROM analytics_events`).Scan(&n); err != nil || n != 0 {
				t.Fatal("Rejected request entered event storage", n, err)
			}
		})
	}
}

func TestAnalyticsLegacyProxyVisitorsHaveIndependentBudgetsAndNoInventedAddress(t *testing.T) {
	a, _, cfg := analyticsFixture(t, true)
	blocked, other := analyticsClientEvent(), analyticsClientEvent()
	key := Hash("unverified-proxy-visitor:" + cfg.SiteID + ":" + blocked.Visitor)
	a.analyticsRates = map[string]analyticsRate{key: {Window: time.Now().Unix() / 60, Count: 1200}}
	spoof := map[string][]string{"X-Forwarded-For": {"192.0.2.21"}, "X-Real-IP": {"198.51.100.22"}}
	if w := analyticsClientRequest(a, cfg, "127.0.0.1:54321", blocked, spoof); w.Code != 429 {
		t.Fatal("Forged forwarding header bypassed the visitor budget", w.Code)
	}
	other.ClientAddressHash, other.ClientAddressSource = strings.Repeat("a", 64), "managed_proxy"
	if w := analyticsClientRequest(a, cfg, "127.0.0.1:54321", other, spoof); w.Code != 204 {
		t.Fatal("One visitor exhausted the whole loopback proxy budget", w.Code, w.Body.String())
	}
	var raw string
	if err := a.Store.DB.QueryRow(`SELECT data FROM analytics_events`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored AnalyticsEvent
	if json.Unmarshal([]byte(raw), &stored) != nil || stored.ClientAddressSource != "unknown_proxy" || stored.ClientAddressHash != "" || strings.Contains(raw, "192.0.2.21") {
		t.Fatal("A legacy connection acquired an invented client address")
	}
}

func TestAnalyticsClientAddressReportSeparatesLegacyAndInvalidSamples(t *testing.T) {
	a := newAnalyticsClientAddresses()
	for _, event := range []AnalyticsEvent{
		{ClientAddressHash: strings.Repeat("a", 64), ClientAddressSource: "direct"},
		{ClientAddressHash: strings.Repeat("a", 64), ClientAddressSource: "managed_proxy"},
		{ClientAddressHash: strings.Repeat("b", 64), ClientAddressSource: "managed_proxy"},
		{ClientAddressSource: "unknown_proxy"}, {},
		{ClientAddressSource: "direct", ClientAddressHash: "invalid"},
	} {
		a.Observe(event)
	}
	v := a.Report()
	if v.UniqueAddresses != 2 || v.KnownPageviews != 3 || v.UnknownPageviews != 3 || v.LegacyPageviews != 1 {
		t.Fatal(v)
	}
}

func TestAnalyticsClientProxyIdentityCannotBeEditedThroughOrdinarySiteSettings(t *testing.T) {
	a, site, _, _ := analyticsClientFixture(t)
	creation, err := a.Store.NextJob()
	if err != nil || creation.SiteID != site.ID {
		t.Fatal("Unable to finish the owned site fixture", err)
	}
	if err := a.Store.Finish(creation, "running", "", nil); err != nil {
		t.Fatal(err)
	}
	site, err = a.Store.Site(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	next := site.Settings
	next.AnalyticsProxyIdentity = strings.Repeat("a", 64)
	jobID, err := a.Store.QueueSiteSettings(site.ID, next, site.SettingsRevision, Hash("original fixture configuration"), ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := a.Store.DB.QueryRow(`SELECT payload FROM jobs WHERE id=?`, jobID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var payload JobPayload
	if json.Unmarshal([]byte(raw), &payload) != nil || payload.Settings == nil || payload.Settings.AnalyticsProxyIdentity != site.Settings.AnalyticsProxyIdentity {
		t.Fatal("Ordinary site settings changed the protected proxy identity")
	}
}
