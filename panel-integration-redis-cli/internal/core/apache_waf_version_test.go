package core

import (
	"database/sql"
	"encoding/json"
	"local/panel/internal/appcatalog"
	"reflect"
	"strings"
	"testing"
)

func apacheNativeRequestFixture() WAFConfig {
	cfg := DefaultApacheWAFConfig()
	cfg.Body = &WAFBodyConfig{EngineJobID: ID(), Sites: []WAFBodySitePolicy{{SiteID: ID(), Policy: DefaultWAFBodyPolicy()}}}
	return cfg
}

func TestApacheNativeUpdateCannotBorrowNilNoopForeignOrRevokedBinding(t *testing.T) {
	for _, scenario := range []string{"signed", "nil", "noop", "foreign", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, _ := wafTaskTestServer(t)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			item := appcatalog.CatalogItem{ID: "apache-waf", Target: "apache-waf", Provider: "panel-module", Version: ApacheWAFNativeBodyVersion, SHA256: strings.Repeat("b", 64)}
			if scenario == "foreign" {
				item.ID = "daily-report"
			}
			key := "native-update-" + scenario
			var bind func(*sql.Tx, string, bool) error
			if scenario == "noop" {
				bind = func(*sql.Tx, string, bool) error { return nil }
			} else if scenario != "nil" {
				bind = s.bindRegistryUpdate(item, "apache-waf", key, u.ID)
			}
			if scenario == "revoked" {
				if _, e := s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", u.ID); e != nil {
					t.Fatal(e)
				}
			}
			job, err := s.queueSoftwareActionBound("apache-waf", "update", map[string]any{"untrusted": "must not replace current settings"}, ApacheWAFNativeBodyVersion, key, u.Username, bind)
			if scenario != "signed" {
				if err == nil || job != "" {
					t.Fatal("unsigned or borrowed native update queued", scenario, job, err)
				}
				for _, table := range []string{"runtime_jobs", "app_registry_update_requests", "app_registry_pending"} {
					var n int
					if e := s.DB.QueryRow("SELECT count(*)FROM " + table).Scan(&n); e != nil || n != 0 {
						t.Fatal("partial unsigned update", n, e)
					}
				}
				return
			}
			if err != nil || !ValidID(job) {
				t.Fatal(err)
			}
			var payload string
			if e := s.DB.QueryRow("SELECT payload FROM runtime_jobs WHERE id=?", job).Scan(&payload); e != nil {
				t.Fatal(e)
			}
			var raw struct {
				Settings map[string]any `json:"settings"`
				Version  string         `json:"version"`
			}
			if json.Unmarshal([]byte(payload), &raw) != nil || raw.Settings != nil || raw.Version != ApacheWAFNativeBodyVersion {
				t.Fatal("update replaced live configuration", payload)
			}
			// A completed original keeps its immutable request identity even after
			// pending consumption; replay never creates a second job or pending row.
			if _, e := s.DB.Exec("UPDATE runtime_jobs SET state='succeeded' WHERE id=?", job); e != nil {
				t.Fatal(e)
			}
			if _, e := s.DB.Exec("DELETE FROM app_registry_pending WHERE job_id=?", job); e != nil {
				t.Fatal(e)
			}
			replay, e := s.queueSoftwareActionBound("apache-waf", "update", nil, ApacheWAFNativeBodyVersion, key, u.Username, bind)
			if e != nil || replay != job {
				t.Fatal("original completed update replay changed", replay, e)
			}
			var n int
			if e := s.DB.QueryRow("SELECT count(*)FROM app_registry_pending").Scan(&n); e != nil || n != 0 {
				t.Fatal("completed pending request recreated", n, e)
			}
		})
	}
}

func TestApacheNativeScopesRequireActuallyRunningManagedApacheSites(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	for n, status := range []string{"running", "stopped", "archived", "needs_attention", "queued"} {
		cfg := apacheNativeRequestFixture()
		cfg.Body.Sites[0].SiteID = wafSiteFixture(t, s, n+1500, "apache", status, nil)
		err := s.validateApacheWAFSites(cfg)
		if (err == nil) != (status == "running") {
			t.Fatal("website lifecycle status confused with native authority", status, err)
		}
	}
}

func TestApacheNativeSignedInstallBindsVersionActorPayloadAndOriginalRequestAtomically(t *testing.T) {
	for _, scenario := range []string{"signed", "missing-registry-binding", "different-signed-version"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, _ := wafTaskTestServer(t)
			u := wafArchivePendingIdentity(t, s, "waf-admin")
			cfg := apacheNativeRequestFixture()
			cfg.Body.Sites[0].SiteID = wafSiteFixture(t, s, 991, "apache", "running", nil)
			settings := WAFSettings(cfg)
			item := appcatalog.CatalogItem{ID: "apache-waf", Target: "apache-waf", Provider: "panel-module", Version: ApacheWAFNativeBodyVersion, SHA256: strings.Repeat("a", 64)}
			if scenario == "different-signed-version" {
				item.Version = ApacheWAFVersion
			}
			key := "native-bound-" + scenario
			bind := s.bindWAFApplyRequest("apache-waf", key, u)
			if scenario != "missing-registry-binding" {
				wafBind := bind
				registryBind := s.bindRegistryInstall(item, "apache-waf", key, u.ID, registryInstallInput{Settings: settings, ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256})
				bind = func(tx *sql.Tx, job string, existing bool) error {
					if err := registryBind(tx, job, existing); err != nil {
						return err
					}
					return wafBind(tx, job, existing)
				}
			}
			job, err := s.queueSoftwareActionBound("apache-waf", "install", settings, ApacheWAFNativeBodyVersion, key, u.Username, bind)
			if scenario != "signed" {
				if err == nil || job != "" {
					t.Fatal("unbound native install queued", job, err)
				}
				for _, table := range []string{"runtime_jobs", "waf_apply_requests", "app_registry_install_requests", "app_registry_pending"} {
					var n int
					if e := s.DB.QueryRow("SELECT count(*)FROM " + table).Scan(&n); e != nil || n != 0 {
						t.Fatal("partial native binding", table, n, e)
					}
				}
				return
			}
			if err != nil || !ValidID(job) {
				t.Fatal(err)
			}
			var payload, actor, version string
			if err = s.DB.QueryRow("SELECT j.payload,w.actor_id,i.version FROM runtime_jobs j JOIN waf_apply_requests w ON w.job_id=j.id JOIN app_registry_install_requests i ON i.job_id=j.id WHERE j.id=?", job).Scan(&payload, &actor, &version); err != nil || actor != u.ID || version != ApacheWAFNativeBodyVersion {
				t.Fatal("original native authority missing", err)
			}
			if _, err = wafApplyOriginalSettingsForRequest("apache-waf", "software_install", payload, version); err != nil {
				t.Fatal(err)
			}
			// Queued is not installed or healthy. No executor exists in this model.
			var state string
			if err = s.DB.QueryRow("SELECT state FROM runtime_jobs WHERE id=?", job).Scan(&state); err != nil || state != "queued" {
				t.Fatal(state, err)
			}
		})
	}
}

func TestApacheNativeVersionDoesNotPromoteMetadataDefaultOrAliases(t *testing.T) {
	if SoftwareImplementationVersion("apache-waf") != ApacheWAFVersion || ApacheWAFVersion != "2.3.0" {
		t.Fatal("programme upgrade silently promoted default")
	}
	cfg := apacheNativeRequestFixture()
	raw := WAFSettings(cfg)
	for _, version := range []string{"", "1.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0-compat1", "2.5.0", "02.4.0", "18446744073709551616.0.0"} {
		if _, err := DecodeApacheWAFVersionConfig(raw, version); err == nil {
			t.Fatal("non-native identity borrowed body capability", version)
		}
	}
	if got, err := DecodeApacheWAFVersionConfig(raw, ApacheWAFNativeBodyVersion); err != nil || !reflect.DeepEqual(WAFSettings(got), raw) {
		t.Fatal("explicit native identity lost policy", err)
	}
	if ValidateSoftwareUpdate("apache-waf", ApacheWAFNativeBodyVersion) != nil {
		t.Fatal("exact signed update unavailable")
	}
	for _, version := range []string{"2.4.0-compat1", "2.4.1", "2.5.0", "02.4.0", "unknown"} {
		if ValidateSoftwareUpdate("apache-waf", version) == nil {
			t.Fatal("unknown/aliased native version update allowed", version)
		}
	}
	if _, err := normalizeSoftwareSettings("apache-waf", raw); err == nil {
		t.Fatal("legacy direct normalizer granted body capability")
	}
}

func TestApacheNativeOriginalRequestNeedsExactSignedInstallButNotNewConfigureVersion(t *testing.T) {
	cfg := apacheNativeRequestFixture()
	settings := WAFSettings(cfg)
	encode := func(version string) string {
		b, e := json.Marshal(map[string]any{"settings": settings, "version": version})
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	good := encode(ApacheWAFNativeBodyVersion)
	if _, err := wafApplyOriginalSettingsForRequest("apache-waf", "software_install", good, ApacheWAFNativeBodyVersion); err != nil {
		t.Fatal("original signed exact native install rejected", err)
	}
	for _, v := range []struct{ app, kind, payload, signed string }{
		{"apache-waf", "software_install", good, ""},
		{"apache-waf", "software_install", good, "2.3.0"},
		{"apache-waf", "software_configure", good, ApacheWAFNativeBodyVersion},
		{"nginx-waf", "software_install", good, ApacheWAFNativeBodyVersion},
		{"apache-waf", "software_update", good, ApacheWAFNativeBodyVersion},
		{"apache-waf", "software_install", encode(""), ""},
		{"apache-waf", "software_install", encode("2.4.0-compat1"), "2.4.0-compat1"},
	} {
		if _, err := wafApplyOriginalSettingsForRequest(v.app, v.kind, v.payload, v.signed); err == nil {
			t.Fatal("native identity lost actor/job/version-bound authority", v)
		}
	}
	if _, err := wafApplyOriginalSettingsForRequest("apache-waf", "software_configure", encode(""), ""); err != nil {
		t.Fatal("retained configure shape rejected; executor still authorizes current installation", err)
	}
	if _, err := wafApplyOriginalSettings("apache-waf", encode("")); err == nil {
		t.Fatal("untyped historical payload was promoted")
	}
	cfg.Policy.CCEnabled = true
	if _, err := DecodeApacheWAFNativeBodyConfig(WAFSettings(cfg)); err == nil {
		t.Fatal("unsupported Apache CC advertised as native feature")
	}
}
