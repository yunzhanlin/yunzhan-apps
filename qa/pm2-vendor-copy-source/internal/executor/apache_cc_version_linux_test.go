//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestApacheCCNativeVersionInheritanceIsReadOnlyAndCannotPromote240(t *testing.T) {
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.CCEnabled = true
	cfg.Policy.Revision = 14
	cfg.ApacheCC = &core.ApacheWAFCCConfig{EngineJobID: strings.Repeat("a", 32)}
	s, original := apacheNativeRecordFixture(t, core.ApacheWAFNativeCCVersion, cfg)
	raw := core.WAFSettings(cfg)
	delete(raw, "apache_cc")
	before := core.WAFSettings(cfg)
	wanted := core.WAFSettings(cfg)
	out, err := s.apacheNativeSettingsVersion(raw, false, false, core.ApacheWAFNativeCCVersion)
	if err != nil || !reflect.DeepEqual(core.WAFSettings(out), wanted) {
		t.Fatal("omitted unchanged CC reference was lost", err)
	}
	if _, exists := raw["apache_cc"]; exists {
		t.Fatal("immutable original request was rewritten during inheritance")
	}
	if !reflect.DeepEqual(core.WAFSettings(cfg), before) {
		t.Fatal("stored source policy was changed")
	}
	stale := core.WAFSettings(cfg)
	stale["policy"].(map[string]any)["revision"] = float64(13)
	if _, err := s.apacheNativeSettingsVersion(stale, false, false, core.ApacheWAFNativeCCVersion); err == nil {
		t.Fatal("stale CC revision accepted")
	}
	path := filepath.Join(s.moduleDir("apache-waf"), "installed.json")
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatal("read-only settings phase changed the private installation", err)
	}
	legacy := core.DefaultApacheWAFConfig()
	old, oldBytes := apacheNativeRecordFixture(t, core.ApacheWAFNativeBodyVersion, legacy)
	if _, err := old.apacheNativeSettings(core.WAFSettings(cfg), false, false); err == nil {
		t.Fatal("240 acquired CC through configure")
	}
	if _, err := old.apacheNativeSettingsVersion(core.WAFSettings(cfg), false, false, core.ApacheWAFNativeCCVersion); err == nil {
		t.Fatal("request flag promoted current installation to250")
	}
	actual, err = os.ReadFile(filepath.Join(old.moduleDir("apache-waf"), "installed.json"))
	if err != nil || !bytes.Equal(actual, oldBytes) {
		t.Fatal("old native installation changed", err)
	}
}

func TestApacheCCLoadedProbeRequiresTheOwnedEmptyRouteAndBothExactFingerprints(t *testing.T) {
	cfg := core.DefaultApacheWAFConfig()
	cfg.ApacheCC = &core.ApacheWAFCCConfig{EngineJobID: strings.Repeat("a", 32)}
	cfg.Policy.CCEnabled = true
	for _, bad := range []string{"none", "main", "cc", "marker", "redirect", "limited", "unavailable", "application-success"} {
		t.Run(bad, func(t *testing.T) {
			client := &http.Client{Transport: siteTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != "HEAD" || r.URL.String() != "http://127.0.0.1:19080/__yunzhan_waf_probe" || r.Host != "owned.localhost" || r.Header.Get("Cookie") != "" {
					t.Fatal("probe used an arbitrary target or credentials")
				}
				h := http.Header{}
				h.Set("X-Panel-Apache-WAF", apacheWAFProbeVersion(cfg, core.ApacheWAFNativeCCVersion))
				h.Set("X-Panel-Apache-CC", apacheCCEngineVersion+":"+apacheCCPolicyFingerprint(cfg))
				h.Set("X-Panel-Apache-CC-Probe", apacheCCEngineVersion)
				status := 204
				switch bad {
				case "main":
					h.Set("X-Panel-Apache-WAF", "stale")
				case "cc":
					h.Set("X-Panel-Apache-CC", "stale")
				case "marker":
					h.Del("X-Panel-Apache-CC-Probe")
				case "redirect":
					status = 302
				case "limited":
					status = 429
				case "unavailable":
					status = 503
				case "application-success":
					status = 200
				}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})}
			err := apacheWAFProbeLoadedVersion(context.Background(), cfg, "owned.localhost", client, core.ApacheWAFNativeCCVersion)
			if (err == nil) != (bad == "none") {
				t.Fatal("false CC health or rejected owned route", bad, err)
			}
		})
	}
}

func TestApacheCCDefaultLogAndOpaqueInstallationStaySeparateFromBodyMetadata(t *testing.T) {
	source, err := os.ReadFile("assets/apache-cc-module.c")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), `#define YZ_CC_LOG_PATH "`+apacheCCLogPath+`"`) || apacheCCLogPath == apacheBodyMetadataLog || filepath.Dir(apacheCCLogPath) != apacheBodyMetadataDirectory {
		t.Fatal("native and Root log identities drifted or alias the numerical body sink")
	}
	_, original := apacheNativeRecordFixture(t, core.ApacheWAFNativeBodyVersion, core.DefaultApacheWAFConfig())
	document, err := apacheBodySiteManifestDocument(original)
	if err != nil {
		t.Fatal(err)
	}
	opaque := json.RawMessage(`{"customer":["owned",{"keep":true}],"schema":17}`)
	document["customer_metadata"] = opaque
	original, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := apacheNativeMutationManifest(original, core.DefaultApacheWAFConfig(), core.ApacheWAFNativeCCVersion, "original-install-time")
	if err != nil || !bytes.Equal(updated["customer_metadata"], opaque) || string(updated["version"]) != `"2.5.0"` || string(updated["installed_at"]) != `"original-install-time"` {
		t.Fatal("upgrade dropped opaque original data or changed the intended identity", updated, err)
	}
}
