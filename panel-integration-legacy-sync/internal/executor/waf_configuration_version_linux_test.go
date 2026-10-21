//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func wafConfigurationTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data := []byte{}
		if !d.IsDir() {
			data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[rel] = fmt.Sprintf("%v:%d:%s", info.Mode(), info.ModTime().UnixNano(), core.Hash(string(data)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// This is a private filesystem regression, not an application update. A
// programme upgrade must not let a legacy client silently promote the app.
func TestWAFConfigurationRequiresInstalledImplementationVersion(t *testing.T) {
	versions := []string{"2.0.1", "2.1.0", "2.1.1", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.5.1", "2.5.3", "2.6.0", "", "unknown"}
	for _, version := range versions {
		for _, legacy := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/legacy=%v", version, legacy), func(t *testing.T) {
				s, cfg := wafLegacyVersionFixture(t, "2.5.1")
				manifest, err := s.readSoftwareManifest("nginx-waf")
				if err != nil {
					t.Fatal(err)
				}
				manifest.Version = version
				if err = s.writeSoftwareManifest(manifest); err != nil {
					t.Fatal(err)
				}
				cfg.Profile = "strict"
				raw := core.WAFSettings(cfg)
				if legacy {
					raw = map[string]any{"profile": "strict", "rate_per_second": 31}
				}
				before := wafConfigurationTree(t, s.Config.SystemRoot)
				calls := 0
				s.Config.Run = func(context.Context, string, ...string) (string, error) {
					calls++
					return "", nil
				}
				if _, err = s.prepareWAFSettings(raw, false); err == nil {
					t.Fatal("old/unknown installed version accepted a current-version configuration")
				}
				if err = s.applyWAF(context.Background(), raw, false, func(string) { t.Error("rejected configuration emitted an apply step") }); err == nil {
					t.Fatal("configuration silently promoted an application outside the signed update path")
				}
				if calls != 0 || !reflect.DeepEqual(before, wafConfigurationTree(t, s.Config.SystemRoot)) {
					t.Fatal("rejected version ran a command, opened a recovery transaction or changed the original tree", calls)
				}
			})
		}
	}
}

func TestWAFConfigurationRoutesRejectOldVersionWithoutMutation(t *testing.T) {
	for _, operation := range []string{"configure", "preview"} {
		t.Run(operation, func(t *testing.T) {
			s, cfg := wafLegacyVersionFixture(t, "2.5.1")
			calls := 0
			s.Config.Run = func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
			before := wafConfigurationTree(t, s.Config.SystemRoot)
			settings := core.WAFSettings(cfg)
			body, err := json.Marshal(settings)
			if operation == "configure" {
				body, err = json.Marshal(map[string]any{"settings": settings})
			}
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			s.softwareRoutes(mux)
			request := httptest.NewRequest(http.MethodPost, "/v1/software/nginx-waf/"+operation, bytes.NewReader(body))
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "应用商店") {
				t.Fatal("old configuration was not refused through the actual executor route", response.Code, response.Body.String())
			}
			if calls != 0 || !reflect.DeepEqual(before, wafConfigurationTree(t, s.Config.SystemRoot)) {
				t.Fatal("refused old-version route changed original state", calls)
			}
		})
	}
}

func TestWAFConfigurationInstallationRejectsMismatchedSignedVersion(t *testing.T) {
	for _, version := range []string{"", "2.0.1", "2.5.1", "2.5.3", "2.6.0", "latest"} {
		t.Run(version, func(t *testing.T) {
			s := wafPolicyFixture(t)
			before := wafConfigurationTree(t, s.Config.SystemRoot)
			calls := 0
			s.Config.Run = func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
			body, err := json.Marshal(map[string]any{"settings": core.WAFSettings(core.DefaultWAFConfig()), "version": version})
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			s.softwareRoutes(mux)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/software/nginx-waf/install", bytes.NewReader(body)))
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "签名版本") {
				t.Fatal("old unsigned/direct installation silently enabled current code", response.Code)
			}
			if calls != 0 || !reflect.DeepEqual(before, wafConfigurationTree(t, s.Config.SystemRoot)) {
				t.Fatal("mismatched installation wrote state or called a command", calls)
			}
		})
	}
}
