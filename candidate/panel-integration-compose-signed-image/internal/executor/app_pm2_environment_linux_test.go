//go:build linux

package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPM2EnvironmentEncryptedWriteOnlyPatchAndIdentity(t *testing.T) {
	s, _, _ := appReliabilityFixture(t)
	app := pm2App{ID: "qa-environment", SiteID: "owned-site", Revision: 1}
	secret, empty := "private-token-not-in-any-report", ""
	if err := s.patchPM2Environment(&app, map[string]*string{"API_TOKEN": &secret, "EMPTY": &empty}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(app.EnvironmentKeys, []string{"API_TOKEN", "EMPTY"}) {
		t.Fatal(app.EnvironmentKeys)
	}
	private, _ := json.Marshal(app)
	public, _ := json.Marshal(publicPM2App(app))
	if strings.Contains(string(private), secret) || strings.Contains(string(public), secret) || strings.Contains(string(public), "environment_cipher") {
		t.Fatal("secret exposed")
	}
	values, err := s.readPM2Environment(app)
	if err != nil || values["API_TOKEN"] != secret {
		t.Fatal(err)
	}
	before := app.EnvironmentCipher
	if err = s.patchPM2Environment(&app, nil); err != nil || app.EnvironmentCipher != before {
		t.Fatal("blank update changed secrets", err)
	}
	app.Revision++
	if err = s.patchPM2Environment(&app, map[string]*string{"API_TOKEN": nil}); err != nil {
		t.Fatal(err)
	}
	values, err = s.readPM2Environment(app)
	if err != nil || len(values) != 1 || values["EMPTY"] != "" {
		t.Fatal(values, err)
	}
	copied := app
	copied.ID = "another-app"
	if _, err = s.readPM2Environment(copied); err == nil {
		t.Fatal("cross-application ciphertext accepted")
	}
	keyPath := filepath.Join(s.moduleDir("pm2-manager"), "environment.key")
	if err = os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = s.readPM2Environment(app); err == nil {
		t.Fatal("publicly readable key accepted")
	}
	if err = os.Chmod(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err = s.patchPM2Environment(&app, map[string]*string{"NEW": &secret}); err == nil {
		t.Fatal("missing key silently regenerated")
	}
	if _, err = os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("missing key overwritten")
	}
}

func TestPM2EnvironmentReservedFieldsLimitsAndExecValues(t *testing.T) {
	for _, key := range []string{"HOST", "PORT", "PATH", "HOME", "PM2_HOME", "NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "DYLD_LIBRARY_PATH", "npm_config_registry", "bad-name", "1bad", "BASH_ENV"} {
		if validPM2Environment(map[string]string{key: "bad"}) == nil {
			t.Fatal("reserved name accepted", key)
		}
	}
	for _, value := range []string{"nul\x00value", strings.Repeat("x", 8193)} {
		if validPM2Environment(map[string]string{"CUSTOM": value}) == nil {
			t.Fatal("unsafe value accepted")
		}
	}
	values := map[string]string{"API_KEY": "quotes' $()\nline", "NODE_ENV": "staging", "EMPTY": ""}
	if err := validPM2Environment(values); err != nil {
		t.Fatal(err)
	}
	env := pm2Environment("/usr/bin/node", "/private/pm2", 23000, values)
	if !slices.Contains(env, "API_KEY=quotes' $()\nline") || !slices.Contains(env, "NODE_ENV=staging") || slices.Contains(env, "NODE_ENV=production") || !slices.Contains(env, "HOST=127.0.0.1") {
		t.Fatal("values treated as shell or defaults override custom values", env)
	}
}
