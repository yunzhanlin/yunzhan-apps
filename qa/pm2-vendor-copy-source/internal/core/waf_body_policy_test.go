package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWAFBodyIsExplicitPerSiteAndCannotBypassOffOrObserve(t *testing.T) {
	v := DefaultWAFConfig()
	if v.Body != nil {
		t.Fatal("default WAF silently enables body engine")
	}
	if _, present := WAFSettings(v)["body"]; present {
		t.Fatal("legacy configuration gained body field")
	}
	id, other := ID(), ID()
	policy := DefaultWAFBodyPolicy()
	policy.Mode = "block"
	v.Body = &WAFBodyConfig{EngineJobID: ID(), Sites: []WAFBodySitePolicy{{SiteID: id, Policy: policy}}}
	if err := validateWAFBodyConfig(v.Body); err != nil {
		t.Fatal(err)
	}
	if got, on := WAFEffectiveBodyPolicy(v, id); !on || got.Mode != "block" {
		t.Fatal("explicit body policy missing")
	}
	if _, on := WAFEffectiveBodyPolicy(v, other); on {
		t.Fatal("unselected website protected silently")
	}
	for _, pair := range [][2]string{{"off", "block"}, {"off", "observe"}, {"observe", "block"}, {"block", "off"}, {"block", "observe"}} {
		v.Policy.Mode = pair[0]
		v.Policy.Sites = []WAFSitePolicy{{SiteID: id, Mode: pair[1]}}
		got, on := WAFEffectiveBodyPolicy(v, id)
		if pair[0] == "off" || pair[1] == "off" {
			if on || got.Mode != "off" {
				t.Fatal("off bypassed", pair, got)
			}
		} else if got.Mode != "observe" || !on {
			t.Fatal("observe bypassed", pair, got)
		}
	}
	decoded, err := DecodeWAFConfig(WAFSettings(v))
	if err != nil || decoded.Body == nil || decoded.Body.Sites[0].SiteID != id {
		t.Fatal("body policy round-trip lost", err)
	}
	if ids := WAFScopedSites(v); len(ids) != 1 || ids[0] != id {
		t.Fatal("body website omitted from access/archive reference validation", ids)
	}
}

func TestWAFBodyRejectsUnboundedUnknownAndUnreadyPolicyInputs(t *testing.T) {
	for name, mutate := range map[string]func(*WAFBodyConfig){
		"no-engine":      func(v *WAFBodyConfig) { v.EngineJobID = "" },
		"path-engine":    func(v *WAFBodyConfig) { v.EngineJobID = "../../module.so" },
		"invalid-site":   func(v *WAFBodyConfig) { v.Sites[0].SiteID = "arbitrary-domain" },
		"duplicate":      func(v *WAFBodyConfig) { v.Sites = append(v.Sites, v.Sites[0]) },
		"too-many":       func(v *WAFBodyConfig) { v.Sites = make([]WAFBodySitePolicy, 65) },
		"mode-injection": func(v *WAFBodyConfig) { v.Sites[0].Policy.Mode = "On\nSecRemoteRules attacker" },
		"paranoia":       func(v *WAFBodyConfig) { v.Sites[0].Policy.Paranoia = 5 },
		"threshold":      func(v *WAFBodyConfig) { v.Sites[0].Policy.Threshold = 101 },
		"body-bytes":     func(v *WAFBodyConfig) { v.Sites[0].Policy.BodyLimitKiB = 8193 },
		"nonfile":        func(v *WAFBodyConfig) { v.Sites[0].Policy.NonFileLimitKiB = 1025 },
		"depth":          func(v *WAFBodyConfig) { v.Sites[0].Policy.JSONDepth = 129 },
		"arguments":      func(v *WAFBodyConfig) { v.Sites[0].Policy.ArgumentLimit = 1001 },
	} {
		t.Run(name, func(t *testing.T) {
			v := DefaultWAFConfig()
			v.Body = &WAFBodyConfig{EngineJobID: ID(), Sites: []WAFBodySitePolicy{{SiteID: ID(), Policy: DefaultWAFBodyPolicy()}}}
			mutate(v.Body)
			if _, err := DecodeWAFConfig(WAFSettings(v)); err == nil {
				t.Fatal("unsafe body policy accepted")
			}
		})
	}
	v := DefaultWAFConfig()
	v.Body = &WAFBodyConfig{EngineJobID: ID(), Sites: []WAFBodySitePolicy{{SiteID: ID(), Policy: DefaultWAFBodyPolicy()}}}
	raw := WAFSettings(v)
	encoded, _ := json.Marshal(raw)
	for _, replacement := range []string{`"sites":null`, `"sites":[],"source_url":"https://attacker.invalid/module"`, `"sites":[],"nginx_snippet":"load_module evil"`} {
		data := strings.Replace(string(encoded), `"sites":[{"policy":`, replacement+`,"unused":[{"policy":`, 1)
		var mutated map[string]any
		if err := json.Unmarshal([]byte(data), &mutated); err != nil {
			t.Fatal("invalid fixture", err)
		}
		if _, err := DecodeWAFConfig(mutated); err == nil {
			t.Fatal("unknown or null body input accepted")
		}
	}
}
