package core

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func countryDataSelectionFixture() WAFCountryDataSelection {
	return WAFCountryDataSelection{"download", "2.6.0", strings.Repeat("a", 64), strings.Repeat("b", 64), "2026-10", 1, strings.Repeat("c", 64), []string{"CN", "US"}}
}

func TestWAFCountryDataProtocolCannotActivatePolicyOrSupplySourceAuthority(t *testing.T) {
	in := countryDataSelectionFixture()
	raw, _ := json.Marshal(in)
	got, err := DecodeWAFCountryDataSelection(raw)
	if err != nil || !SameWAFCountryDataSelection(got, in) {
		t.Fatal(got, err)
	}
	for _, kind := range []string{"action", "future-version", "alias", "app-sha", "instance", "data-sha", "revision", "month", "order", "duplicate", "unknown", "lowercase", "empty", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			v := in
			v.Countries = append([]string(nil), in.Countries...)
			switch kind {
			case "action":
				v.Action = "activate"
			case "future-version":
				v.AppVersion = "2.7.0"
			case "alias":
				v.AppVersion = "2.6.0-build"
			case "app-sha":
				v.AppManifestSHA = "/etc/shadow"
			case "instance":
				v.InstallationSHA = ""
			case "data-sha":
				v.DataManifestSHA = strings.ToUpper(v.DataManifestSHA)
			case "revision":
				v.Revision = 1001
			case "month":
				v.Release = "2026-13"
			case "order":
				v.Countries = []string{"US", "CN"}
			case "duplicate":
				v.Countries = []string{"US", "US"}
			case "unknown":
				v.Countries = []string{"ZZ"}
			case "lowercase":
				v.Countries = []string{"us"}
			case "empty":
				v.Countries = nil
			case "oversize":
				v.Countries = make([]string, 33)
			}
			raw, _ := json.Marshal(v)
			if out, err := DecodeWAFCountryDataSelection(raw); err == nil || !reflect.DeepEqual(out, WAFCountryDataSelection{}) || SameWAFCountryDataSelection(in, v) {
				t.Fatal("unqualified selection accepted", out, err)
			}
		})
	}
	for _, bad := range []string{`null`, `[]`, `{}`, string(raw) + ` {}`, strings.Replace(string(raw), `"action":"download"`, `"action":"download","action":"download"`, 1), strings.Replace(string(raw), `"action":"download"`, `"Action":"download"`, 1), strings.Replace(string(raw), `"action":"download"`, `"action":null`, 1), strings.Replace(string(raw), `"revision":1`, `"revision":"1"`, 1), strings.Replace(string(raw), `"countries":["CN","US"]`, `"countries":[null,"US"]`, 1), strings.TrimSuffix(string(raw), "}") + `,"source":"https://evil.invalid/data"}`, strings.TrimSuffix(string(raw), "}") + `,"public_key":"forged"}`, strings.TrimSuffix(string(raw), "}") + `,"path":"/etc/nginx/nginx.conf"}`, strings.Repeat(" ", 2049)} {
		if out, err := DecodeWAFCountryDataSelection([]byte(bad)); err == nil || !reflect.DeepEqual(out, WAFCountryDataSelection{}) {
			t.Fatal("malformed request accepted", bad, out, err)
		}
	}
}

func TestWAFCountryDataQueryBindsOneCompleteCanonicalSelection(t *testing.T) {
	in := countryDataSelectionFixture()
	q := WAFCountryDataSelectionQuery(in)
	got, err := ParseWAFCountryDataSelectionQuery(q)
	if err != nil || !SameWAFCountryDataSelection(got, in) {
		t.Fatal(got, err)
	}
	for _, kind := range []string{"extra", "missing", "duplicate", "leading-zero", "signed-revision", "separator", "spaces", "none"} {
		t.Run(kind, func(t *testing.T) {
			q := WAFCountryDataSelectionQuery(in)
			switch kind {
			case "extra":
				q.Set("source", "https://evil.invalid")
			case "missing":
				q.Del("installation_sha256")
			case "duplicate":
				q["countries"] = []string{"CN", "US"}
			case "leading-zero":
				q.Set("revision", "01")
			case "signed-revision":
				q.Set("revision", "+1")
			case "separator":
				q.Set("countries", "CN,,US")
			case "spaces":
				q.Set("countries", "CN, US")
			case "none":
				q = url.Values{}
			}
			if out, err := ParseWAFCountryDataSelectionQuery(q); err == nil || !reflect.DeepEqual(out, WAFCountryDataSelection{}) {
				t.Fatal(out, err)
			}
		})
	}
	changed := in
	changed.Countries = []string{"US"}
	if SameWAFCountryDataSelection(in, changed) {
		t.Fatal("country slices not compared")
	}
}
