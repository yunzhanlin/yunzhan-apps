package core

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestWAFCountrySubmissionRejectsAliasesDuplicateMissingForeignAndExecutableAuthority(t *testing.T) {
	in := WAFCountryDataSubmission{Actor: ID(), Selection: countryDataSelectionFixture(), Envelope: appcatalog.GeoDataEnvelope{AppCatalog: []byte("shape-only unsigned fixture"), AppSignature: []byte("unsigned"), AppManifest: []byte("unsigned"), DataManifest: []byte("unsigned"), DataSignature: []byte("unsigned")}}
	raw, _ := json.Marshal(in)
	got, err := DecodeWAFCountryDataSubmission(raw)
	if err != nil || !reflect.DeepEqual(got, in) {
		t.Fatal("shape-only original fixture rejected, NOT signature authority", got, err)
	}
	for _, bad := range []string{"null", "{}", string(raw) + ` {}`, strings.Replace(string(raw), `"actor_id":`, `"Actor_id":`, 1), strings.Replace(string(raw), `"actor_id":"`+in.Actor+`"`, `"actor_id":"`+in.Actor+`","actor_id":"`+in.Actor+`"`, 1), strings.Replace(string(raw), `"action":"download"`, `"action":"download","action":"download"`, 1), strings.Replace(string(raw), `"envelope":{`, `"envelope":{"source":"https://evil.invalid",`, 1), strings.Replace(string(raw), `"selection":{`, `"selection":{"path":"/etc/nginx/nginx.conf",`, 1), strings.Replace(string(raw), `"app_catalog":`, `"App_catalog":`, 1), strings.TrimSuffix(string(raw), "}") + `,"verify":true}`, strings.Repeat(" ", WAFCountrySubmissionMaxBytes+1)} {
		if got, err := DecodeWAFCountryDataSubmission([]byte(bad)); err == nil || !reflect.DeepEqual(got, WAFCountryDataSubmission{}) {
			t.Fatal("unqualified country delivery accepted", got, err)
		}
	}
}

func TestWAFCountryObservationQueryRequiresExactOriginalActorAndPayload(t *testing.T) {
	actor, digest := ID(), Hash("original exact payload")
	if a, h, err := ParseWAFCountryObservationQuery(WAFCountryObservationQuery(actor, digest)); err != nil || a != actor || h != digest {
		t.Fatal(a, h, err)
	}
	for _, q := range []url.Values{{}, {"actor_id": {actor}}, {"actor_id": {actor, actor}, "payload_sha256": {digest}}, {"actor_id": {actor}, "payload_sha256": {digest, digest}}, {"actor_id": {actor}, "payload_sha256": {digest}, "source": {"https://evil.invalid"}}, {"actor_id": {"../"}, "payload_sha256": {digest}}, {"actor_id": {actor}, "payload_sha256": {strings.ToUpper(digest)}}} {
		if _, _, err := ParseWAFCountryObservationQuery(q); err == nil {
			t.Fatal("ambiguous or caller-controlled observation accepted", q)
		}
	}
}

func TestWAFCountryStateCannotBorrowOldVersionOrInventInstalledCapability(t *testing.T) {
	base := WAFCountryDataState{MaxCountries: 32, MaxBytes: 64 << 20, MaxNetworks: 1 << 20, DownloadsDoNotActivatePolicy: true}
	for _, v := range []WAFCountryDataState{base, {Installed: true, AppVersion: "2.5.1", MaxCountries: 32, MaxBytes: 64 << 20, MaxNetworks: 1 << 20, DownloadsDoNotActivatePolicy: true}, {Installed: true, AppVersion: "2.6.0", InstallationSHA: Hash("synthetic installed instance"), Supported: true, MaxCountries: 32, MaxBytes: 64 << 20, MaxNetworks: 1 << 20, DownloadsDoNotActivatePolicy: true}} {
		raw, _ := json.Marshal(v)
		if got, err := DecodeWAFCountryDataState(raw); err != nil || got != v {
			t.Fatal(got, err)
		}
	}
	for _, kind := range []string{"missing-install", "old-capability", "missing-instance", "unknown-instance", "countries", "bytes", "networks", "activate", "alias", "null", "duplicate"} {
		v := base
		switch kind {
		case "missing-install":
			v.AppVersion = "2.6.0"
		case "old-capability":
			v.Installed, v.Supported, v.AppVersion, v.InstallationSHA = true, true, "2.5.1", Hash("wrong old version")
		case "missing-instance":
			v.Installed, v.Supported, v.AppVersion = true, true, "2.6.0"
		case "unknown-instance":
			v.Installed, v.AppVersion, v.InstallationSHA = true, "2.6.0", Hash("not advertised instance")
		case "countries":
			v.MaxCountries = 33
		case "bytes":
			v.MaxBytes++
		case "networks":
			v.MaxNetworks++
		case "activate":
			v.DownloadsDoNotActivatePolicy = false
		}
		raw, _ := json.Marshal(v)
		switch kind {
		case "alias":
			raw = []byte(strings.Replace(string(raw), `"supported":`, `"Supported":`, 1))
		case "null":
			raw = []byte(strings.Replace(string(raw), `"supported":false`, `"supported":null`, 1))
		case "duplicate":
			raw = []byte(strings.Replace(string(raw), `"supported":false`, `"supported":false,"supported":false`, 1))
		}
		if got, err := DecodeWAFCountryDataState(raw); err == nil || got != (WAFCountryDataState{}) {
			t.Fatal("unqualified Root installed state accepted", kind, got, err)
		}
	}
}
