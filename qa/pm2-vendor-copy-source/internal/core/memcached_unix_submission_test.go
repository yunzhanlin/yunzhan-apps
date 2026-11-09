package core

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func memcachedUnixSubmissionFixture(t *testing.T, site string) MemcachedUnixInstallSubmission {
	t.Helper()
	raw, err := MemcachedUnixRequestCompose(strings.Repeat("b", 32), site)
	if err != nil {
		t.Fatal(err)
	}
	op := DockerProjectRequest{JobID: strings.Repeat("a", 32), ProjectID: strings.Repeat("b", 32), Action: "create", Name: "own-socket", Compose: raw, TemplateID: "memcached-cache", TemplateProfile: MemcachedUnixProfile, SiteID: site, ActorID: strings.Repeat("c", 32)}
	// Deliberately unsigned framing data. Root MUST independently reject this
	// as official authority; codec acceptance is not an installation grant.
	envelope := appcatalog.MemcachedUnixReleaseEnvelope{Catalog: []byte("own unsigned catalog"), Signature: []byte("own unsigned signature"), AppManifest: []byte("own unsigned manifest")}
	out, err := NewMemcachedUnixInstallSubmission(op, MemcachedUnixBinding{appcatalog.MemcachedUnixVersion, Hash(string(envelope.AppManifest))}, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMemcachedUnixInstallSubmissionCanonicalSeparateAndDetached(t *testing.T) {
	for _, site := range []string{"", strings.Repeat("d", 32)} {
		in := memcachedUnixSubmissionFixture(t, site)
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		before := bytes.Clone(raw)
		out, err := DecodeMemcachedUnixInstallSubmission(raw)
		if err != nil || !reflect.DeepEqual(out, in) || !bytes.Equal(raw, before) {
			t.Fatal("original exact bound transfer lost", err)
		}
		out.Envelope.Catalog[0] ^= 1
		if bytes.Equal(out.Envelope.Catalog, in.Envelope.Catalog) {
			t.Fatal("decoder retained caller buffers")
		}
		from := in.Envelope
		made, err := NewMemcachedUnixInstallSubmission(in.Operation, in.Binding, from)
		if err != nil {
			t.Fatal(err)
		}
		from.AppManifest[0] ^= 1
		if bytes.Equal(made.Envelope.AppManifest, from.AppManifest) {
			t.Fatal("factory retained mutable bytes")
		}
		if _, err := DecodeMemcachedUpdateSubmission(raw); err == nil {
			t.Fatal("Unix install widened the compat2 update journal")
		}
	}
}

func TestMemcachedUnixInstallSubmissionRejectsIdentityAndWireBorrowing(t *testing.T) {
	in := memcachedUnixSubmissionFixture(t, "")
	canonical, _ := json.Marshal(in)
	for _, change := range []func(*MemcachedUnixInstallSubmission){
		func(v *MemcachedUnixInstallSubmission) { v.Operation.Action = "restart" },
		func(v *MemcachedUnixInstallSubmission) { v.Operation.TemplateProfile = "" },
		func(v *MemcachedUnixInstallSubmission) { v.Operation.ActorID = "" },
		func(v *MemcachedUnixInstallSubmission) { v.Operation.SiteID = strings.Repeat("d", 32) },
		func(v *MemcachedUnixInstallSubmission) { v.Operation.RequestSHA = strings.Repeat("e", 64) },
		func(v *MemcachedUnixInstallSubmission) { v.Operation.Compose += "\nports: [11211]\n" },
		func(v *MemcachedUnixInstallSubmission) { v.Operation.TemplateID = "mongodb" },
		func(v *MemcachedUnixInstallSubmission) { v.Binding.Version = appcatalog.MemcachedDigestVersion },
		func(v *MemcachedUnixInstallSubmission) { v.Binding.ManifestSHA256 = strings.Repeat("a", 64) },
		func(v *MemcachedUnixInstallSubmission) { v.Envelope.AppManifest = []byte("changed") },
		func(v *MemcachedUnixInstallSubmission) { v.Envelope.Signature = nil },
	} {
		var v MemcachedUnixInstallSubmission
		if json.Unmarshal(canonical, &v) != nil {
			t.Fatal("fixture")
		}
		change(&v)
		raw, _ := json.Marshal(v)
		if _, err := DecodeMemcachedUnixInstallSubmission(raw); err == nil {
			t.Fatal("changed identity accepted")
		}
	}
	for _, raw := range [][]byte{
		nil, []byte("null"), []byte("[]"), []byte("{}"),
		append(bytes.Clone(canonical), '\n'), append(bytes.Clone(canonical), canonical...),
		bytes.Replace(canonical, []byte(`"operation":`), []byte(`"operation":{},"operation":`), 1),
		bytes.Replace(canonical, []byte(`"actor_id":`), []byte(`"Actor_ID":`), 1),
		bytes.Replace(canonical, []byte(`"binding":{`), []byte(`"binding":{"verified":true,`), 1),
		bytes.Replace(canonical, []byte(`"template_profile":`), []byte(`"uid":0,"template_profile":`), 1),
		bytes.Replace(canonical, []byte(`"envelope":{`), []byte(`"envelope":{"path":"/var/run/docker.sock",`), 1),
		[]byte(strings.Repeat("x", MaxMemcachedUnixInstallSubmissionBytes+1)),
	} {
		if _, err := DecodeMemcachedUnixInstallSubmission(raw); err == nil {
			t.Fatal("noncanonical/ambiguous/private field injection accepted")
		}
	}
}
