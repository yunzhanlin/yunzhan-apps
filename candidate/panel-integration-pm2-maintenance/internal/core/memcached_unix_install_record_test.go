package core

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func memcachedUnixInstallChain(t *testing.T, site string) []MemcachedUnixInstallRecord {
	t.Helper()
	first, err := NewMemcachedUnixInstallRecord(memcachedUnixSubmissionFixture(t, site))
	if err != nil {
		t.Fatal(err)
	}
	out := []MemcachedUnixInstallRecord{first}
	for index, phase := range memcachedUnixInstallPhases[1:] {
		next := out[len(out)-1]
		next.Sequence, next.Phase = index+1, phase
		switch phase {
		case "account-verified":
			next.UID, next.GID = 999, 998
		case "image-verified":
			next.ImageID = "sha256:" + strings.Repeat("d", 64)
		case "project-intent":
			next.ComposeSHA256 = strings.Repeat("e", 64)
		case "runtime-verified":
			next.ContainerID = strings.Repeat("f", 64)
		}
		if err := ValidateMemcachedUnixInstallTransition(out[len(out)-1], next); err != nil {
			t.Fatal(phase, err)
		}
		out = append(out, next)
	}
	return out
}

func TestMemcachedUnixInstallRecordCanonicalCompleteChainAndFailures(t *testing.T) {
	for _, site := range []string{"", strings.Repeat("d", 32)} {
		t.Run("scope-"+site, func(t *testing.T) {
			chain := memcachedUnixInstallChain(t, site)
			for _, record := range chain {
				raw, _ := json.Marshal(record)
				got, err := DecodeMemcachedUnixInstallRecord(raw)
				if err != nil || got != record || record.Operation.SiteID != site {
					t.Fatal(record.Phase, err)
				}
				if _, err := DecodeMemcachedUpdateSubmission(raw); err == nil {
					t.Fatal("Unix event widened compat2 transfer")
				}
			}
			for _, record := range chain[:len(chain)-1] {
				for _, fault := range []string{"authority-unavailable", "account-unverified", "image-unverified", "project-unverified", "runtime-unverified", "interrupted"} {
					failed := record
					failed.Sequence++
					failed.Phase, failed.Fault = "needs-attention", fault
					if err := ValidateMemcachedUnixInstallTransition(record, failed); err != nil {
						t.Fatal(record.Phase, fault, err)
					}
					replayed := failed
					replayed.Sequence++
					if ValidateMemcachedUnixInstallTransition(failed, replayed) == nil {
						t.Fatal("uncertain original intent was replayable")
					}
				}
			}
			first := chain[0]
			refused := first
			refused.Phase, refused.Fault, refused.Sequence = "refused", "authority-unavailable", 1
			if ValidateMemcachedUnixInstallTransition(first, refused) != nil {
				t.Fatal("pre-effect refusal not expressible")
			}
		})
	}
}

func TestMemcachedUnixInstallRecordRejectsReboundIdentityAndInventedSuccess(t *testing.T) {
	chain := memcachedUnixInstallChain(t, "")
	for _, before := range chain[:len(chain)-1] {
		original := chain[before.Sequence+1]
		for _, change := range []struct {
			name, addedAt string
			apply         func(*MemcachedUnixInstallRecord)
		}{
			{"sequence", "", func(v *MemcachedUnixInstallRecord) { v.Sequence++ }},
			{"actor", "", func(v *MemcachedUnixInstallRecord) { v.Operation.ActorID = strings.Repeat("e", 32) }},
			{"job", "", func(v *MemcachedUnixInstallRecord) { v.Operation.JobID = strings.Repeat("e", 32) }},
			{"project", "", func(v *MemcachedUnixInstallRecord) { v.Operation.ProjectID = strings.Repeat("e", 32) }},
			{"site", "", func(v *MemcachedUnixInstallRecord) { v.Operation.SiteID = strings.Repeat("e", 32) }},
			{"manifest", "", func(v *MemcachedUnixInstallRecord) { v.Binding.ManifestSHA256 = strings.Repeat("e", 64) }},
			{"submission", "", func(v *MemcachedUnixInstallRecord) { v.SubmissionSHA256 = strings.Repeat("e", 64) }},
			{"catalog", "", func(v *MemcachedUnixInstallRecord) { v.CatalogSHA256 = strings.Repeat("e", 64) }},
			{"root-uid", "", func(v *MemcachedUnixInstallRecord) { v.UID = 0 }},
			{"new-uid", "account-verified", func(v *MemcachedUnixInstallRecord) { v.UID = 1000 }},
			{"root-gid", "", func(v *MemcachedUnixInstallRecord) { v.GID = 0 }},
			{"new-gid", "account-verified", func(v *MemcachedUnixInstallRecord) { v.GID = 1000 }},
			{"image", "image-verified", func(v *MemcachedUnixInstallRecord) { v.ImageID = "sha256:" + strings.Repeat("a", 64) }},
			{"compose", "project-intent", func(v *MemcachedUnixInstallRecord) { v.ComposeSHA256 = strings.Repeat("a", 64) }},
			{"container", "runtime-verified", func(v *MemcachedUnixInstallRecord) { v.ContainerID = strings.Repeat("a", 64) }},
		} {
			next := original
			change.apply(&next)
			if next == original {
				continue
			}
			// A newly introduced identity is framing data, NOT proof. The
			// worker must independently verify it at exactly this phase.
			allowedAddition := change.addedAt != "" && next.Phase == change.addedAt
			if accepted := ValidateMemcachedUnixInstallTransition(before, next) == nil; accepted != allowedAddition {
				t.Fatal("identity phase mismatch", before.Phase, change.name, accepted)
			}
		}
		failed := before
		failed.Phase, failed.Fault, failed.Sequence = "needs-attention", "interrupted", before.Sequence+1
		failed.UID, failed.GID = 123, 124
		if failed.UID != before.UID && ValidateMemcachedUnixInstallTransition(before, failed) == nil {
			t.Fatal("failed event synthesized a verified account")
		}
	}
	last := chain[len(chain)-1]
	for _, phase := range []string{"needs-attention", "refused", "prepared", "committed"} {
		next := last
		next.Sequence++
		next.Phase, next.Fault = phase, "interrupted"
		if ValidateMemcachedUnixInstallTransition(last, next) == nil {
			t.Fatal("committed chain was mutable")
		}
	}
}

func TestMemcachedUnixInstallRecordRejectsMalformedOrPrivateFields(t *testing.T) {
	chain := memcachedUnixInstallChain(t, "")
	raw, _ := json.Marshal(chain[0])
	for _, body := range [][]byte{
		nil, []byte("null"), []byte("{}"), []byte("[]"),
		append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), raw...),
		bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1),
		bytes.Replace(raw, []byte(`"sequence":`), []byte(`"Sequence":`), 1),
		bytes.Replace(raw, []byte(`"uid":0`), []byte(`"uid":0,"path":"/tmp/socket"`), 1),
		bytes.Replace(raw, []byte(`"uid":0`), []byte(`"uid":-1`), 1),
		bytes.Replace(raw, []byte(`"phase":"prepared"`), []byte(`"phase":"committed"`), 1),
		bytes.Replace(raw, []byte(`"fault":""`), []byte(`"fault":"an arbitrary secret-bearing diagnostic"`), 1),
		[]byte(strings.Repeat("x", MaxMemcachedUnixInstallRecordBytes+1)),
	} {
		if _, err := DecodeMemcachedUnixInstallRecord(body); err == nil {
			t.Fatal("ambiguous/over-limit/authority injection accepted")
		}
	}
}
