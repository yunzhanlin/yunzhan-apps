package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestLoadBalanceStreamInstallRecoveryPreservesOriginalRunningRow(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		for _, fault := range []string{"original", "payload-drift", "target-drift", "kind-drift"} {
			t.Run(action+"/"+fault, func(t *testing.T) {
				s, _, job, _ := streamInstallFixture(t, action, true)
				var err error
				switch fault {
				case "payload-drift":
					_, err = s.DB.Exec("UPDATE runtime_jobs SET payload='unparseable original bytes'WHERE id=?", job)
				case "target-drift":
					_, err = s.DB.Exec("UPDATE runtime_jobs SET target_id='other'WHERE id=?", job)
				case "kind-drift":
					_, err = s.DB.Exec("UPDATE runtime_jobs SET kind='software_configure'WHERE id=?", job)
				}
				if err != nil {
					t.Fatal(err)
				}
				before := streamInstallSnapshot(t, s)
				if err := s.Recover(); err != nil {
					t.Fatal(err)
				}
				if streamInstallSnapshot(t, s) != before {
					t.Fatal("restart changed or requeued original native install evidence")
				}
			})
		}
	}
}

func TestLoadBalanceStreamInstallRecoveryUnboundNativeIsNeverNewQueuedWork(t *testing.T) {
	for _, version := range []string{"1.8.5", "1.9.0"} {
		t.Run(version, func(t *testing.T) {
			s := testStore(t)
			job, key := ID(), ID()
			now := Now()
			payload := `{"settings":{},"version":"` + version + `"}`
			if _, err := s.DB.Exec("INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at)VALUES(?,'load-balance','software_install','running',?,?,?,?)", job, payload, key, now, now); err != nil {
				t.Fatal(err)
			}
			if err := s.Recover(); err != nil {
				t.Fatal(err)
			}
			var state, original, last string
			if err := s.DB.QueryRow("SELECT state,payload,updated_at FROM runtime_jobs WHERE id=?", job).Scan(&state, &original, &last); err != nil {
				t.Fatal(err)
			}
			want := "running"
			if version == "1.8.5" {
				want = "queued"
			}
			if state != want || original != payload || last != now {
				t.Fatal("old HTTP recovery contract changed or native label was reissued", version, state)
			}
		})
	}
}

func TestLoadBalanceStreamInstallRetryNeverResetsRetainedNativeAttempt(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		for _, state := range []string{"failed", "needs_attention"} {
			t.Run(action+"/"+state, func(t *testing.T) {
				s, _, job, _ := streamInstallFixture(t, action, true)
				if _, err := s.DB.Exec("UPDATE runtime_jobs SET state=?,error='retained original uncertainty'WHERE id=?", state, job); err != nil {
					t.Fatal(err)
				}
				before := streamInstallSnapshot(t, s)
				if err := s.RetryRuntime(job, "admin"); err == nil {
					t.Fatal("native original accepted replay")
				}
				if streamInstallSnapshot(t, s) != before {
					t.Fatal("retry refusal changed native original bytes or audits")
				}
			})
		}
	}
}

func TestLoadBalanceStreamInstallSubmissionClosedCanonicalWire(t *testing.T) {
	v := LoadBalanceStreamInstallSubmission{1, ID(), appcatalog.LoadBalanceStreamReleaseEnvelope{Catalog: []byte(`{"fixture":true}`), Signature: []byte("not-signed"), AppManifest: []byte(`{"fixture":true}`)}}
	raw, err := LoadBalanceStreamInstallSubmissionBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeLoadBalanceStreamInstallSubmission(raw); err != nil || got.JobID != v.JobID {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"duplicate":     []byte(strings.Replace(string(raw), `"format":1`, `"format":1,"format":1`, 1)),
		"alias":         []byte(strings.Replace(string(raw), `"format"`, `"Format"`, 1)),
		"escaped-alias": []byte(strings.Replace(string(raw), `"format"`, `"\u0066ormat"`, 1)),
		"unknown":       []byte(strings.Replace(string(raw), `"format":1`, `"retry":true,"format":1`, 1)),
		"bad-id":        []byte(strings.Replace(string(raw), v.JobID, "bad", 1)),
		"space":         append(append([]byte(nil), raw...), ' '),
		"two-values":    append(append([]byte(nil), raw...), raw...),
		"oversize":      []byte(strings.Repeat(" ", LoadBalanceStreamInstallSubmissionMaxBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLoadBalanceStreamInstallSubmission(bad); err == nil {
				t.Fatal("ambiguous native input normalized")
			}
		})
	}
	// A valid bounded wire is NOT signed authority or a current actor grant.
	if _, err := appcatalog.VerifyLoadBalanceStreamReleaseEnvelope(context.Background(), v.Release, "1.9.0", Hash(string(v.Release.AppManifest))); err == nil {
		t.Fatal("serialization fixture acquired signed release authority")
	}
	encoded, _ := json.Marshal(v)
	if string(encoded) != string(raw) {
		t.Fatal("wire encoding changed")
	}
}
