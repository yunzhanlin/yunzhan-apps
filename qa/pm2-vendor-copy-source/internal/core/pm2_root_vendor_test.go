package core

import (
	"strings"
	"testing"
)

func TestPM2RootVendorUpdateUsesInstallWorkerOnlyForExactImplementedRevision(t *testing.T) {
	for _, row := range []struct {
		target, kind, payload string
		install               bool
	}{
		{"pm2-manager", "software_update", `{"version":"7.0.4-compat11","settings":null}`, true},
		{"pm2-manager", "software_update", `{"version":"7.0.4-compat10","settings":null}`, false},
		{"pm2-manager", "software_update", `{"version":"7.0.4-compat11.0"}`, false},
		{"pm2-manager", "software_configure", `{"version":"7.0.4-compat11"}`, false},
		{"daily-report", "software_update", `{"version":"7.0.4-compat11"}`, false},
		{"pm2-manager", "software_update", `{`, false},
		{"pm2-manager", "software_update", `{"version":"7.0.4-compat11","padding":"` + strings.Repeat("x", 4096) + `"}`, false},
	} {
		s := testStore(t)
		id, stamp := ID(), Now()
		if _, err := s.DB.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,?,?,'queued',?,?,?,?)`, id, row.target, row.kind, row.payload, ID(), stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if row.install {
			if j, err := s.nextRuntimeControlJob(); err == nil {
				t.Fatal("control worker claimed a fixed runtime build", j)
			}
			if j, err := s.nextRuntimeInstallJob(); err != nil || j.ID != id {
				t.Fatal("install worker lost fixed runtime build", j, err)
			}
		} else {
			if j, err := s.nextRuntimeInstallJob(); err == nil {
				t.Fatal("install worker borrowed an unrelated/aliased request", j, row)
			}
			if j, err := s.nextRuntimeControlJob(); err != nil || j.ID != id {
				t.Fatal("original control request changed queues", j, err, row)
			}
		}
	}
}
