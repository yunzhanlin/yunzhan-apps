package core

import (
	"context"
	"testing"

	"local/panel/internal/loadbalancestream"
)

// Published HTTP-only receipts remain usable by their original handlers but
// never opt into a newly added privileged transport after a panel upgrade.
func TestLoadBalanceStreamControlLegacyHTTPReceiptsNeverGainL4Authority(t *testing.T) {
	if loadbalancestream.AppVersion != "1.9.0" {
		t.Fatal("future stream version must remain independently selected")
	}
	for _, legacy := range []string{"1.8.4", "1.8.5"} {
		t.Run(legacy, func(t *testing.T) {
			s, _, op := streamControlFixture(t)
			if _, err := s.DB.Exec("UPDATE app_registry_receipts SET version=? WHERE app_id='load-balance'", legacy); err != nil {
				t.Fatal(err)
			}
			// The separate future migration may create an EMPTY store while an
			// old HTTP-only receipt is present. It must not infer prior L4 work.
			if _, err := s.DB.Exec("DROP TABLE load_balance_stream_controls"); err != nil {
				t.Fatal(err)
			}
			if err := s.migrateLoadBalanceStreamControls(); err != nil {
				t.Fatal("legacy HTTP receipt obstructed empty independent migration", err)
			}
			before := streamControlCounts(t, s)
			if _, fresh, err := s.reserveLoadBalanceStreamControl(context.Background(), op); err == nil || fresh {
				t.Fatal("legacy HTTP receipt granted a new stream reservation")
			}
			if fresh, err := s.issueLoadBalanceStreamControl(context.Background(), op); err == nil || fresh {
				t.Fatal("legacy HTTP receipt granted a native dispatch")
			}
			if s.CheckLoadBalanceStreamControl(context.Background(), op) == nil {
				t.Fatal("legacy HTTP receipt became native effect authority")
			}
			if streamControlCounts(t, s) != before || before != [3]int{} {
				t.Fatal("refusal fabricated requests, jobs or control audit rows")
			}
			var version string
			if s.DB.QueryRow("SELECT version FROM app_registry_receipts WHERE app_id='load-balance'").Scan(&version) != nil || version != legacy {
				t.Fatal("stream admission changed the original HTTP receipt")
			}
		})
	}
}
