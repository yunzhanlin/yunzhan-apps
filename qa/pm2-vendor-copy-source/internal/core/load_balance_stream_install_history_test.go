package core

import (
	"context"
	"strings"
	"testing"
)

func TestLoadBalanceStreamInstallAuthorityOriginalActiveIndexRemainsEnforced(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			s, _, job, _ := streamInstallFixture(t, action, true)
			before := streamInstallSnapshot(t, s)
			if _, err := s.DB.Exec("INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at)VALUES(?,'load-balance','software_configure','queued','{}',?,?,?)", ID(), ID(), Now(), Now()); err == nil {
				t.Fatal("original unique active-job index did not refuse competing work")
			}
			if _, err := s.LoadBalanceStreamInstallAuthority(context.Background(), job); err != nil || streamInstallSnapshot(t, s) != before {
				t.Fatal("constraint refusal changed original valid authority", err)
			}
		})
	}
}

func TestLoadBalanceStreamInstallAuthorityLostHistoryNeverBackfilled(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			s, _, job, _ := streamInstallFixture(t, action, true)
			if _, err := s.DB.Exec("DROP TABLE load_balance_stream_install_requests"); err != nil {
				t.Fatal(err)
			}
			if s.migrateLoadBalanceStreamInstallRequests() == nil {
				t.Fatal("lost original grant was backfilled from a job or version label")
			}
			if _, err := s.LoadBalanceStreamInstallAuthority(context.Background(), job); err == nil {
				t.Fatal("missing history authorized native effects")
			}
			var n int
			if s.DB.QueryRow("SELECT count(*)FROM sqlite_master WHERE tbl_name='load_balance_stream_install_requests'").Scan(&n) != nil || n != 0 {
				t.Fatal("failed migration created replacement history")
			}
		})
	}
}

func TestLoadBalanceStreamInstallAuthorityLegacyHTTPReceiptAllowsOnlyEmptyMigration(t *testing.T) {
	for _, version := range []string{"1.8.4", "1.8.5"} {
		t.Run(version, func(t *testing.T) {
			s := testStore(t)
			if _, err := s.DB.Exec("INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at)VALUES('load-balance','load-balance',?,?,'load-balance',?)", version, strings.Repeat("1", 64), Now()); err != nil {
				t.Fatal(err)
			}
			if err := s.migrateLoadBalanceStreamInstallRequests(); err != nil {
				t.Fatal("old HTTP receipt obstructed independent empty migration", err)
			}
			var n int
			if s.DB.QueryRow("SELECT count(*)FROM load_balance_stream_install_requests").Scan(&n) != nil || n != 0 {
				t.Fatal("legacy receipt fabricated a native grant")
			}
		})
	}
}
