package core

import (
	"context"
	"strings"
	"testing"
)

func TestMemcachedRestorationNeedsOriginalAuditedReservationNotRenewedGrant(t *testing.T) {
	for _, scenario := range []string{"revoked", "missing-audit", "wrong-seed", "committed", "needs-attention", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, actor.ID); err != nil {
				t.Fatal(err)
			}
			if s.CheckMemcachedUpdateMutation(context.Background(), seed) == nil {
				t.Fatal("revoked user obtained a NEW mutation grant")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "missing-audit":
				if _, err := s.DB.Exec(`DELETE FROM audit_logs WHERE action='app.memcached.update.reserve'`); err != nil {
					t.Fatal(err)
				}
			case "wrong-seed":
				seed.Dispatch.JobID = strings.Repeat("f", 32)
				seed.DispatchSHA256 = MemcachedUpdateDispatchSHA(seed.Dispatch)
				var err error
				seed, err = SealMemcachedUpdateRecord(seed)
				if err != nil {
					t.Fatal(err)
				}
			case "committed":
				if _, err := s.reconcileMemcachedUpdate(ctx, seed.Dispatch.RequestID, memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")); err != nil {
					t.Fatal(err)
				}
			case "needs-attention":
				if _, err := s.reconcileMemcachedUpdate(ctx, seed.Dispatch.RequestID, memcachedStoreChain(t, seed, "needs_attention")); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			}
			before := memcachedStoreCounts(t, s)
			err := s.CheckMemcachedUpdateRestoration(ctx, seed)
			if (err == nil) != (scenario == "revoked") {
				t.Fatal("wrong bounded original restoration condition", err)
			}
			if memcachedStoreCounts(t, s) != before {
				t.Fatal("SELECT-only condition changed requests/audits/receipts")
			}
		})
	}
}
