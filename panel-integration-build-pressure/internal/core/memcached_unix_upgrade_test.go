package core

import (
	"context"
	"reflect"
	"testing"
)

func TestMemcachedUnixUpgradeOriginalUndeliveredReservationStaysWorkAfterRevoke(t *testing.T) {
	s, actor, _, _ := memcachedUnixStoreFixture(t)
	before := installReplayCounts(t, s)
	if s.CheckMemcachedUnixInstallUpgrade(context.Background()) == nil {
		t.Fatal("undelivered original install reservation appeared quiescent")
	}
	if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='operator' WHERE user_id=?`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if s.CheckMemcachedUnixInstallUpgrade(context.Background()) == nil {
		t.Fatal("revoking actor erased pending original work")
	}
	if !reflect.DeepEqual(before, installReplayCounts(t, s)) {
		t.Fatal("read-only queue fence reconciled/deleted/resubmitted a job")
	}
}

func TestMemcachedUnixUpgradeEmptyQueueDoesNotBorrowLegacyOrIgnoreCancellation(t *testing.T) {
	s := testStore(t)
	if err := s.CheckMemcachedUnixInstallUpgrade(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.CheckMemcachedUnixInstallUpgrade(ctx) == nil || s.CheckMemcachedUnixInstallUpgrade(nil) == nil || (*Store)(nil).CheckMemcachedUnixInstallUpgrade(context.Background()) == nil {
		t.Fatal("invalid admission context/store accepted")
	}
	// This fixed new version cannot be hidden behind an old/malformed provider.
	if _, err := s.DB.Exec(`INSERT INTO app_registry_pending(job_id,app_id,scope,version,sha256,target,provider,created_at) VALUES('original','memcached','scope','1.6.45-compat4','digest','memcached-cache','foreign','now')`); err != nil {
		t.Fatal(err)
	}
	if s.CheckMemcachedUnixInstallUpgrade(context.Background()) == nil {
		t.Fatal("orphan/malformed original new-profile reservation ignored")
	}
}
