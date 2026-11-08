package core

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestMemcachedUnixBindingReadsExactOriginalManifestInsteadOfCallerGuess(t *testing.T) {
	s, actor, op, item := memcachedUnixStoreFixture(t)
	before := installReplayCounts(t, s)
	want := MemcachedUnixBinding{Version: item.Version, ManifestSHA256: item.SHA256}
	if value, err := s.MemcachedUnixInstallBinding(context.Background(), op); err != nil || value != want {
		t.Fatal("full original reservation identity lost", value, err)
	}
	if !reflect.DeepEqual(before, installReplayCounts(t, s)) {
		t.Fatal("identity read advanced original operation")
	}
	if value, err := s.MemcachedUnixOperationBinding(context.Background(), actor.ID, op, "start"); err == nil || value != (MemcachedUnixBinding{}) {
		t.Fatal("pending reservation manufactured an installed receipt")
	}
	if _, err := s.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at)VALUES('memcached',?,?,?,?,?)`, op.ProjectID, item.Version, item.SHA256, item.Target, Now()); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"start", "stop", "restart", "update", "delete"} {
		if value, err := s.MemcachedUnixOperationBinding(context.Background(), actor.ID, op, action); err != nil || value != want {
			t.Fatal("actual receipt identity lost", action, value, err)
		}
	}
	// A valid-looking hash is not equality with the independently signed
	// source. This API returns the actual fresh binding for Root to compare.
	changed := strings.Repeat("b", 64)
	for _, query := range []string{`UPDATE app_registry_install_requests SET sha256=?`, `UPDATE app_registry_pending SET sha256=?`, `UPDATE app_registry_receipts SET sha256=?`} {
		if _, err := s.DB.Exec(query, changed); err != nil {
			t.Fatal(err)
		}
	}
	for _, read := range []func() (MemcachedUnixBinding, error){
		func() (MemcachedUnixBinding, error) { return s.MemcachedUnixInstallBinding(context.Background(), op) },
		func() (MemcachedUnixBinding, error) {
			return s.MemcachedUnixOperationBinding(context.Background(), actor.ID, op, "start")
		},
	} {
		if value, err := read(); err != nil || value == want || value.ManifestSHA256 != changed {
			t.Fatal("current DB digest was replaced with a caller/old digest", value, err)
		}
	}
	if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='operator' WHERE user_id=?`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if value, err := s.MemcachedUnixInstallBinding(context.Background(), op); err == nil || value != (MemcachedUnixBinding{}) {
		t.Fatal("identity reader revived revoked install grant")
	}
	if value, err := s.MemcachedUnixOperationBinding(context.Background(), actor.ID, op, "stop"); err == nil || value != (MemcachedUnixBinding{}) {
		t.Fatal("identity reader revived revoked lifecycle grant")
	}
}
