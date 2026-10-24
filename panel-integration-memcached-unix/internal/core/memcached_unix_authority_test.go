package core

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func memcachedUnixStoreFixture(t *testing.T) (*Store, identity, DockerProjectRequest, appcatalog.CatalogItem) {
	t.Helper()
	s := testStore(t)
	actor := accessUser(t, s, "socket-owner", "admin", nil)
	m := memcachedUnixPackageFixture()
	m.Version = appcatalog.MemcachedUnixVersion
	m.RequiredPanelFeatures = []string{appcatalog.MemcachedDigestFeature, appcatalog.MemcachedUnixFeature}
	op, e := registryMemcachedUnixRequest(m, registryInstallInput{}, actor.ID, ID())
	if e != nil {
		t.Fatal(e)
	}
	item := appcatalog.CatalogItem{ID: "memcached", Version: appcatalog.MemcachedUnixVersion, SHA256: strings.Repeat("a", 64), Provider: "compose", Target: "memcached-cache"}
	if _, fresh, e := s.reserveRegistryCompose(item, "socket-fixed", actor, registryInstallInput{}, op); e != nil || !fresh {
		t.Fatal("normal immutable compose reservation", e)
	}
	return s, actor, op, item
}

func TestMemcachedUnixInstallAuthorityUsesRealBoundReservationAndReadOnlyFreshGrant(t *testing.T) {
	s, actor, op, _ := memcachedUnixStoreFixture(t)
	before := installReplayCounts(t, s)
	for i := 0; i < 2; i++ {
		if e := s.CheckMemcachedUnixInstall(context.Background(), op); e != nil {
			t.Fatal("original bound request refused", e)
		}
	}
	if !reflect.DeepEqual(before, installReplayCounts(t, s)) {
		t.Fatal("read-only authority enqueued/reconciled/advanced installation")
	}
	if _, e := s.DB.Exec(`UPDATE app_user_roles SET role='operator' WHERE user_id=?`, actor.ID); e != nil {
		t.Fatal(e)
	}
	if s.CheckMemcachedUnixInstall(context.Background(), op) == nil {
		t.Fatal("fresh revoked role was ignored")
	}
}

func TestMemcachedUnixInstallAuthorityRefusesChangedOriginalOrMissingPending(t *testing.T) {
	for _, name := range []string{"actor", "project", "job", "name", "site", "payload", "version", "digest", "pending", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			s, _, op, _ := memcachedUnixStoreFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "actor":
				op.ActorID = ID()
			case "project":
				op.ProjectID = ID()
			case "job":
				op.JobID = ID()
			case "name":
				op.Name = "different"
			case "site":
				op.SiteID = ID()
				op.Compose, _ = MemcachedUnixRequestCompose(op.ProjectID, op.SiteID)
			case "payload":
				s.DB.Exec(`UPDATE app_registry_install_requests SET job_payload_sha256=?`, strings.Repeat("b", 64))
			case "version":
				s.DB.Exec(`UPDATE app_registry_install_requests SET version='1.6.45-compat3'`)
			case "digest":
				s.DB.Exec(`UPDATE app_registry_install_requests SET sha256='invalid'`)
			case "pending":
				s.DB.Exec(`DELETE FROM app_registry_pending`)
			case "cancelled":
				cancel()
			}
			before := installReplayCounts(t, s)
			if s.CheckMemcachedUnixInstall(ctx, op) == nil {
				t.Fatal("changed or missing authority accepted", name)
			}
			if !reflect.DeepEqual(before, installReplayCounts(t, s)) {
				t.Fatal("authority refusal wrote or repaired state")
			}
		})
	}
}

func TestMemcachedUnixOperationRequiresActualReceiptAndOriginalComposeBinding(t *testing.T) {
	s, actor, op, item := memcachedUnixStoreFixture(t)
	if s.CheckMemcachedUnixOperation(context.Background(), actor.ID, op, "start") == nil {
		t.Fatal("reservation alone was treated as an installed app")
	}
	if _, e := s.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at)VALUES('memcached',?,?,?,?,?)`, op.ProjectID, item.Version, item.SHA256, item.Target, Now()); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"start", "stop", "restart", "update", "delete"} {
		if e := s.CheckMemcachedUnixOperation(context.Background(), actor.ID, op, action); e != nil {
			t.Fatal(action, e)
		}
	}
	if _, e := s.DB.Exec(`UPDATE app_registry_install_requests SET provider='runtime',runtime_job_id=NULL WHERE job_id=?`, op.JobID); e == nil {
		t.Fatal("SQLite closed provider invariant unexpectedly accepted inconsistent fixture")
	}
	if _, e := s.DB.Exec(`DELETE FROM app_registry_install_requests WHERE job_id=?`, op.JobID); e != nil {
		t.Fatal(e)
	}
	if s.CheckMemcachedUnixOperation(context.Background(), actor.ID, op, "start") == nil {
		t.Fatal("a label-only receipt borrowed original compose authority")
	}
}

func TestMemcachedUnixProducerSettingsCannotSupplyUIDPortOrForeignPath(t *testing.T) {
	m := memcachedUnixPackageFixture()
	m.Version = appcatalog.MemcachedUnixVersion
	m.RequiredPanelFeatures = []string{appcatalog.MemcachedDigestFeature, appcatalog.MemcachedUnixFeature}
	for _, in := range []registryInstallInput{{HostPort: 21216}, {Settings: map[string]any{"uid": 11211}}, {Settings: map[string]any{"site_id": "../other"}}, {Settings: map[string]any{"site_id": true}}, {Settings: map[string]any{"site_id": "", "path": "/run/docker.sock"}}} {
		if _, e := registryMemcachedUnixRequest(m, in, ID(), ID()); e == nil {
			t.Fatal("caller chose an account/path/port")
		}
	}
	op, e := registryMemcachedUnixRequest(m, registryInstallInput{Settings: map[string]any{"site_id": strings.Repeat("b", 32)}}, ID(), ID())
	if e != nil || op.ActorID == "" || op.SiteID == "" || op.TemplateProfile != MemcachedUnixProfile {
		t.Fatal("closed producer identity", e)
	}
	raw, _ := json.Marshal(op)
	if !strings.Contains(string(raw), `"actor_id"`) || !strings.Contains(string(raw), `"site_id"`) {
		t.Fatal("original payload failed to bind account/site")
	}
}

func memcachedUnixPackageFixture() appcatalog.Manifest {
	return appcatalog.Manifest{ID: "memcached", Version: appcatalog.MemcachedUnixVersion, Delivery: appcatalog.Delivery{Provider: "compose", Target: "memcached-cache", ManageRoute: "docker", Image: appcatalog.MemcachedDigestImage}, RequiredPanelFeatures: []string{appcatalog.MemcachedDigestFeature, appcatalog.MemcachedUnixFeature}}
}
