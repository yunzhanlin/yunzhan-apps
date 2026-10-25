package core

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestMemcachedUnixReservationAtomicallyRequiresCurrentHostGrantAndStableWebsite(t *testing.T) {
	for _, kind := range []string{"administrator", "running-site", "stopped-site", "provisioning-site", "attention-site", "archived-site", "missing-site", "operator", "actor-mismatch", "foreign-package", "old-package", "invalid-digest"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			actor := accessUser(t, s, "reserve-socket-owner", "admin", nil)
			in := registryInstallInput{}
			status := map[string]string{"running-site": "running", "stopped-site": "stopped", "provisioning-site": "provisioning", "attention-site": "needs_attention", "archived-site": "archived"}[kind]
			if status != "" || kind == "missing-site" {
				site := ID()
				in.Settings = map[string]any{"site_id": site}
				if status != "" {
					if _, e := s.DB.Exec(`INSERT INTO sites(id,name,slug,domain,status,created_at,updated_at)VALUES(?,?,?,?,?,?,?)`, site, "socket-owned", "socket-owned", "socket-owned.invalid", status, Now(), Now()); e != nil {
						t.Fatal(e)
					}
				}
			}
			op, e := registryMemcachedUnixRequest(memcachedUnixPackageFixture(), in, actor.ID, ID())
			if e != nil {
				t.Fatal(e)
			}
			item := appcatalog.CatalogItem{ID: "memcached", Version: appcatalog.MemcachedUnixVersion, SHA256: strings.Repeat("a", 64), Provider: "compose", Target: "memcached-cache"}
			switch kind {
			case "operator":
				s.DB.Exec(`UPDATE app_user_roles SET role='operator' WHERE user_id=?`, actor.ID)
			case "actor-mismatch":
				op.ActorID = ID()
			case "foreign-package":
				item.ID = "mongodb"
			case "old-package":
				item.Version = appcatalog.MemcachedDigestVersion
			case "invalid-digest":
				item.SHA256 = "unknown"
			}
			before := installReplayCounts(t, s)
			_, fresh, e := s.reserveRegistryCompose(item, "socket-reserve-case", actor, in, op)
			want := kind == "administrator" || kind == "running-site" || kind == "stopped-site"
			if (e == nil && fresh) != want {
				t.Fatal(kind, e, fresh)
			}
			if want {
				if s.CheckMemcachedUnixInstall(context.Background(), op) != nil {
					t.Fatal("original reservation cannot be independently revalidated")
				}
			} else if !reflect.DeepEqual(before, installReplayCounts(t, s)) {
				t.Fatal("declined grant left a job, pending receipt or audit")
			}
		})
	}
}
