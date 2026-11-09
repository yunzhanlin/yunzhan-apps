package core

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestMemcachedUnixGenericDockerCannotBorrowInstallationFields(t *testing.T) {
	base := DockerProjectRequest{JobID: ID(), ProjectID: ID(), Action: "create", Name: "own-generic", Compose: "services:\n  nginx:\n    image: nginx:1.28-alpine\n"}
	if ValidateDockerProject(base) != nil {
		t.Fatal("ordinary template compatibility changed")
	}
	for _, kind := range []string{"actor", "site", "unknown-profile", "profile-no-actor", "profile-generic", "lifecycle-profile", "lifecycle-actor", "request-sha"} {
		t.Run(kind, func(t *testing.T) {
			v := base
			switch kind {
			case "actor":
				v.ActorID = ID()
			case "site":
				v.SiteID = ID()
			case "unknown-profile":
				v.TemplateProfile = "foreign"
			case "profile-no-actor":
				v.TemplateProfile = MemcachedUnixProfile
			case "profile-generic":
				v.TemplateProfile = MemcachedUnixProfile
				v.ActorID = ID()
			case "lifecycle-profile":
				v.Action = "start"
				v.Name = ""
				v.Compose = ""
				v.TemplateProfile = MemcachedUnixProfile
				v.ActorID = ID()
			case "lifecycle-actor":
				v.Action = "stop"
				v.Name = ""
				v.Compose = ""
				v.ActorID = ID()
			case "request-sha":
				v.TemplateProfile = MemcachedUnixProfile
				v.ActorID = ID()
				v.RequestSHA = strings.Repeat("a", 64)
			}
			if ValidateDockerProject(v) == nil {
				t.Fatal("unbound generic route borrowed Unix scope")
			}
		})
	}
}

func TestMemcachedUnixOperationBindsOriginalFullPayloadAndCurrentGrantWithoutWrites(t *testing.T) {
	for _, kind := range []string{"valid", "site", "actor", "job", "project", "name", "compose", "profile", "receipt-version", "receipt-digest", "revoked", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, actor, op, item := memcachedUnixStoreFixture(t)
			if _, e := s.DB.Exec(`INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at)VALUES('memcached',?,?,?,?,?)`, op.ProjectID, item.Version, item.SHA256, item.Target, Now()); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "site":
				op.SiteID = ID()
				op.Compose, _ = MemcachedUnixRequestCompose(op.ProjectID, op.SiteID)
			case "actor":
				op.ActorID = ID()
			case "job":
				op.JobID = ID()
			case "project":
				op.ProjectID = ID()
				op.Compose, _ = MemcachedUnixRequestCompose(op.ProjectID, op.SiteID)
			case "name":
				op.Name = "borrowed-name"
			case "compose":
				op.Compose += "\n# changed"
			case "profile":
				op.TemplateProfile = ""
			case "receipt-version":
				s.DB.Exec(`UPDATE app_registry_receipts SET version='1.6.45-compat2'`)
			case "receipt-digest":
				s.DB.Exec(`UPDATE app_registry_receipts SET sha256=?`, strings.Repeat("e", 64))
			case "revoked":
				s.DB.Exec(`UPDATE app_user_roles SET role='operator' WHERE user_id=?`, actor.ID)
			case "cancelled":
				cancel()
			}
			before := installReplayCounts(t, s)
			e := s.CheckMemcachedUnixOperation(ctx, actor.ID, op, "start")
			if (kind == "valid") != (e == nil) {
				t.Fatal(kind, e)
			}
			if !reflect.DeepEqual(before, installReplayCounts(t, s)) {
				t.Fatal("scope observation mutated/repaired state")
			}
		})
	}
}
