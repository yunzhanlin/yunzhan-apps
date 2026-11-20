package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRabbitMQMigrationInputRequiresExactPreflightAndDowntimeConsent(t *testing.T) {
	valid := RabbitMQMigrationInput{
		SourceSHA256: strings.Repeat("a", 64), TargetManifestSHA256: strings.Repeat("b", 64),
		DowntimeAcknowledged: true,
	}
	raw, _ := json.Marshal(valid)
	if got, err := DecodeRabbitMQMigrationInput(raw); err != nil || got != valid {
		t.Fatalf("exact input failed: %v", err)
	}
	for _, mutation := range []string{
		strings.Replace(string(raw), ":true", ":false", 1),
		strings.Replace(string(raw), ":true", ":null", 1),
		strings.Replace(string(raw), "source_sha256", "Source_SHA256", 1),
		`{"downtime_acknowledged":true,` + string(raw)[1:],
		`{"project_id":"new",` + string(raw)[1:],
	} {
		if _, err := DecodeRabbitMQMigrationInput([]byte(mutation)); err == nil {
			t.Fatal("accepted inexact downtime confirmation or source identity")
		}
	}
}

func TestRabbitMQMigrationReservationRevokesStaleDispatchAndKeepsOriginalID(t *testing.T) {
	store := testStore(t)
	admin := accessUser(t, store, "rabbitmq-migration-admin", "admin", nil)
	viewer := accessUser(t, store, "rabbitmq-migration-viewer", "viewer", []string{"overview"})
	ctx := context.Background()
	project, request := ID(), ID()
	in := RabbitMQMigrationInput{strings.Repeat("a", 64), strings.Repeat("b", 64), true}
	if _, _, err := store.reserveRabbitMQMigration(ctx, viewer.ID, project, request, in); err == nil {
		t.Fatal("viewer reserved a host migration")
	}
	dispatch, fresh, err := store.reserveRabbitMQMigration(ctx, admin.ID, project, request, in)
	if err != nil || !fresh || store.VerifyRabbitMQMigrationDispatch(ctx, dispatch) != nil {
		t.Fatalf("original dispatch was not verified: %v", err)
	}
	retry, fresh, err := store.reserveRabbitMQMigration(ctx, admin.ID, project, request, in)
	if err != nil || fresh || retry != dispatch {
		t.Fatalf("idempotency lookup replaced the original job: %v", err)
	}
	if _, _, err := store.reserveRabbitMQMigration(ctx, admin.ID, project, ID(), in); err == nil {
		t.Fatal("second active migration for the project")
	}
	tampered := dispatch
	tampered.Input.SourceSHA256 = strings.Repeat("c", 64)
	if err := store.VerifyRabbitMQMigrationDispatch(ctx, tampered); err == nil {
		t.Fatal("native worker accepted a different plan")
	}
	if _, err := store.DB.Exec(`INSERT INTO app_user_menus(user_id,menu_ids,revision) VALUES(?,'null',2)
		ON CONFLICT(user_id) DO UPDATE SET revision=2`, admin.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyRabbitMQMigrationDispatch(ctx, dispatch); err == nil {
		t.Fatal("native worker accepted a superseded administrator permission revision")
	}
}
