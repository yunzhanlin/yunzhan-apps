package core

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func dailySavedCertificate(t *testing.T, store *Store, at time.Time, days int) Certificate {
	t.Helper()
	leaf, key, ca := certificateFixture(t, []string{"daily-cert.example.test"}, at.Add(-time.Hour), at.AddDate(0, 0, days), x509.ExtKeyUsageServerAuth)
	cert, err := store.SaveCertificate("owned daily expiry", leaf+ca, key, ID(), "owned-daily-fixture")
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestDailyCertificatesCountActualBoundedSavedLeafNotPrivateKeys(t *testing.T) {
	a, _ := dailyWorkerFixture(t, dailyWorkerInstalled(), false)
	at := time.Now()
	first := dailySavedCertificate(t, a.Store, at, 7)
	dailySavedCertificate(t, a.Store, at, 30)
	// Counting expiry must not decrypt key material. Deliberately unavailable
	// key decryption leaves the actual public certificate observation valid.
	if _, err := a.Store.DB.Exec(`UPDATE certificates SET key_cipher=? WHERE id=?`, []byte("owned unavailable encrypted key"), first.ID); err != nil {
		t.Fatal(err)
	}
	count, err := a.Store.dailyCertificatesDue(context.Background(), at)
	if err != nil || count != 1 {
		t.Fatal("actual saved leaf expiry not counted", count, err)
	}
	count, err = a.Store.dailyCertificatesDue(context.Background(), at.AddDate(0, 0, 8))
	if err != nil || count != 1 {
		t.Fatal("expired saved certificate was not counted", count, err)
	}
}

func TestDailyCertificatesDamagedMetadataAndMaterialDoNotBecomeZeroOrRepair(t *testing.T) {
	for _, kind := range []string{"duplicate", "oversized", "wrong-id", "wrong-expiry", "wrong-material"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := dailyWorkerFixture(t, dailyWorkerInstalled(), false)
			at := time.Now()
			cert := dailySavedCertificate(t, a.Store, at, 7)
			var raw, material string
			var cipher []byte
			a.Store.DB.QueryRow(`SELECT metadata,certificate_pem,key_cipher FROM certificates WHERE id=?`, cert.ID).Scan(&raw, &material, &cipher)
			var meta map[string]any
			if json.Unmarshal([]byte(raw), &meta) != nil {
				t.Fatal("own metadata")
			}
			switch kind {
			case "duplicate":
				raw = `{"id":"` + cert.ID + `","ID":"` + cert.ID + `"}`
			case "oversized":
				raw = strings.Repeat("x", 131073)
			case "wrong-id":
				meta["id"] = ID()
				b, _ := json.Marshal(meta)
				raw = string(b)
			case "wrong-expiry":
				meta["not_after"] = at.AddDate(0, 0, 30).UTC().Format(time.RFC3339)
				b, _ := json.Marshal(meta)
				raw = string(b)
			case "wrong-material":
				material += "\nowned material changed\n"
			}
			if _, err := a.Store.DB.Exec(`UPDATE certificates SET metadata=?,certificate_pem=? WHERE id=?`, raw, material, cert.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Store.dailyCertificatesDue(context.Background(), at); err == nil {
				t.Fatal("unverifiable inventory returned a normal count")
			}
			var retained, retainedMaterial string
			var retainedCipher []byte
			a.Store.DB.QueryRow(`SELECT metadata,certificate_pem,key_cipher FROM certificates WHERE id=?`, cert.ID).Scan(&retained, &retainedMaterial, &retainedCipher)
			if retained != raw || retainedMaterial != material || string(retainedCipher) != string(cipher) {
				t.Fatal("readonly expiry count repaired or changed certificate/key")
			}
		})
	}
}

func TestDailyCertificateSourceFailureSavesExplicitPartialReportAndNotification(t *testing.T) {
	a, _ := dailyWorkerFixture(t, dailyWorkerInstalled(), false)
	at := time.Now()
	cert := dailySavedCertificate(t, a.Store, at, 7)
	if _, err := a.Store.DB.Exec(`UPDATE certificates SET metadata='{' WHERE id=?`, cert.ID); err != nil {
		t.Fatal(err)
	}
	a.dailyWorkerTick(context.Background(), at)
	state := a.dailyWorkerSnapshot(at)
	_, report, err := readDailyReportRecord(context.Background(), a.Store.DB, at.In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01-02"))
	if err != nil || state.State != "saved_partial" || report["certificates_error"] == nil {
		t.Fatal("partial source failure hidden", state, err)
	}
	if _, exists := report["certificates_due_14_days"]; exists {
		t.Fatal("unverifiable certificates synthesized zero")
	}
	summary, err := outboundDailyReportSummary(state.ReportDay, report)
	if err != nil || summary.CountAvailable["certificates_due_14_days"] {
		t.Fatal("notification cert count falsely available", err)
	}
	a.dailyWorkerTick(context.Background(), at.Add(time.Minute))
	if a.dailyWorkerSnapshot(at.Add(time.Minute)).State != "saved_partial" {
		t.Fatal("re-read of partial snapshot became a complete observation")
	}
	var retained string
	a.Store.DB.QueryRow(`SELECT metadata FROM certificates WHERE id=?`, cert.ID).Scan(&retained)
	if retained != "{" {
		t.Fatal("background repaired original certificate")
	}
}

func TestDailyCertificateCountRespectsCancelledContext(t *testing.T) {
	a, _ := dailyWorkerFixture(t, dailyWorkerInstalled(), false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Store.dailyCertificatesDue(ctx, time.Now()); err == nil {
		t.Fatal("cancelled source was reported as zero saved certificates")
	}
}
