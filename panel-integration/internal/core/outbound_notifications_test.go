package core

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func outboundFixture(t *testing.T) (*Store, *Server) {
	t.Helper()
	s := testStore(t)
	s.encryptionKey = []byte(strings.Repeat("k", 32))
	return s, &Server{Store: s, accountSecretKey: s.encryptionKey}
}
func TestOutboundModuleCursorIsolationDeduplicationAndDailyPrivacy(t *testing.T) {
	s, a := outboundFixture(t)
	ids := map[string]string{"file-monitor": ID(), "files-sync": ID()}
	stage := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		module := r.URL.Query().Get("module")
		if stage == 1 && module == "file-monitor" {
			return &http.Response{StatusCode: 409, Body: io.NopCloser(strings.NewReader(`{"error":"damaged private ledger"}`)), Header: make(http.Header)}, nil
		}
		page := ModuleAlertPage{Cursor: 20, Events: []ModuleAlertEvent{}}
		if stage > 0 && (module == "file-monitor" || module == "files-sync") {
			page.Cursor = 21
			if r.URL.Query().Get("cursor") == "20" {
				page.Events = []ModuleAlertEvent{{Sequence: 21, ID: ids[module], Time: Now(), Outcome: "succeeded", Changes: 2, Conflicts: 1}}
			}
		}
		b, _ := json.Marshal(page)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
	})}}
	if e := a.collectModuleNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	channel := outboundCreate(t, s, "http://127.0.0.1:12345")
	stage = 1
	if e := a.collectModuleNotifications(context.Background()); e == nil {
		t.Fatal("broken source was hidden")
	}
	var count int
	_ = s.DB.QueryRow(`SELECT count(*) FROM notifications WHERE kind='sync'`).Scan(&count)
	if count != 1 {
		t.Fatal("unrelated source blocked working module", count)
	}
	stage = 2
	for i := 0; i < 2; i++ {
		if e := a.collectModuleNotifications(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM notifications WHERE kind='integrity'`).Scan(&count)
	if count != 1 {
		t.Fatal("module cursor skipped or duplicated", count)
	}
	_, e := s.DB.Exec(`INSERT INTO app_daily_reports VALUES('2026-10-07','{"sites":5,"running_sites":4,"certificates_due_14_days":2,"private_password":"do-not-forward","resources":{"cpu_percent":1.5,"memory_percent":40.0,"disk_percent":30.0,"hostname":"private-host"}}',?)`, Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = s.QueueDailyNotification("2026-10-07"); e != nil {
		t.Fatal(e)
	}
	if e = s.QueueOutboundNotifications(); e != nil {
		t.Fatal(e)
	}
	var payload string
	if e = s.DB.QueryRow(`SELECT payload FROM notification_deliveries WHERE channel_id=? AND payload LIKE '%"kind":"daily"%'`, channel.ID).Scan(&payload); e != nil {
		t.Fatal(e)
	}
	var message OutboundMessage
	if json.Unmarshal([]byte(payload), &message) != nil || message.Report == nil || message.Report.Sites != 5 || message.Report.Resources.CPU == nil || *message.Report.Resources.CPU != 1.5 || strings.Contains(payload, "private_password") || strings.Contains(payload, "private-host") || strings.Contains(payload, "do-not-forward") {
		t.Fatal(payload)
	}
}
func TestOutboundLiveExecutorDailyReport(t *testing.T) {
	socket := os.Getenv("PANEL_OUTBOUND_QA_SOCKET")
	if socket == "" {
		t.Skip("live Linux executor acceptance is explicitly opt-in")
	}
	if socket != "/run/panel-executor/control.sock" {
		t.Fatal("unrecognized isolated QA executor socket")
	}
	s, a := outboundFixture(t)
	a.Executor = NewExecutorClient(socket)
	var delivered *OutboundDailySummary
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var message OutboundMessage
		if json.Unmarshal(b, &message) != nil || message.Kind != "daily" || message.Report == nil {
			t.Error("missing daily summary", string(b))
		}
		if r.Header.Get("X-Yunzhan-Signature") != webhookSignature("fixture-signing-secret", r.Header.Get("X-Yunzhan-Delivery-ID"), r.Header.Get("X-Yunzhan-Timestamp"), b) {
			t.Error("invalid live summary signature")
		}
		delivered = message.Report
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	channel := outboundCreate(t, s, receiver.URL)
	if _, err := a.appDailyReport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.appDailyReport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	if err := a.dispatchOutbound(context.Background(), webhookHTTPClient()); err != nil {
		t.Fatal(err)
	}
	history, err := s.NotificationDeliveryHistory(channel.ID)
	if err != nil || len(history) != 1 || history[0]["state"] != "succeeded" || delivered == nil || delivered.Resources.Memory == nil || delivered.Resources.Disk == nil || *delivered.Resources.Memory < 0 || *delivered.Resources.Disk < 0 {
		t.Fatal("actual executor daily payload or dedup failed", history, err, delivered)
	}
}
func outboundCreate(t *testing.T, s *Store, url string) NotificationChannel {
	t.Helper()
	c, e := s.SaveNotificationChannel("", NotificationChannelInput{Name: "operations", URL: url, Secret: "fixture-signing-secret", Enabled: true, Kinds: outboundKinds})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func outboundEvent(t *testing.T, s *Store, kind string) string {
	t.Helper()
	id := ID()
	_, e := s.DB.Exec(`INSERT INTO notifications VALUES(?,?,?,'private-password raw-file-content','critical','qa',?,?,0)`, id, kind, "secret in title", id, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	return id
}

func TestOutboundActualHTTPRetryAfterSignatureAndRestart(t *testing.T) {
	s, a := outboundFixture(t)
	attempt := 0
	var deliveredID string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "private-password") || strings.Contains(string(b), "raw-file-content") || strings.Contains(string(b), "secret in title") {
			t.Error("source data leaked")
		}
		id, timestamp := r.Header.Get("X-Yunzhan-Delivery-ID"), r.Header.Get("X-Yunzhan-Timestamp")
		mac := hmac.New(sha256.New, []byte("fixture-signing-secret"))
		fmt.Fprintf(mac, "%s.%s.", timestamp, id)
		mac.Write(b)
		if r.Header.Get("X-Yunzhan-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Error("invalid signature")
		}
		if deliveredID != "" && deliveredID != id {
			t.Error("retry changed delivery identity")
		}
		deliveredID = id
		if attempt == 1 {
			w.Header().Set("Retry-After", "90")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	channel := outboundCreate(t, s, receiver.URL+"/private-path?access_token=private-query")
	event := outboundEvent(t, s, "sync")
	if e := s.QueueOutboundNotifications(); e != nil {
		t.Fatal(e)
	}
	if e := s.QueueOutboundNotifications(); e != nil {
		t.Fatal(e)
	}
	if e := a.dispatchOutbound(context.Background(), webhookHTTPClient()); e != nil {
		t.Fatal(e)
	}
	history, e := s.NotificationDeliveryHistory(channel.ID)
	if e != nil || len(history) != 1 || history[0]["state"] != "pending" || history[0]["event_id"] != event {
		t.Fatal(history, e)
	}
	var next int64
	if e = s.DB.QueryRow(`SELECT next_attempt_at FROM notification_deliveries`).Scan(&next); e != nil || next < time.Now().Unix()+85 {
		t.Fatal(next, e)
	}
	if e = a.dispatchOutbound(context.Background(), webhookHTTPClient()); e != nil || attempt != 1 {
		t.Fatal("retry ignored delay", e, attempt)
	}
	_, _ = s.DB.Exec(`UPDATE notification_deliveries SET next_attempt_at=0`)
	// A separately reopened store has the same encrypted key and durable queue.
	var path string
	if e = s.DB.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); e != nil {
		t.Fatal(e)
	}
	restarted, e := OpenStore(filepath.Clean(path))
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.DB.Close()
	restarted.encryptionKey = s.encryptionKey
	b := &Server{Store: restarted, accountSecretKey: s.encryptionKey}
	if e = b.dispatchOutbound(context.Background(), webhookHTTPClient()); e != nil {
		t.Fatal(e)
	}
	history, e = restarted.NotificationDeliveryHistory(channel.ID)
	if e != nil || history[0]["state"] != "succeeded" || history[0]["attempts"] != 2 || attempt != 2 {
		t.Fatal(history, e, attempt)
	}
	channels, e := s.NotificationChannels()
	raw, _ := json.Marshal(channels)
	if e != nil || strings.Contains(string(raw), "fixture-signing") || strings.Contains(string(raw), "private-path") || strings.Contains(string(raw), "private-query") {
		t.Fatal("channel read exposed credentials", string(raw), e)
	}
	var cipher []byte
	_ = s.DB.QueryRow(`SELECT credential FROM notification_channels`).Scan(&cipher)
	if strings.Contains(string(cipher), "fixture-signing") || strings.Contains(string(cipher), "private-query") {
		t.Fatal("unencrypted credentials")
	}
}
func TestOutboundNoticeRetentionNeverReusesWatermark(t *testing.T) {
	s, _ := outboundFixture(t)
	c := outboundCreate(t, s, "http://127.0.0.1:12345")
	first := outboundEvent(t, s, "sync")
	if err := s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("DELETE FROM notifications"); err != nil {
		t.Fatal(err)
	}
	var orders int
	_ = s.DB.QueryRow("SELECT count(*) FROM notification_event_order").Scan(&orders)
	if orders != 0 {
		t.Fatal("deleted notice index not reclaimed")
	}
	second := outboundEvent(t, s, "sync")
	if err := s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	history, err := s.NotificationDeliveryHistory(c.ID)
	if err != nil || len(history) != 2 || history[0]["event_id"] != second || history[1]["event_id"] != first {
		t.Fatal("post-retention notice lost", history, err)
	}
	var last int64
	_ = s.DB.QueryRow("SELECT last_sequence FROM notification_sequence WHERE id=1").Scan(&last)
	if last != 2 {
		t.Fatal("notice sequence restarted", last)
	}
	// Every startup re-runs idempotent migration. It must not assign the reused
	// SQLite rowid as a second sequence for an already indexed notification.
	if err = s.migrateOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	third := outboundEvent(t, s, "sync")
	if err = s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	history, err = s.NotificationDeliveryHistory(c.ID)
	if err != nil || len(history) != 3 || history[0]["event_id"] != third {
		t.Fatal("migration lost post-retention notice", history, err)
	}
}

func TestOutboundPauseRevisionLeaseAndDisabledHistory(t *testing.T) {
	s, _ := outboundFixture(t)
	old := outboundEvent(t, s, "monitor")
	c := outboundCreate(t, s, "http://127.0.0.1:21555/hooks")
	if e := s.QueueOutboundNotifications(); e != nil {
		t.Fatal(e)
	}
	h, _ := s.NotificationDeliveryHistory(c.ID)
	if len(h) != 0 {
		t.Fatal("replayed existing notices", old, h)
	}
	_ = outboundEvent(t, s, "sync")
	if e := s.QueueOutboundNotifications(); e != nil {
		t.Fatal(e)
	}
	d, e := s.claimOutbound(time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.claimOutbound(time.Now().Unix()); e == nil {
		t.Fatal("active lease stolen")
	}
	_, _ = s.DB.Exec(`UPDATE notification_deliveries SET lease_until=0`)
	retry, e := s.claimOutbound(time.Now().Unix())
	if e != nil || retry.ID != d.ID || retry.Attempts != 2 {
		t.Fatal(retry, e)
	}
	in := NotificationChannelInput{Name: c.Name, Enabled: false, Kinds: c.Kinds, Revision: c.Revision}
	updated, e := s.SaveNotificationChannel(c.ID, in)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.completeOutbound(retry, 204, "", 0, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	h, _ = s.NotificationDeliveryHistory(c.ID)
	if h[0]["state"] != "cancelled" {
		t.Fatal("old completion overwrote disabled state", h)
	}
	if _, e = s.SaveNotificationChannel(c.ID, in); e == nil {
		t.Fatal("accepted stale revision")
	}
	_ = outboundEvent(t, s, "sync")
	in.Enabled = true
	in.Revision = updated.Revision
	if _, e = s.SaveNotificationChannel(c.ID, in); e != nil {
		t.Fatal(e)
	}
	if e = s.QueueOutboundNotifications(); e != nil {
		t.Fatal(e)
	}
	h, _ = s.NotificationDeliveryHistory(c.ID)
	if len(h) != 1 {
		t.Fatal("replayed disabled events", h)
	}
}

func TestOutboundURLTLSRedirectLimitsAndNoSecretErrors(t *testing.T) {
	for _, raw := range []string{"http://example.com/hook", "https://user:secret@example.com/hook", "https://example.com/#x", "file:///tmp/x", "https://example.com:0/a"} {
		if _, e := validateWebhookURL(raw); e == nil {
			t.Fatal("invalid URL accepted", raw)
		}
	}
	s, a := outboundFixture(t)
	badTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer badTLS.Close()
	c := outboundCreate(t, s, badTLS.URL+"/private-token")
	_ = outboundEvent(t, s, "monitor")
	_ = s.QueueOutboundNotifications()
	if e := a.dispatchOutbound(context.Background(), webhookHTTPClient()); e != nil {
		t.Fatal(e)
	}
	h, _ := s.NotificationDeliveryHistory(c.ID)
	if h[0]["state"] != "pending" || strings.Contains(h[0]["error"].(string), "private-token") {
		t.Fatal("TLS failed open or leaked URL", h)
	}
	var second int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { second++; w.WriteHeader(200) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	c = outboundCreate(t, s, redirect.URL)
	_ = outboundEvent(t, s, "monitor")
	_ = s.QueueOutboundNotifications()
	if e := a.dispatchOutbound(context.Background(), webhookHTTPClient()); e != nil {
		t.Fatal(e)
	}
	h, _ = s.NotificationDeliveryHistory(c.ID)
	if second != 0 || len(h) != 1 || h[0]["state"] != "failed" {
		t.Fatal("followed redirect or retried permanent error", h, second)
	}
	var delivery string
	_ = s.DB.QueryRow(`SELECT id FROM notification_deliveries WHERE channel_id=?`, c.ID).Scan(&delivery)
	_, _ = s.DB.Exec(`UPDATE notification_deliveries SET state='running',attempts=6,lease_until=0 WHERE id=?`, delivery)
	_, _ = s.claimOutbound(time.Now().Unix())
	h, _ = s.NotificationDeliveryHistory(c.ID)
	if h[0]["state"] != "failed" {
		t.Fatal("exhausted lease retried forever", h)
	}
}

func TestOutboundQueueBackpressureDoesNotSkipCursorAndDailyOnce(t *testing.T) {
	s, _ := outboundFixture(t)
	c := outboundCreate(t, s, "http://127.0.0.1:21555/hooks")
	if e := s.QueueDailyNotification("2026-10-07"); e != nil {
		t.Fatal(e)
	}
	if e := s.QueueDailyNotification("2026-10-07"); e != nil {
		t.Fatal(e)
	}
	if e := s.QueueOutboundNotifications(); e != nil {
		t.Fatal(e)
	}
	h, _ := s.NotificationDeliveryHistory(c.ID)
	if len(h) != 1 {
		t.Fatal("duplicated daily notice", h)
	}
	tx, e := s.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 999; i++ {
		e = insertOutbound(tx, c.ID, c.Revision, OutboundMessage{EventID: ID(), Kind: "test"})
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	_ = outboundEvent(t, s, "sync")
	var before, after int64
	_ = s.DB.QueryRow(`SELECT watermark FROM notification_channels WHERE id=?`, c.ID).Scan(&before)
	if e = s.QueueOutboundNotifications(); e == nil {
		t.Fatal("unbounded pending queue")
	}
	_ = s.DB.QueryRow(`SELECT watermark FROM notification_channels WHERE id=?`, c.ID).Scan(&after)
	if before != after {
		t.Fatal("capacity silently skipped event")
	}
}
