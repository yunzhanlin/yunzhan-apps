package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOutboundDeliverySummaryClosedSubtypesReconstructPrivateText(t *testing.T) {
	for _, c := range []struct{ kind, source, severity string }{
		{"load-balance-traffic", "app:load-balance-traffic-pending", "critical"},
		{"load-balance-traffic", "app:load-balance-traffic-committed", "info"},
		{"load-balance-traffic", "app:load-balance-traffic-recovered", "warning"},
		{"load-balance-traffic", "app:load-balance-worker", "info"},
		{"load-balance-source", "app:load-balance-source-unavailable", "critical"},
		{"load-balance-source", "app:load-balance-source-ready", "info"},
		{"sync", "app:files-sync", "warning"},
		{"test", "", "info"},
	} {
		m := safeOutboundMessage(Notification{ID: ID(), Kind: c.kind, Source: c.source, Severity: c.severity, CreatedAt: time.Now().Unix()})
		original := m
		m.Title, m.Message, m.Test = "owned-private-title", "owned-private-task-output", true
		raw, _ := json.Marshal(m)
		got, e := outboundDeliverySummary(string(raw), m.EventID)
		if e != nil || got.Title != original.Title || got.Message != original.Message || got.EventType != original.EventType || !got.Test || strings.Contains(got.Title+got.Message, "owned-private") {
			t.Fatal(got, e)
		}
	}
}
func TestOutboundWebhookRebuildsClosedSavedSummaryAndRefusesCorruptionWithoutRequest(t *testing.T) {
	s, a := outboundFixture(t)
	requests := 0
	r := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		b, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		if len(b) > 4096 || strings.Contains(string(b), "owned-private") || r.Header.Get("X-Yunzhan-Signature") != webhookSignature("fixture-signing-secret", r.Header.Get("X-Yunzhan-Delivery-ID"), r.Header.Get("X-Yunzhan-Timestamp"), b) {
			t.Error("private data, invalid HMAC or unbounded body")
		}
		var m OutboundMessage
		if json.Unmarshal(b, &m) != nil || m.Title != "负载均衡告警来源重新可核对" || m.EventType != "source_ready" {
			t.Error("closed source type not retained")
		}
		w.WriteHeader(204)
	}))
	defer r.Close()
	c := outboundCreate(t, s, r.URL)
	m := safeOutboundMessage(Notification{ID: ID(), Kind: "load-balance-source", Source: "app:load-balance-source-ready", Severity: "info", CreatedAt: time.Now().Unix()})
	m.Title, m.Message = "owned-private-title", "owned-private-output"
	b, _ := json.Marshal(m)
	d := outboundDelivery{ID: ID(), ChannelID: c.ID, Payload: string(b)}
	if e := s.DB.QueryRow(`SELECT credential FROM notification_channels WHERE id=?`, c.ID).Scan(&d.Cipher); e != nil {
		t.Fatal(e)
	}
	if code, message, _ := a.sendOutbound(context.Background(), webhookHTTPClient(), d); code != 204 || message != "" || requests != 1 || d.Payload != string(b) {
		t.Fatal("fixed summary did not preserve original saved evidence", code, message)
	}
	for _, bad := range []string{strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"secret":"owned-private"`, 1), strings.Replace(string(b), `"info"`, `"critical"`, 1), "{}"} {
		d.Payload = bad
		if code, _, _ := a.sendOutbound(context.Background(), webhookHTTPClient(), d); code != 400 || requests != 1 || d.Payload != bad {
			t.Fatal("malformed saved payload sent or evidence mutated", code)
		}
	}
}
func TestOutboundDeliverySummaryRejectsUnknownDuplicateWrongIdentityAndOversize(t *testing.T) {
	m := safeOutboundMessage(Notification{ID: ID(), Kind: "load-balance-source", Source: "app:load-balance-source-ready", Severity: "info", CreatedAt: time.Now().Unix()})
	b, _ := json.Marshal(m)
	valid := string(b)
	for _, bad := range []string{strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"SCHEMA_VERSION":1`, 1), strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"password":"owned-private"`, 1), strings.Replace(valid, `"source_ready"`, `"traffic_pending"`, 1), strings.Replace(valid, `"info"`, `"owned-private-severity"`, 1), strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1), valid + `{}`, "null", "{}", strings.Repeat("x", 4097)} {
		if _, e := outboundDeliverySummary(bad, m.EventID); e == nil {
			t.Fatal("unverifiable saved payload accepted", bad)
		}
	}
	if _, e := outboundDeliverySummary(valid, ID()); e == nil {
		t.Fatal("payload identity differs from retained row")
	}
}
func TestOutboundDeliveryHistoryNoPartialPagePreservesOriginalEvidence(t *testing.T) {
	s, _ := outboundFixture(t)
	c := outboundCreate(t, s, "http://127.0.0.1:12345")
	var payloads []string
	for i := 0; i < 2; i++ {
		m := safeOutboundMessage(Notification{ID: ID(), Kind: "sync", Severity: "warning", CreatedAt: time.Now().Unix()})
		m.Title, m.Message = "owned-private-title", "owned-private-output"
		b, _ := json.Marshal(m)
		if i == 0 {
			b = []byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"private":"owned-private"`, 1))
		}
		payloads = append(payloads, string(b))
		_, e := s.DB.Exec(`INSERT INTO notification_deliveries(id,channel_id,channel_revision,event_id,payload,state,created_at) VALUES(?,?,?,?,?,'succeeded',?)`, ID(), c.ID, c.Revision, m.EventID, string(b), time.Now().Unix())
		if e != nil {
			t.Fatal(e)
		}
	}
	if rows, e := s.NotificationDeliveryHistory(c.ID); e == nil || rows != nil {
		t.Fatal("damaged second row yielded healthy partial history", rows, e)
	}
	rows, e := s.DB.Query(`SELECT payload FROM notification_deliveries WHERE channel_id=? ORDER BY rowid`, c.ID)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var original string
		if e := rows.Scan(&original); e != nil || i >= len(payloads) || original != payloads[i] {
			t.Fatal("original evidence mutated", e)
		}
		i++
	}
	if i != 2 || rows.Err() != nil {
		t.Fatal("original row disappeared")
	}
}
func TestOutboundSourceRealTLSClosedSummaryAndUnknownExtensionRefusedBeforeAuth(t *testing.T) {
	for _, state := range []string{"unavailable", "ready"} {
		t.Run(state, func(t *testing.T) {
			r, input := smtpReceiver(t, "tls", "mail.example.test", false, func(r *smtpTestReceiver) { r.dropAfterAcceptance = true })
			severity := "critical"
			if state == "ready" {
				severity = "info"
			}
			m := safeOutboundMessage(Notification{ID: ID(), Kind: "load-balance-source", Source: "app:load-balance-source-" + state, Severity: severity, CreatedAt: time.Now().Unix()})
			m.Title, m.Message = "owned-private-title", "owned-private-error"
			b, _ := json.Marshal(m)
			d := outboundDelivery{ID: ID(), Payload: strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"secret":"owned-private"`, 1)}
			if code, _, _ := sendSMTPNotification(context.Background(), d, &input); code != 550 {
				t.Fatal("unknown extension sent")
			}
			r.mu.Lock()
			if r.authAttempts != 0 || r.dataAttempts != 0 {
				t.Error("refusal happened after credential or data transmission")
			}
			r.mu.Unlock()
			d.Payload = string(b)
			if code, message, _ := sendSMTPNotification(context.Background(), d, &input); code != 250 || message != "" {
				t.Fatal(code, message)
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			if len(r.messages) != 1 || strings.Contains(r.messages[0], "owned-private") {
				t.Fatal("private source leaked")
			}
			_, body := smtpParsedBody(t, r.messages[0])
			if strings.Contains(body, "owned-private") || !strings.Contains(body, "不代表") && !strings.Contains(body, "不是网站或节点故障结论") {
				t.Fatal(body)
			}
		})
	}
}
