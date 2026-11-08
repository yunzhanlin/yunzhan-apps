package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func lbTrafficFixture(t *testing.T) (*Store, *Server, *LoadBalanceTrafficFeed) {
	t.Helper()
	s, a := outboundFixture(t)
	f := &LoadBalanceTrafficFeed{SchemaVersion: 1, Available: true, Records: []LoadBalanceTrafficRecord{}, WorkerState: "clear", WorkerCheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/load-balance-traffic-alert-events" || r.URL.RawQuery != "" {
			t.Error("traffic collection mutated or accepted targets")
		}
		b, _ := json.Marshal(f)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b))}, nil
	})}}
	return s, a, f
}
func lbTrafficRecord(state string) LoadBalanceTrafficRecord {
	return LoadBalanceTrafficRecord{ID: ID(), EntryID: ID(), State: state, CreatedAt: Now()}
}
func lbTrafficCollect(t *testing.T, a *Server) {
	t.Helper()
	if e := a.collectLoadBalanceTrafficNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func lbTrafficCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if e := s.DB.QueryRow("SELECT count(*) FROM notifications WHERE kind='load-balance-traffic'").Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func lbTrafficCursorCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if e := s.DB.QueryRow("SELECT count(*) FROM load_balance_traffic_cursors").Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestOutboundTrafficInitialCompletedBaselineButCurrentPendingAlwaysWarns(t *testing.T) {
	s, a, f := lbTrafficFixture(t)
	f.Records = []LoadBalanceTrafficRecord{lbTrafficRecord("committed"), lbTrafficRecord("recovered"), lbTrafficRecord("pending")}
	lbTrafficCollect(t, a)
	lbTrafficCollect(t, a)
	if lbTrafficCount(t, s) != 1 || lbTrafficCursorCount(t, s) != 3 {
		t.Fatal("historical backfill or missing current pending")
	}
	var source, severity string
	if e := s.DB.QueryRow("SELECT source,severity FROM notifications WHERE kind='load-balance-traffic'").Scan(&source, &severity); e != nil || source != "app:load-balance-traffic-pending" || severity != "critical" {
		t.Fatal(source, severity, e)
	}
}
func TestOutboundTrafficActualHMACOnlyExplicitNewScopeAndFixedSummaries(t *testing.T) {
	s, a, f := lbTrafficFixture(t)
	lbTrafficCollect(t, a)
	var messages []OutboundMessage
	r := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		if len(b) > 4096 || r.Header.Get("X-Yunzhan-Signature") != webhookSignature("traffic-fixture-secret", r.Header.Get("X-Yunzhan-Delivery-ID"), r.Header.Get("X-Yunzhan-Timestamp"), b) {
			t.Error("invalid bounded HMAC")
		}
		var m OutboundMessage
		if json.Unmarshal(b, &m) != nil || m.Kind != "load-balance-traffic" {
			t.Error("wrong scope")
		}
		for _, private := range []string{f.Records[0].ID, f.Records[0].EntryID, "traffic-fixture-secret", "domain", "ca_pem", "raw-error"} {
			if strings.Contains(string(b), private) {
				t.Error("source information leaked")
			}
		}
		messages = append(messages, m)
		w.WriteHeader(204)
	}))
	defer r.Close()
	_, e := s.SaveNotificationChannel("", NotificationChannelInput{Name: "traffic only", URL: r.URL, Secret: "traffic-fixture-secret", Enabled: true, Kinds: []string{"load-balance-traffic"}})
	if e != nil {
		t.Fatal(e)
	}
	old, e := s.SaveNotificationChannel("", NotificationChannelInput{Name: "health remains health only", URL: r.URL, Secret: "traffic-fixture-secret", Enabled: true, Kinds: []string{"load-balance"}})
	if e != nil {
		t.Fatal(e)
	}
	f.Records = []LoadBalanceTrafficRecord{lbTrafficRecord("pending")}
	lbTrafficCollect(t, a)
	f.Records[0].State = "committed"
	lbTrafficCollect(t, a)
	if e = s.QueueOutboundNotifications(); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = a.dispatchOutbound(context.Background(), webhookHTTPClient()); e != nil {
			t.Fatal(e)
		}
	}
	if len(messages) != 2 || messages[0].Severity != "critical" || messages[1].Title != "负载均衡切流事务已提交" || !strings.Contains(messages[1].Message, "不代表当前所有节点或业务已恢复") {
		t.Fatal(messages)
	}
	history, e := s.NotificationDeliveryHistory(old.ID)
	if e != nil || len(history) != 0 {
		t.Fatal("health-only scope expanded", e)
	}
}
func TestOutboundTrafficCommitRecoveryAndRestartHaveStableOriginalIdentity(t *testing.T) {
	s, a, f := lbTrafficFixture(t)
	lbTrafficCollect(t, a)
	f.Records = []LoadBalanceTrafficRecord{lbTrafficRecord("pending"), lbTrafficRecord("pending")}
	lbTrafficCollect(t, a)
	f.Records[0].State = "committed"
	f.Records[1].State = "recovered"
	lbTrafficCollect(t, a)
	fresh := &Server{Store: s, Executor: a.Executor}
	lbTrafficCollect(t, fresh)
	if lbTrafficCount(t, s) != 4 || lbTrafficCursorCount(t, s) != 2 {
		t.Fatal("restart or archive presentation duplicated records")
	}
	m := safeOutboundMessage(Notification{Kind: "load-balance-traffic", Source: "app:load-balance-traffic-recovered", Severity: "warning"})
	if !strings.Contains(m.Message, "不代表故障已修复") {
		t.Fatal(m)
	}
}
func TestOutboundTrafficMalformedInventoryAndClockNeverReplaceOriginalState(t *testing.T) {
	s, a, f := lbTrafficFixture(t)
	f.Records = []LoadBalanceTrafficRecord{lbTrafficRecord("committed")}
	lbTrafficCollect(t, a)
	original, _ := json.Marshal(f)
	bad := []func(*LoadBalanceTrafficFeed){func(f *LoadBalanceTrafficFeed) { f.SchemaVersion = 0 }, func(f *LoadBalanceTrafficFeed) { f.Records = nil }, func(f *LoadBalanceTrafficFeed) { f.Available = false }, func(f *LoadBalanceTrafficFeed) { f.Records = append(f.Records, f.Records[0]) }, func(f *LoadBalanceTrafficFeed) { f.Records[0].EntryID = "domain.example.test" }, func(f *LoadBalanceTrafficFeed) { f.Records[0].State = "healthy" }, func(f *LoadBalanceTrafficFeed) {
		f.Records[0].CreatedAt = time.Now().Add(time.Hour).Format(time.RFC3339)
	}, func(f *LoadBalanceTrafficFeed) { f.WorkerState = "healthy" }, func(f *LoadBalanceTrafficFeed) {
		f.WorkerCheckedAt = time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	}, func(f *LoadBalanceTrafficFeed) { f.WorkerState = "unknown" }, func(f *LoadBalanceTrafficFeed) { f.Records = make([]LoadBalanceTrafficRecord, 2561) }}
	for i, mutate := range bad {
		json.Unmarshal(original, f)
		mutate(f)
		if a.collectLoadBalanceTrafficNotifications(context.Background()) == nil {
			t.Fatal("invalid feed accepted", i)
		}
		if lbTrafficCount(t, s) != 0 || lbTrafficCursorCount(t, s) != 1 {
			t.Fatal("rejection changed state", i)
		}
	}
}
func TestOutboundTrafficRollbackMissingHistoryAndTerminalRegressionAreAtomic(t *testing.T) {
	s, a, f := lbTrafficFixture(t)
	f.Records = []LoadBalanceTrafficRecord{lbTrafficRecord("committed")}
	lbTrafficCollect(t, a)
	old := f.Records[0]
	for _, change := range []func(*LoadBalanceTrafficRecord){func(r *LoadBalanceTrafficRecord) { r.State = "pending" }, func(r *LoadBalanceTrafficRecord) { r.State = "recovered" }, func(r *LoadBalanceTrafficRecord) { r.EntryID = ID() }, func(r *LoadBalanceTrafficRecord) { r.CreatedAt = time.Now().Add(-time.Hour).Format(time.RFC3339) }} {
		modified := old
		change(&modified)
		f.Records = []LoadBalanceTrafficRecord{lbTrafficRecord("pending"), modified}
		if a.collectLoadBalanceTrafficNotifications(context.Background()) == nil {
			t.Fatal("original identity changed")
		}
		if lbTrafficCount(t, s) != 0 || lbTrafficCursorCount(t, s) != 1 {
			t.Fatal("part of rejected batch committed")
		}
	}
	f.Records = []LoadBalanceTrafficRecord{lbTrafficRecord("pending")}
	if a.collectLoadBalanceTrafficNotifications(context.Background()) == nil {
		t.Fatal("missing original history hidden")
	}
	if lbTrafficCount(t, s) != 0 || lbTrafficCursorCount(t, s) != 1 {
		t.Fatal("missing-history failure committed")
	}
}
func TestOutboundTrafficSQLFailureKeepsEveryCursorAndWorkerTransition(t *testing.T) {
	s, a, f := lbTrafficFixture(t)
	lbTrafficCollect(t, a)
	f.Records = []LoadBalanceTrafficRecord{lbTrafficRecord("pending")}
	f.WorkerState = "error"
	if _, e := s.DB.Exec("CREATE TRIGGER reject_traffic_worker BEFORE INSERT ON notifications WHEN NEW.source='app:load-balance-worker' BEGIN SELECT RAISE(ABORT,'owned fixture SQL interruption'); END"); e != nil {
		t.Fatal(e)
	}
	if a.collectLoadBalanceTrafficNotifications(context.Background()) == nil {
		t.Fatal("partial SQL commit accepted")
	}
	if lbTrafficCount(t, s) != 0 || lbTrafficCursorCount(t, s) != 0 {
		t.Fatal("records published before failed worker notice")
	}
	s.DB.Exec("DROP TRIGGER reject_traffic_worker")
	lbTrafficCollect(t, a)
	if lbTrafficCount(t, s) != 2 {
		t.Fatal("original events lost")
	}
}
func TestOutboundTrafficNoticeCapacityPreservesOriginalCursorAndNativeIndependence(t *testing.T) {
	s, a, f := lbTrafficFixture(t)
	lbTrafficCollect(t, a)
	_, e := s.DB.Exec(`WITH RECURSIVE n(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM n WHERE v<10000) INSERT INTO notifications(id,kind,title,message,severity,source,source_id,created_at) SELECT lower(hex(randomblob(16))),'load-balance-traffic','fixture','fixture','info','fixture:traffic-capacity',cast(v AS text),0 FROM n`)
	if e != nil {
		t.Fatal(e)
	}
	f.Records = []LoadBalanceTrafficRecord{lbTrafficRecord("committed")}
	if a.collectLoadBalanceTrafficNotifications(context.Background()) == nil {
		t.Fatal("unbounded traffic notices")
	}
	if lbTrafficCursorCount(t, s) != 0 || lbTrafficCount(t, s) != 10000 {
		t.Fatal("capacity advanced original cursor")
	}
}
func TestOutboundTrafficWorkerUnknownRestartIsNotRecoveryOrRepeatedError(t *testing.T) {
	s, a, f := lbTrafficFixture(t)
	lbTrafficCollect(t, a)
	f.WorkerState = "error"
	lbTrafficCollect(t, a)
	lbTrafficCollect(t, a)
	f.WorkerState, f.WorkerCheckedAt = "unknown", ""
	fresh := &Server{Store: s, Executor: a.Executor}
	lbTrafficCollect(t, fresh)
	f.WorkerState, f.WorkerCheckedAt = "error", time.Now().UTC().Format(time.RFC3339Nano)
	lbTrafficCollect(t, fresh)
	if lbTrafficCount(t, s) != 1 {
		t.Fatal("unknown restart cleared or duplicated error")
	}
	f.WorkerState = "clear"
	lbTrafficCollect(t, fresh)
	if lbTrafficCount(t, s) != 2 {
		t.Fatal("actual new completed cycle not distinguished")
	}
	f.WorkerState, f.WorkerCheckedAt = "stale", time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	if a.collectLoadBalanceTrafficNotifications(context.Background()) == nil {
		t.Fatal("clock rollback accepted")
	}
	f.WorkerState, f.WorkerCheckedAt = "clear", time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
	lbTrafficCollect(t, fresh)
	if lbTrafficCount(t, s) != 2 {
		t.Fatal("same clear state duplicated")
	}
}

func TestOutboundTrafficSMTPRealTLSKeepsClosedSubtypeAndScrubsOriginalText(t *testing.T) {
	for _, c := range []struct{ source, severity, phrase string }{
		{"app:load-balance-traffic-committed", "info", "不代表当前所有节点或业务已恢复"},
		{"app:load-balance-traffic-recovered", "warning", "不代表故障已修复"},
		{"app:load-balance-traffic-pending", "critical", "不将未知结果当作成功"},
		{"app:load-balance-worker", "critical", "这是采样状态"},
		{"app:load-balance-worker", "info", "不代表所有节点或业务健康"},
	} {
		t.Run(c.source+"/"+c.severity, func(t *testing.T) {
			r, input := smtpReceiver(t, "tls", "mail.example.test", false, func(r *smtpTestReceiver) { r.dropAfterAcceptance = true })
			m := safeOutboundMessage(Notification{ID: ID(), Kind: "load-balance-traffic", Source: c.source, Severity: c.severity, CreatedAt: time.Now().Unix()})
			title := m.Title
			m.Title, m.Message = "owned-private-title", "owned-private-output"
			b, _ := json.Marshal(m)
			d := outboundDelivery{ID: ID(), Type: "smtp", Payload: string(b), Attempts: 1}
			code, err, _ := sendSMTPNotification(context.Background(), d, &input)
			if code != 250 || err != "" {
				t.Fatal("actual validated TLS receipt", code, err)
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			if len(r.messages) != 1 || r.dataAttempts != 1 {
				t.Fatal("wrong real SMTP attempts")
			}
			header, body := smtpParsedBody(t, r.messages[0])
			subject, e := (&mime.WordDecoder{}).DecodeHeader(header.Get("Subject"))
			if e != nil || subject != title || !strings.Contains(body, c.phrase) || strings.Contains(body, "owned-private") || header.Get("X-Yunzhan-Delivery-ID") != d.ID {
				t.Fatal("SMTP lost subtype/privacy/identity", subject, body, e)
			}
		})
	}
	input := SMTPNotificationInput{Host: "mail.example.test", Port: 465, TLSMode: "tls", ServerName: "mail.example.test", AuthMode: "none", From: "sender@example.test", To: []string{"receiver@example.test"}}
	for _, kind := range []string{"load-balance-traffic", "daily"} {
		m := OutboundMessage{SchemaVersion: 1, EventID: ID(), Kind: kind, EventType: "arbitrary-source-domain-or-error", Severity: "info"}
		b, _ := json.Marshal(m)
		if _, e := smtpNotificationMessage(outboundDelivery{ID: ID(), Payload: string(b)}, &input); e == nil {
			t.Fatal("unreviewed SMTP subtype accepted", kind)
		}
	}
}
