package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func lbSourceFixture(t *testing.T) (*Store, *Server, *int, map[string]int) {
	t.Helper()
	s, a := outboundFixture(t)
	mode := new(int)
	calls := map[string]int{}
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls[r.URL.Path]++
		if r.Method != "GET" {
			t.Error("source observer attempted mutation")
		}
		status, value := 200, any(ModuleAlertPage{Cursor: 0, Events: []ModuleAlertEvent{}})
		switch r.URL.Path {
		case "/v1/load-balance-alert-events":
			value = LoadBalanceAlertFeed{SchemaVersion: 1, Available: true, Entries: []LoadBalanceAlertEntry{}}
			if *mode == 1 {
				status, value = 409, map[string]string{"error": "owned-secret-domain-and-raw-error"}
			}
		case "/v1/load-balance-traffic-alert-events":
			f := LoadBalanceTrafficFeed{SchemaVersion: 1, Available: true, WorkerState: "unknown", Records: []LoadBalanceTrafficRecord{}}
			if *mode == 2 {
				f.Available = false
			}
			if *mode == 3 {
				f.Records = nil
			}
			value = f
		}
		b, _ := json.Marshal(value)
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b))}, nil
	})}}
	return s, a, mode, calls
}
func lbSourceChannel(t *testing.T, s *Store, endpoint, kind string, enabled bool) NotificationChannel {
	t.Helper()
	c, e := s.SaveNotificationChannel("", NotificationChannelInput{Name: "owned source scope", URL: endpoint, Secret: "source-fixture-secret", Enabled: enabled, Kinds: []string{kind}})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func lbSourceCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM notifications WHERE kind='load-balance-source'`).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestOutboundSourceNoImplicitSubscriptionOrUninstalledPhantom(t *testing.T) {
	for _, kind := range []string{"load-balance", "load-balance-traffic", "sync", "load-balance-source"} {
		t.Run(kind, func(t *testing.T) {
			s, a, mode, _ := lbSourceFixture(t)
			lbSourceChannel(t, s, "http://127.0.0.1:12345", kind, kind != "load-balance-source")
			*mode = 2
			if e := a.collectModuleNotifications(context.Background()); e != nil {
				t.Fatal(e)
			}
			var n int
			s.DB.QueryRow(`SELECT count(*) FROM load_balance_source_observation`).Scan(&n)
			if n != 0 || lbSourceCount(t, s) != 0 {
				t.Fatal("old scope or disabled channel implicitly subscribed")
			}
		})
	}
}
func TestOutboundSourceBothValidatedFeedsOnceHMACRecoveryQualifiedAndRestartDedup(t *testing.T) {
	s, a, mode, calls := lbSourceFixture(t)
	var messages []OutboundMessage
	r := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		if len(b) > 4096 || r.Header.Get("X-Yunzhan-Signature") != webhookSignature("source-fixture-secret", r.Header.Get("X-Yunzhan-Delivery-ID"), r.Header.Get("X-Yunzhan-Timestamp"), b) {
			t.Error("invalid HMAC or size")
		}
		var m OutboundMessage
		if json.Unmarshal(b, &m) != nil || m.Kind != "load-balance-source" || strings.Contains(string(b), "owned-secret-domain-and-raw-error") {
			t.Error("private source evidence or wrong kind")
		}
		messages = append(messages, m)
		w.WriteHeader(204)
	}))
	defer r.Close()
	c := lbSourceChannel(t, s, r.URL, "load-balance-source", true)
	old := lbSourceChannel(t, s, r.URL, "load-balance", true)
	for i, m := range []int{0, 1, 1, 2, 3, 0, 0} {
		*mode = m
		fresh := &Server{Store: s, Executor: a.Executor}
		e := fresh.collectModuleNotifications(context.Background())
		if (m == 1 || m == 3) != (e != nil) {
			t.Fatal("source failure concealed", i, e)
		}
		if calls["/v1/load-balance-alert-events"] != i+1 || calls["/v1/load-balance-traffic-alert-events"] != i+1 {
			t.Fatal("duplicate feed requests")
		}
	}
	if lbSourceCount(t, s) != 2 {
		t.Fatal("initial ready backfill or repeated unavailable/restart duplicates")
	}
	if e := s.QueueOutboundNotifications(); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e := a.dispatchOutbound(context.Background(), webhookHTTPClient()); e != nil {
			t.Fatal(e)
		}
	}
	if len(messages) != 2 || messages[0].EventType != "source_unavailable" || messages[0].Severity != "critical" || messages[1].EventType != "source_ready" || !strings.Contains(messages[1].Message, "不代表全部节点") {
		t.Fatal(messages)
	}
	history, e := s.NotificationDeliveryHistory(c.ID)
	if e != nil || len(history) != 2 || history[0]["event_type"] != "source_ready" || history[0]["title"] != messages[1].Title {
		t.Fatal(history, e)
	}
	if h, e := s.NotificationDeliveryHistory(old.ID); e != nil || len(h) != 0 {
		t.Fatal("old health channel acquired source events", h, e)
	}
}
func TestOutboundSourceInitialUnavailableCancellationClockAndPausedEvidence(t *testing.T) {
	s, a, mode, _ := lbSourceFixture(t)
	c := lbSourceChannel(t, s, "http://127.0.0.1:12345", "load-balance-source", true)
	*mode = 2
	if e := a.collectModuleNotifications(context.Background()); e != nil || lbSourceCount(t, s) != 1 {
		t.Fatal(e)
	}
	var seq, at int64
	s.DB.QueryRow(`SELECT sequence,checked_at FROM load_balance_source_observation`).Scan(&seq, &at)
	if e := s.observeLoadBalanceSource(context.Background(), true, at-1); e == nil || lbSourceCount(t, s) != 1 {
		t.Fatal("clock rollback accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := s.observeLoadBalanceSource(ctx, true, at); e == nil || lbSourceCount(t, s) != 1 {
		t.Fatal("cancellation became recovery")
	}
	if _, e := s.SaveNotificationChannel(c.ID, NotificationChannelInput{Name: c.Name, Enabled: false, Revision: c.Revision, Kinds: c.Kinds}); e != nil {
		t.Fatal(e)
	}
	if e := s.observeLoadBalanceSource(context.Background(), true, at+1); e != nil {
		t.Fatal(e)
	}
	var state string
	s.DB.QueryRow(`SELECT state FROM load_balance_source_observation`).Scan(&state)
	if state != "unavailable" || lbSourceCount(t, s) != 1 {
		t.Fatal("pause lost source evidence or generated events")
	}
}
func TestOutboundSourceSQLFailureCapacityAndSequenceKeepOriginalCursor(t *testing.T) {
	s, _, _, _ := lbSourceFixture(t)
	lbSourceChannel(t, s, "http://127.0.0.1:12345", "load-balance-source", true)
	ctx, now := context.Background(), time.Now().Unix()
	if e := s.observeLoadBalanceSource(ctx, false, now); e != nil {
		t.Fatal(e)
	}
	_, e := s.DB.Exec(`CREATE TRIGGER refuse_source_ready BEFORE INSERT ON notifications WHEN NEW.kind='load-balance-source' AND NEW.severity='info' BEGIN SELECT RAISE(ABORT,'owned SQL refusal'); END`)
	if e != nil || s.observeLoadBalanceSource(ctx, true, now+1) == nil || lbSourceCount(t, s) != 1 {
		t.Fatal("SQL failure consumed source transition", e)
	}
	var state string
	var sequence int64
	s.DB.QueryRow(`SELECT state,sequence FROM load_balance_source_observation`).Scan(&state, &sequence)
	if state != "unavailable" || sequence != 1 {
		t.Fatal("cursor changed after refusal")
	}
	s.DB.Exec(`DROP TRIGGER refuse_source_ready`)
	s.DB.Exec(`UPDATE load_balance_source_observation SET sequence=1152921504606846975`)
	if s.observeLoadBalanceSource(ctx, true, now+1) == nil || lbSourceCount(t, s) != 1 {
		t.Fatal("exhausted identity sequence wrapped")
	}
	s.DB.Exec(`UPDATE load_balance_source_observation SET sequence=1`)
	_, e = s.DB.Exec(`WITH RECURSIVE n(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM n WHERE v<9999) INSERT INTO notifications(id,kind,title,message,severity,source,source_id,created_at) SELECT lower(hex(randomblob(16))),'load-balance-source','fixture','fixture','info','fixture:source-capacity',cast(v AS text),0 FROM n`)
	if e != nil || s.observeLoadBalanceSource(ctx, true, now+1) == nil || lbSourceCount(t, s) != 10000 {
		t.Fatal("source capacity discarded evidence", e)
	}
}
func TestOutboundSourceSlowReadUsesChildDeadlineThenObservesUnavailableAndOtherSources(t *testing.T) {
	s, a, _, calls := lbSourceFixture(t)
	lbSourceChannel(t, s, "http://127.0.0.1:12345", "load-balance-source", true)
	base := a.Executor.Client.Transport
	a.Executor.Client.Transport = scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/load-balance-alert-events" {
			deadline, exists := r.Context().Deadline()
			if !exists || time.Until(deadline) > 2*time.Second {
				t.Fatal("source read lacks its real production deadline")
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return base.RoundTrip(r)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	start := time.Now()
	if e := a.collectModuleNotifications(ctx); e == nil || ctx.Err() != nil || lbSourceCount(t, s) != 1 || calls["/v1/load-balance-traffic-alert-events"] != 1 || calls["/v1/module-alert-events"] != 5 || time.Since(start) > 5*time.Second {
		t.Fatal("slow source blocked observation or other reads", e, ctx.Err(), calls)
	}
}
func TestOutboundSourceValidatedFeedButCursorRefusalIsUnavailableNotReady(t *testing.T) {
	s, a, _, _ := lbSourceFixture(t)
	lbSourceChannel(t, s, "http://127.0.0.1:12345", "load-balance-source", true)
	if e := a.collectModuleNotifications(context.Background()); e != nil {
		t.Fatal(e)
	}
	_, e := s.DB.Exec(`CREATE TRIGGER refuse_traffic_observation BEFORE INSERT ON load_balance_traffic_source BEGIN SELECT RAISE(ABORT,'owned cursor refusal'); END`)
	if e != nil || a.collectModuleNotifications(context.Background()) == nil || lbSourceCount(t, s) != 1 {
		t.Fatal("failed cursor commit presented as ready", e)
	}
	var state string
	s.DB.QueryRow(`SELECT state FROM load_balance_source_observation`).Scan(&state)
	if state != "unavailable" {
		t.Fatal(state)
	}
}
