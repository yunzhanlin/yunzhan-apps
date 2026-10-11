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

func loadBalanceOutboundFixture(t *testing.T) (*Store, *Server, *LoadBalanceAlertFeed) {
	t.Helper()
	s, a := outboundFixture(t)
	feed := &LoadBalanceAlertFeed{SchemaVersion: 1, Available: true, Entries: []LoadBalanceAlertEntry{{ID: ID(), Revision: 1, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), Transitions: []LoadBalanceAlertTransition{}}}}
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/load-balance-alert-events" || r.URL.RawQuery != "" {
			t.Error("alert collection added mutation or targets")
		}
		b, _ := json.Marshal(feed)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
	})}}
	return s, a, feed
}
func lbAlertEvent(sequence int64, from, to string) LoadBalanceAlertTransition {
	return LoadBalanceAlertTransition{Sequence: sequence, From: from, To: to, Time: time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)}
}
func lbAlertCollect(t *testing.T, a *Server) {
	t.Helper()
	if err := a.collectLoadBalanceNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func lbAlertCursor(t *testing.T, s *Store, id string) (int64, int64) {
	t.Helper()
	var rev, seq int64
	if err := s.DB.QueryRow("SELECT revision,sequence FROM load_balance_notification_cursors WHERE entry_id=?", id).Scan(&rev, &seq); err != nil {
		t.Fatal(err)
	}
	return rev, seq
}
func lbAlertCount(t *testing.T, s *Store) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM notifications WHERE kind='load-balance'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestOutboundLoadBalanceThresholdEventsAreDeduplicatedScopedAndHMACSigned(t *testing.T) {
	s, a, feed := loadBalanceOutboundFixture(t)
	lbAlertCollect(t, a)
	var received []OutboundMessage
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(data) > 4096 {
			t.Error("unbounded message")
		}
		var message OutboundMessage
		if json.Unmarshal(data, &message) != nil || message.Kind != "load-balance" {
			t.Error("wrong event kind")
		}
		for _, private := range []string{feed.Entries[0].ID, "fixture-signing-secret", "health_check", "domain", "address", "ca_pem"} {
			if strings.Contains(string(data), private) {
				t.Error("private source information forwarded", private)
			}
		}
		if r.Header.Get("X-Yunzhan-Signature") != webhookSignature("fixture-signing-secret", r.Header.Get("X-Yunzhan-Delivery-ID"), r.Header.Get("X-Yunzhan-Timestamp"), data) {
			t.Error("invalid signed health message")
		}
		received = append(received, message)
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	_, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "health only", URL: receiver.URL, Secret: "fixture-signing-secret", Enabled: true, Kinds: []string{"load-balance"}})
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "not subscribed", URL: receiver.URL, Secret: "fixture-signing-secret", Enabled: true, Kinds: []string{"integrity"}})
	if err != nil {
		t.Fatal(err)
	}
	feed.Entries[0].Sequence = 2
	feed.Entries[0].Transitions = []LoadBalanceAlertTransition{lbAlertEvent(1, "unknown", "unhealthy"), lbAlertEvent(2, "unhealthy", "healthy")}
	for i := range feed.Entries[0].Transitions {
		feed.Entries[0].Transitions[i].Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	feed.Entries[0].CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < 2; i++ {
		lbAlertCollect(t, a)
	}
	if n := lbAlertCount(t, s); n != 2 {
		t.Fatal("duplicate or missing threshold change", n)
	}
	_, seq := lbAlertCursor(t, s, feed.Entries[0].ID)
	if seq != 2 {
		t.Fatal(seq)
	}
	if err = s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = a.dispatchOutbound(context.Background(), webhookHTTPClient()); err != nil {
			t.Fatal(err)
		}
	}
	if len(received) != 2 || received[0].Severity != "critical" || received[1].Severity != "info" || received[1].Title != "负载均衡健康确认" {
		t.Fatal("failure/recovery not independently delivered")
	}
	history, err := s.NotificationDeliveryHistory(unrelated.ID)
	if err != nil || len(history) != 0 {
		t.Fatal("unsubscribed channel received health", err)
	}
	// Cursor survives another server instance; no resampling or repeated signal.
	fresh := &Server{Store: s, Executor: a.Executor}
	lbAlertCollect(t, fresh)
	if n := lbAlertCount(t, s); n != 2 {
		t.Fatal("restart replay", n)
	}
}
func TestOutboundLoadBalanceInitialAndRevisionBaselinesNeverReplayOldRecords(t *testing.T) {
	s, a, feed := loadBalanceOutboundFixture(t)
	entry := &feed.Entries[0]
	entry.Sequence = 2
	entry.Transitions = []LoadBalanceAlertTransition{lbAlertEvent(1, "unknown", "unhealthy"), lbAlertEvent(2, "unhealthy", "healthy")}
	lbAlertCollect(t, a)
	if lbAlertCount(t, s) != 0 {
		t.Fatal("initial history backfilled")
	}
	entry.Revision = 2
	entry.Sequence = 1
	entry.Transitions = []LoadBalanceAlertTransition{lbAlertEvent(1, "unknown", "healthy")}
	lbAlertCollect(t, a)
	if lbAlertCount(t, s) != 0 {
		t.Fatal("new policy history backfilled")
	}
	entry.Sequence = 2
	entry.Transitions = append(entry.Transitions, lbAlertEvent(2, "healthy", "unhealthy"))
	lbAlertCollect(t, a)
	if lbAlertCount(t, s) != 1 {
		t.Fatal("post-baseline threshold change missing")
	}
	entry.Revision = 1
	if a.collectLoadBalanceNotifications(context.Background()) == nil {
		t.Fatal("revision rollback accepted")
	}
	rev, seq := lbAlertCursor(t, s, entry.ID)
	if rev != 2 || seq != 2 {
		t.Fatal("rollback erased cursor", rev, seq)
	}
	entry.Revision = 2
	entry.Sequence = 1
	entry.Transitions = entry.Transitions[:1]
	if a.collectLoadBalanceNotifications(context.Background()) == nil {
		t.Fatal("sequence rollback accepted")
	}
	if lbAlertCount(t, s) != 1 {
		t.Fatal("refusal changed notifications")
	}
}
func TestOutboundLoadBalanceRetainedWindowGapIsExplicitAndStable(t *testing.T) {
	s, a, feed := loadBalanceOutboundFixture(t)
	lbAlertCollect(t, a)
	entry := &feed.Entries[0]
	entry.Sequence = 35
	for n := int64(4); n <= 35; n++ {
		from, to := "healthy", "unhealthy"
		if n%2 == 1 {
			from, to = to, from
		}
		entry.Transitions = append(entry.Transitions, lbAlertEvent(n, from, to))
	}
	for i := 0; i < 2; i++ {
		lbAlertCollect(t, a)
	}
	if n := lbAlertCount(t, s); n != 33 {
		t.Fatal("window loss silently hidden or duplicated", n)
	}
	var gaps int
	if err := s.DB.QueryRow("SELECT count(*) FROM notifications WHERE source='app:load-balance-gap' AND severity='critical'").Scan(&gaps); err != nil || gaps != 1 {
		t.Fatal(gaps, err)
	}
	_, seq := lbAlertCursor(t, s, entry.ID)
	if seq != 35 {
		t.Fatal(seq)
	}
}
func TestOutboundLoadBalanceInvalidFeedNeverAdvancesOriginalCursor(t *testing.T) {
	s, a, feed := loadBalanceOutboundFixture(t)
	lbAlertCollect(t, a)
	original, _ := json.Marshal(feed)
	mutations := []func(*LoadBalanceAlertFeed){
		func(f *LoadBalanceAlertFeed) { f.SchemaVersion = 0 }, func(f *LoadBalanceAlertFeed) { f.Entries = nil },
		func(f *LoadBalanceAlertFeed) { f.Available = false }, func(f *LoadBalanceAlertFeed) { f.Entries = append(f.Entries, f.Entries[0]) },
		func(f *LoadBalanceAlertFeed) {
			f.Entries[0].CheckedAt = time.Now().Add(time.Hour).Format(time.RFC3339Nano)
		},
		func(f *LoadBalanceAlertFeed) {
			f.Entries[0].Sequence = 2
			f.Entries[0].Transitions = []LoadBalanceAlertTransition{lbAlertEvent(1, "unknown", "healthy")}
		},
		func(f *LoadBalanceAlertFeed) {
			f.Entries[0].Sequence = 3
			f.Entries[0].Transitions = []LoadBalanceAlertTransition{lbAlertEvent(1, "unknown", "healthy"), lbAlertEvent(3, "healthy", "unhealthy")}
		},
		func(f *LoadBalanceAlertFeed) {
			f.Entries[0].Sequence = 1
			f.Entries[0].Transitions = []LoadBalanceAlertTransition{lbAlertEvent(1, "unknown", "unknown")}
		},
		func(f *LoadBalanceAlertFeed) { f.Entries[0].Transitions = nil },
	}
	for i, mutate := range mutations {
		if err := json.Unmarshal(original, feed); err != nil {
			t.Fatal(err)
		}
		mutate(feed)
		if a.collectLoadBalanceNotifications(context.Background()) == nil {
			t.Fatal("invalid feed accepted", i)
		}
		var count int
		if err := s.DB.QueryRow("SELECT count(*) FROM load_balance_notification_cursors WHERE revision=1 AND sequence=0").Scan(&count); err != nil || count != 1 || lbAlertCount(t, s) != 0 {
			t.Fatal("failed collection changed original identity", i)
		}
	}
}
func TestOutboundLoadBalanceSQLFailureRollsBackEveryEventAndCursor(t *testing.T) {
	s, a, feed := loadBalanceOutboundFixture(t)
	lbAlertCollect(t, a)
	entry := &feed.Entries[0]
	entry.Sequence = 2
	entry.Transitions = []LoadBalanceAlertTransition{lbAlertEvent(1, "unknown", "unhealthy"), lbAlertEvent(2, "unhealthy", "healthy")}
	if _, err := s.DB.Exec("CREATE TRIGGER reject_health_recovery BEFORE INSERT ON notifications WHEN NEW.kind='load-balance' AND NEW.severity='info' BEGIN SELECT RAISE(ABORT,'fixture SQL refusal'); END"); err != nil {
		t.Fatal(err)
	}
	if a.collectLoadBalanceNotifications(context.Background()) == nil {
		t.Fatal("partial transaction accepted")
	}
	_, seq := lbAlertCursor(t, s, entry.ID)
	if seq != 0 || lbAlertCount(t, s) != 0 {
		t.Fatal("partial event or cursor committed", seq)
	}
	if _, err := s.DB.Exec("DROP TRIGGER reject_health_recovery"); err != nil {
		t.Fatal(err)
	}
	lbAlertCollect(t, a)
	if lbAlertCount(t, s) != 2 {
		t.Fatal("original events not recovered exactly once")
	}
}
func TestOutboundLoadBalanceNotificationCapacityKeepsOriginalCursor(t *testing.T) {
	s, a, feed := loadBalanceOutboundFixture(t)
	lbAlertCollect(t, a)
	_, err := s.DB.Exec(`WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<10000) INSERT INTO notifications(id,kind,title,message,severity,source,source_id,created_at) SELECT lower(hex(randomblob(16))),'load-balance','fixture','fixture','info','fixture:capacity',cast(n AS text),0 FROM numbers`)
	if err != nil {
		t.Fatal(err)
	}
	entry := &feed.Entries[0]
	entry.Sequence = 1
	entry.Transitions = []LoadBalanceAlertTransition{lbAlertEvent(1, "unknown", "unhealthy")}
	if a.collectLoadBalanceNotifications(context.Background()) == nil {
		t.Fatal("unbounded source inventory")
	}
	_, seq := lbAlertCursor(t, s, entry.ID)
	if seq != 0 || lbAlertCount(t, s) != 10000 {
		t.Fatal("capacity refusal erased watermark or evidence")
	}
}
func TestOutboundLoadBalanceCursorCapacityRollsBackEarlierEntryEvents(t *testing.T) {
	s, a, feed := loadBalanceOutboundFixture(t)
	lbAlertCollect(t, a)
	if _, err := s.DB.Exec(`WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<4095) INSERT INTO load_balance_notification_cursors SELECT lower(hex(randomblob(16))),1,0 FROM numbers`); err != nil {
		t.Fatal(err)
	}
	entry := &feed.Entries[0]
	id := entry.ID
	entry.Sequence = 1
	entry.Transitions = []LoadBalanceAlertTransition{lbAlertEvent(1, "unknown", "unhealthy")}
	feed.Entries = append(feed.Entries, LoadBalanceAlertEntry{ID: ID(), Revision: 1, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), Transitions: []LoadBalanceAlertTransition{}})
	if a.collectLoadBalanceNotifications(context.Background()) == nil {
		t.Fatal("cursor namespace capacity silently pruned old identities")
	}
	_, seq := lbAlertCursor(t, s, id)
	if seq != 0 || lbAlertCount(t, s) != 0 {
		t.Fatal("earlier entry partially committed on later capacity failure")
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM load_balance_notification_cursors").Scan(&count); err != nil || count != 4096 {
		t.Fatal("original cursor inventory changed", count, err)
	}
}

func TestLoadBalanceAlertsRequireIndependentReviewedPatchVersion(t *testing.T) {
	if SoftwareImplementationVersion("load-balance") != "1.8.3" {
		t.Fatal("alert handler changed without an independent app version")
	}
	for _, version := range []string{"1.8.2", "1.8.3"} {
		if err := ValidateSoftwareUpdate("load-balance", version); err != nil {
			t.Fatal("prior/current reviewed app release refused", err)
		}
	}
	if ValidateSoftwareUpdate("load-balance", "1.8.4") == nil {
		t.Fatal("unimplemented future app update accepted")
	}
	var definition AppModuleDefinition
	for _, d := range AppModules() {
		if d.ID == "load-balance" {
			definition = d
		}
	}
	if definition.ID != "load-balance" {
		t.Fatal("missing definition")
	}
	// Version is advertised by the same normal handler as the installed module.
	found := false
	for _, item := range moduleSoftwareCatalog() {
		if item.ID == "load-balance" {
			found = item.Version == "1.8.3"
		}
	}
	if !found {
		t.Fatal("actual normal module handler did not advertise the independent alert patch")
	}
	if !LoadBalanceHistoryVersion("1.8.3") || LoadBalanceHistoryVersion("1.8.4") {
		t.Fatal("new version lacks the reviewed inherited contract or accepts unknown future")
	}
}
