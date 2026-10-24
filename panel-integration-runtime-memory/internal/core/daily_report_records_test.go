package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDailyTrafficIdentityQueryIsBoundedAndDoesNotReadWebsiteSettings(t *testing.T) {
	s := testStore(t)
	ids, err := s.dailyTrafficSiteIDs(context.Background())
	if err != nil || ids == nil || len(ids) != 0 {
		t.Fatal("actual empty inventory not an observed empty list", ids, err)
	}
	for i := 0; i < 128; i++ {
		name := fmt.Sprintf("owned-daily-%d", i)
		if _, err := s.DB.Exec(`INSERT INTO sites(id,name,slug,domain,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, ID(), name, name, name+".example.test", "running", Now(), Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`UPDATE sites SET settings_json=? WHERE rowid=1`, strings.Repeat("x", 2<<20)); err != nil {
		t.Fatal(err)
	}
	ids, err = s.dailyTrafficSiteIDs(context.Background())
	if err != nil || len(ids) != 128 {
		t.Fatal("unneeded large settings were read or valid bounded IDs lost", len(ids), err)
	}
	if _, err := s.DB.Exec(`INSERT INTO sites(id,name,slug,domain,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, ID(), "owned-limit", "owned-limit", "owned-limit.example.test", "running", Now(), Now()); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.dailyTrafficSiteIDs(context.Background()); err == nil || ids != nil {
		t.Fatal("129 sites returned a false complete 128-site list")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.dailyTrafficSiteIDs(ctx); err == nil {
		t.Fatal("cancelled site query became empty observed traffic")
	}
	var n int
	s.DB.QueryRow(`SELECT count(*) FROM sites`).Scan(&n)
	if n != 129 {
		t.Fatal("readonly inventory changed websites")
	}
}

func TestDailyReportStrictRecordsPreserveLegacyAbsenceAndGenuineZero(t *testing.T) {
	for _, raw := range []string{`{"sites":9}`, `{"sites":0,"running_sites":0,"created_at":"2026-10-10T00:00:00Z","resources":{"cpu_percent":null}}`, `{"private_password":"not-forwarded","sites":5,"resources":{"hostname":"private-host","memory_percent":20}}`} {
		record, err := decodeDailyReportRecord([]byte(raw))
		if err != nil {
			t.Fatal(raw, err)
		}
		summary, err := outboundDailyReportSummary("2026-10-10", record)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		var exported map[string]any
		if json.Unmarshal(payload, &exported) != nil {
			t.Fatal("summary cannot be parsed")
		}
		if strings.Contains(string(payload), "private_password") || strings.Contains(string(payload), "private-host") || strings.Contains(string(payload), "not-forwarded") {
			t.Fatal("outbound summary forwarded private extra fields")
		}
		if _, exists := record["running_sites"]; exists {
			if _, exists := exported["running_sites"]; !exists || !summary.CountAvailable["running_sites"] {
				t.Fatal("genuine zero lost", string(payload))
			}
		} else {
			if _, exists := exported["running_sites"]; exists || summary.CountAvailable["running_sites"] {
				t.Fatal("missing legacy counter became zero", string(payload))
			}
		}
	}
}

func TestDailyReportBadRecordsFreezeReadOverwriteAndNotification(t *testing.T) {
	cases := map[string]string{"empty": "", "null": "null", "array": "[]", "scalar": "1", "malformed": "{", "duplicate": `{"sites":1,"sites":2}`, "escaped": `{"sites":1,"\u0073ites":2}`, "case": `{"sites":1,"Sites":2}`, "nested": `{"resources":{"cpu_percent":1,"cpu_percent":2}}`, "trailing": `{"sites":1} {}`, "negative": `{"sites":-1}`, "fraction": `{"sites":1.5}`, "oversized-counter": `{"sites":1000000001}`, "string-counter": `{"sites":"1"}`, "null-counter": `{"sites":null}`, "bad-date": `{"created_at":"invalid"}`, "bad-date-type": `{"created_at":1}`, "invalid-utf8": string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}), "depth": strings.Repeat(`{"x":`, 18) + `0` + strings.Repeat(`}`, 18), "nodes": `{"values":[` + strings.Repeat(`0,`, 100000) + `0]}`, "oversize": `{"value":"` + strings.Repeat("x", dailyReportRecordBytes) + `"}`}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			day := "2026-10-10"
			if _, err := s.DB.Exec(`INSERT INTO app_daily_reports VALUES(?,?,?)`, day, raw, "2026-10-10T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readDailyReportRecord(context.Background(), s.DB, day); err == nil {
				t.Fatal("bad report accepted")
			}
			if err := s.saveDailyReportRecord(context.Background(), day, map[string]any{"sites": 1}); err == nil {
				t.Fatal("bad report replaced with fresh snapshot")
			}
			var retained string
			var count int
			if err := s.DB.QueryRow(`SELECT report FROM app_daily_reports WHERE day=?`, day).Scan(&retained); err != nil || retained != raw {
				t.Fatal("original report changed", err)
			}
			if err := s.DB.QueryRow(`SELECT count(*) FROM notifications WHERE kind='daily'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed report generated source event", count, err)
			}
		})
	}
}

func TestDailyReportSnapshotAndSourceEventCommitTogether(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	day := "2026-10-10"
	if err := s.saveDailyReportRecord(ctx, day, map[string]any{"sites": 5, "running_sites": 0}); err != nil {
		t.Fatal(err)
	}
	var id, before string
	if err := s.DB.QueryRow(`SELECT id FROM notifications WHERE source='daily-report' AND source_id=?`, day).Scan(&id); err != nil {
		t.Fatal(err)
	}
	s.DB.QueryRow(`SELECT report FROM app_daily_reports WHERE day=?`, day).Scan(&before)
	if _, err := s.DB.Exec(`CREATE TRIGGER own_daily_notification_failure BEFORE INSERT ON notifications WHEN NEW.kind='daily' BEGIN SELECT RAISE(ABORT,'owned source event failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if err := s.saveDailyReportRecord(ctx, day, map[string]any{"sites": 7}); err == nil {
		t.Fatal("report committed without source event")
	}
	if err := s.saveDailyReportRecord(ctx, "2026-10-11", map[string]any{"sites": 8}); err == nil {
		t.Fatal("fresh day committed without source event")
	}
	var after string
	var count int
	s.DB.QueryRow(`SELECT report FROM app_daily_reports WHERE day=?`, day).Scan(&after)
	s.DB.QueryRow(`SELECT count(*) FROM app_daily_reports`).Scan(&count)
	if after != before || count != 1 {
		t.Fatal("notification failure did not roll report back", after, count)
	}
	if _, err := s.DB.Exec(`DROP TRIGGER own_daily_notification_failure`); err != nil {
		t.Fatal(err)
	}
	if err := s.saveDailyReportRecord(ctx, day, map[string]any{"sites": 7}); err != nil {
		t.Fatal(err)
	}
	var currentID string
	s.DB.QueryRow(`SELECT id FROM notifications WHERE source='daily-report' AND source_id=?`, day).Scan(&currentID)
	s.DB.QueryRow(`SELECT count(*) FROM notifications WHERE source='daily-report' AND source_id=?`, day).Scan(&count)
	if currentID != id || count != 1 {
		t.Fatal("refresh duplicated or changed original notification identity")
	}
}

func TestDailyReportArchiveByteInventoryAndReadAreNonMutating(t *testing.T) {
	s := testStore(t)
	a := &Server{Store: s}
	raw := `{"notes":"中文","sites":0}`
	day := "2026-10-10"
	if _, err := s.DB.Exec(`INSERT INTO app_daily_reports VALUES(?,?,?)`, day, raw, "2026-10-10T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	out, err := a.dailyReportOperation(context.Background(), "archive", AppModuleInput{})
	if err != nil {
		t.Fatal(err)
	}
	row := out.(map[string]any)["reports"].([]map[string]any)[0]
	if row["bytes"] != int64(len(raw)) {
		t.Fatal("UTF8 characters were labelled bytes", row)
	}
	for i := 0; i < 3; i++ {
		if _, err := a.dailyReportOperation(context.Background(), "report", AppModuleInput{ResourceID: day}); err != nil {
			t.Fatal(err)
		}
	}
	var retained string
	var count int
	s.DB.QueryRow(`SELECT report FROM app_daily_reports WHERE day=?`, day).Scan(&retained)
	s.DB.QueryRow(`SELECT count(*) FROM notifications`).Scan(&count)
	if retained != raw || count != 0 {
		t.Fatal("read rewrote report or created notification")
	}
	for _, day := range []string{"2026-02-30", "../2026-10-10", "2026-10-10 00:00:00"} {
		if validDailyReportDay(day) {
			t.Fatal(fmt.Sprintf("invalid date %q accepted", day))
		}
	}
}

func TestDailyReportArchivePaginationAndInvalidBounds(t *testing.T) {
	s := testStore(t)
	a := &Server{Store: s}
	for i := 1; i <= 20; i++ {
		if _, err := s.DB.Exec(`INSERT INTO app_daily_reports VALUES(?,?,?)`, fmt.Sprintf("2026-09-%02d", i), `{"sites":0}`, "2026-10-10T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	out, err := a.dailyReportOperation(context.Background(), "archive", AppModuleInput{Limit: 7, Offset: 7})
	if err != nil {
		t.Fatal(err)
	}
	page := out.(map[string]any)
	rows := page["reports"].([]map[string]any)
	if len(rows) != 7 || rows[0]["day"] != "2026-09-13" || page["total"] != 20 || page["read_only"] != true || page["report_contents_verified"] != false {
		t.Fatal(page)
	}
	for _, in := range []AppModuleInput{{Limit: -1}, {Limit: 101}, {Offset: -1}, {Offset: 100001}} {
		if _, err := a.dailyReportOperation(context.Background(), "archive", in); err == nil {
			t.Fatal("invalid page accepted", in)
		}
	}
}

func TestDailyReportCorruptOrMissingSourceIsDurablyIsolatedNotDelivered(t *testing.T) {
	for _, raw := range []string{"", "{", `{"sites":-1}`, `{"sites":1,"sites":2}`} {
		t.Run(fmt.Sprintf("record-bytes-%d-%s", len(raw), Hash(raw)[:8]), func(t *testing.T) {
			s, _ := outboundFixture(t)
			channel := outboundCreate(t, s, "http://127.0.0.1:21555/hooks")
			day := "2026-10-10"
			if raw != "" {
				if _, err := s.DB.Exec(`INSERT INTO app_daily_reports VALUES(?,?,?)`, day, raw, Now()); err != nil {
					t.Fatal(err)
				}
			}
			// Both surrounding good events survive; cursor advancement is
			// permitted only alongside a durable original source block.
			outboundEvent(t, s, "monitor")
			if err := s.QueueDailyNotification(day); err != nil {
				t.Fatal(err)
			}
			outboundEvent(t, s, "sync")
			var before, after int64
			if err := s.DB.QueryRow(`SELECT watermark FROM notification_channels WHERE id=?`, channel.ID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := s.QueueOutboundNotifications(); err == nil {
				t.Fatal("unverifiable source queued as a generated report")
			}
			var count int
			if err := s.DB.QueryRow(`SELECT watermark FROM notification_channels WHERE id=?`, channel.ID).Scan(&after); err != nil || after != before+3 {
				t.Fatal("durably isolated source blocked surrounding good events", before, after, err)
			}
			if err := s.DB.QueryRow(`SELECT count(*) FROM notification_deliveries`).Scan(&count); err != nil || count != 2 {
				t.Fatal("normal surrounding events not queued independently", count, err)
			}
			blocks, total, err := s.OutboundSourceBlocks(context.Background(), channel.ID)
			if err != nil || total != 1 || len(blocks) != 1 || blocks[0]["state"] != "source_blocked" || blocks[0]["day"] != day {
				t.Fatal("original blocked event absent", blocks, total, err)
			}
			var daily int
			if err = s.DB.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE json_extract(payload,'$.kind')='daily'`).Scan(&daily); err != nil || daily != 0 {
				t.Fatal("bad source sent as generated daily", daily, err)
			}
			if err = s.QueueOutboundNotifications(); err == nil {
				t.Fatal("outstanding source block hidden on next tick")
			}
			if raw != "" {
				var retained string
				if err := s.DB.QueryRow(`SELECT report FROM app_daily_reports WHERE day=?`, day).Scan(&retained); err != nil || retained != raw {
					t.Fatal("queue repaired or changed original report", err)
				}
			}
		})
	}
}

func TestDailyReportSMTPMissingCounterIsNotGenuineZero(t *testing.T) {
	for _, record := range []map[string]any{{"sites": 0, "running_sites": 0}, {"sites": 5}} {
		summary, err := outboundDailyReportSummary("2026-10-10", record)
		if err != nil {
			t.Fatal(err)
		}
		message := safeOutboundMessage(Notification{ID: ID(), Kind: "daily", Severity: "info", CreatedAt: 1})
		message.Report = &summary
		payload, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		data, err := smtpNotificationMessage(outboundDelivery{ID: ID(), Payload: string(payload)}, &SMTPNotificationInput{From: "panel@example.test", To: []string{"recipient@example.test"}})
		if err != nil {
			t.Fatal(err)
		}
		_, body := smtpParsedBody(t, string(data))
		if !strings.Contains(body, "失败网站任务：未记录") || strings.Contains(body, "失败网站任务：0") {
			t.Fatal("absent count rendered as zero", body)
		}
		if record["sites"] == 0 {
			if !strings.Contains(body, "网站：0（运行 0）") {
				t.Fatal("observed zero lost", body)
			}
		} else if !strings.Contains(body, "网站：5（运行 未记录）") {
			t.Fatal("partial report misrepresented", body)
		}
	}
}

func TestDailyReportResourceBoundsAndCanonicalOutboundFields(t *testing.T) {
	for _, raw := range []string{`{"resources":"unknown"}`, `{"resources":[]}`, `{"resources":{"cpu_percent":-1}}`, `{"resources":{"memory_percent":101}}`, `{"resources":{"disk_percent":"0"}}`, `{"resources":{"cpu_available":"false"}}`, `{"resources":{"disk_percent_available":0}}`} {
		s := testStore(t)
		if _, err := s.DB.Exec(`INSERT INTO app_daily_reports VALUES('2026-10-10',?,?)`, raw, Now()); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readDailyReportRecord(context.Background(), s.DB, "2026-10-10"); err == nil {
			t.Fatal("invalid stored resource returned as a normal report", raw)
		}
		if err := s.saveDailyReportRecord(context.Background(), "2026-10-10", map[string]any{"sites": 0}); err == nil {
			t.Fatal("invalid resource record overwritten", raw)
		}
		var retained string
		s.DB.QueryRow(`SELECT report FROM app_daily_reports`).Scan(&retained)
		if retained != raw {
			t.Fatal("resource evidence changed")
		}
	}
	summary, err := outboundDailyReportSummary("2026-10-10", map[string]any{"Sites": 99, "resources": map[string]any{"CPU_Percent": 90, "memory_percent": 0, "memory_available": false, "disk_percent": 0, "disk_percent_available": true, "disk_available": uint64(4096)}, "count_available": map[string]bool{"sites": true}})
	if err != nil || summary.CountAvailable["sites"] || summary.Sites != 0 || summary.Resources.CPU != nil || summary.Resources.Memory != nil || summary.Resources.Disk == nil || *summary.Resources.Disk != 0 {
		t.Fatal("unknown case/availability metadata became an observed value", err)
	}
	for _, raw := range []string{`{"resources":null}`, `{"resources":{"cpu_percent":null}}`, `{"resources":{"cpu_percent":0,"cpu_available":false}}`} {
		if _, err := decodeDailyReportRecord([]byte(raw)); err != nil {
			t.Fatal("explicit unavailable legacy resource rejected", err)
		}
	}
	// Use the actual executor overview's established byte field, not a
	// percentage-only fixture. It must survive a persisted report round trip.
	s := testStore(t)
	report := map[string]any{"resources": map[string]any{"disk_total": uint64(8192), "disk_used": uint64(4096), "disk_available": uint64(4096), "disk_percent": float64(50)}}
	if err := s.saveDailyReportRecord(context.Background(), "2026-10-10", report); err != nil {
		t.Fatal("real disk byte contract rejected", err)
	}
	_, persisted, err := readDailyReportRecord(context.Background(), s.DB, "2026-10-10")
	if err != nil || persisted["resources"].(map[string]any)["disk_available"] != float64(4096) {
		t.Fatal("available bytes were retyped or lost", err)
	}
	actual, err := outboundDailyReportSummary("2026-10-10", persisted)
	if err != nil || actual.Resources.Disk == nil || *actual.Resources.Disk != 50 {
		t.Fatal("valid disk percentage not included", err)
	}
	persisted["resources"].(map[string]any)["disk_percent_available"] = false
	actual, err = outboundDailyReportSummary("2026-10-10", persisted)
	if err != nil || actual.Resources.Disk != nil {
		t.Fatal("available bytes promoted an unavailable percentage", err)
	}
	for _, available := range []any{nil, false, true} {
		resources := map[string]any{"cpu_percent": 0}
		if available != nil {
			resources["cpu_available"] = available
		}
		actual, err := outboundDailyReportSummary("2026-10-10", map[string]any{"resources": resources})
		if err != nil || (actual.Resources.CPU != nil) != (available == true) {
			t.Fatal("legacy first-sample default became an observed idle interval", available, err)
		}
	}
}

func TestDailyReportAuthenticatedPageDoesNotLeakStaleFallbackOrGenerate(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "daily-record-reader", "admin", []string{"audit"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/app-modules/daily-report" {
			t.Fatal("report page dispatched business", r.Method, r.URL.Path)
		}
		reads++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"definition":{"id":"daily-report"},"status":{"installed":true,"enabled":true,"healthy":true},"report":{"stale":"fallback-is-not-actual-daily-data"},"report_state_unknown":true}`))}, nil
	})}}
	login := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+admin.Username+`","password":"access-test-password-long"}`))
	login.Header.Set("Origin", a.Config.Origin)
	login.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, login)
	if w.Code != 200 {
		t.Fatal("fixture login failed", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	for _, kind := range []string{"missing", "malformed", "legacy-valid"} {
		if _, err := s.DB.Exec(`DELETE FROM app_daily_reports`); err != nil {
			t.Fatal(err)
		}
		if kind != "missing" {
			raw := "{"
			if kind == "legacy-valid" {
				raw = `{"sites":9}`
			}
			if _, err := s.DB.Exec(`INSERT INTO app_daily_reports VALUES('2026-10-10',?,'2026-10-10T00:00:00Z')`, raw); err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest("GET", "/api/app-modules/daily-report", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		var page struct {
			Report  any  `json:"report"`
			Unknown bool `json:"report_state_unknown"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || strings.Contains(w.Body.String(), "fallback-is-not-actual-daily-data") {
			t.Fatal("stale executor fallback surfaced", kind, w.Code)
		}
		if kind == "legacy-valid" {
			if page.Unknown || page.Report.(map[string]any)["sites"] != float64(9) {
				t.Fatal("actual legacy report hidden")
			}
		} else if page.Report != nil || page.Unknown != (kind == "malformed") {
			t.Fatal("absence and malformed report merged", kind, page)
		}
	}
	var count int
	s.DB.QueryRow(`SELECT count(*) FROM notifications WHERE kind='daily'`).Scan(&count)
	if reads != 3 || count != 0 {
		t.Fatal("readonly page generated or queued report", reads, count)
	}
	// Current menu grants, not just an old login, remain authoritative.
	if _, err := s.DB.Exec(`UPDATE app_user_menus SET menu_ids='["system-tools"]',revision=revision+1 WHERE user_id=?`, admin.ID); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/app-modules/daily-report", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	a.ServeHTTP(w, req)
	if w.Code != 403 || reads != 3 || strings.Contains(w.Body.String(), `"sites":9`) {
		t.Fatal("revoked audit grant reached executor or disclosed daily report", w.Code, reads)
	}
}
