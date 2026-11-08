package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOutboundPHPEventCountsScopeAndPrivacy(t *testing.T) {
	s, a := outboundFixture(t)
	stage := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		page := ModuleAlertPage{Cursor: 0, Events: []ModuleAlertEvent{}}
		if stage == 1 {
			page.Cursor = 5
			if r.URL.Query().Get("cursor") == "0" {
				page.Events = []ModuleAlertEvent{
					{Sequence: 1, ID: ID(), Time: Now(), Outcome: "succeeded", Findings: 2},
					{Sequence: 2, ID: ID(), Time: Now(), Outcome: "succeeded", Quarantined: 1},
					{Sequence: 3, ID: ID(), Time: Now(), Outcome: "succeeded", Restored: 1},
					{Sequence: 4, ID: ID(), Time: Now(), Outcome: "succeeded"},
					{Sequence: 5, ID: ID(), Time: Now(), Outcome: "failed"},
				}
			}
		}
		data, _ := json.Marshal(page)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}}
	if err := a.collectOneModuleNotification(context.Background(), "php-code-security"); err != nil {
		t.Fatal(err)
	}
	var received []OutboundMessage
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var message OutboundMessage
		if json.Unmarshal(data, &message) != nil || message.Kind != "php-security" || !strings.Contains(message.Message, "不等于已确认后门") {
			t.Error("misleading PHP alert", string(data))
		}
		if r.Header.Get("X-Yunzhan-Signature") != webhookSignature("fixture-signing-secret", r.Header.Get("X-Yunzhan-Delivery-ID"), r.Header.Get("X-Yunzhan-Timestamp"), data) {
			t.Error("invalid HMAC")
		}
		received = append(received, message)
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	channel, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "PHP only", URL: receiver.URL, Secret: "fixture-signing-secret", Enabled: true, Kinds: []string{"php-security"}})
	if err != nil {
		t.Fatal(err)
	}
	stage = 1
	for i := 0; i < 2; i++ {
		if err = a.collectOneModuleNotification(context.Background(), "php-code-security"); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err = a.dispatchOutbound(context.Background(), webhookHTTPClient()); err != nil {
			t.Fatal(err)
		}
	}
	if len(received) != 4 {
		t.Fatal("blank report alerted or PHP event missing", len(received))
	}
	severities := map[string]int{}
	for _, message := range received {
		severities[message.Severity]++
	}
	if severities["warning"] != 1 || severities["info"] != 2 || severities["critical"] != 1 {
		t.Fatal(received)
	}
	history, err := s.NotificationDeliveryHistory(channel.ID)
	if err != nil || len(history) != 4 {
		t.Fatal(history, err)
	}
	for _, row := range history {
		if row["state"] != "succeeded" {
			t.Fatal(row)
		}
	}
}

// Real installed application + source ledger + HMAC HTTP delivery. The caller
// supplies only an owned isolated site; production/main use is rejected.
func TestOutboundLivePHPCodeSecurity(t *testing.T) {
	socket, siteID := os.Getenv("PANEL_OUTBOUND_QA_SOCKET"), os.Getenv("PANEL_PHP_QA_SITE")
	if socket == "" || siteID == "" {
		t.Skip("isolated real PHP application acceptance is opt-in")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") || socket != "/run/panel-executor/control.sock" || !ValidID(siteID) {
		t.Fatal("not an authorized isolated fixture")
	}
	root := filepath.Join("/srv/panel/sites", siteID)
	marker, err := os.ReadFile(filepath.Join(root, ".panel-site.json"))
	if err != nil {
		t.Fatal(err)
	}
	var owner map[string]string
	if json.Unmarshal(marker, &owner) != nil || owner["id"] != siteID || !strings.HasPrefix(owner["domain"], "php-security-") {
		t.Fatal("site is not the owned PHP QA fixture")
	}
	s, a := outboundFixture(t)
	a.Executor = NewExecutorClient(socket)
	if err = a.collectOneModuleNotification(context.Background(), "php-code-security"); err != nil {
		t.Fatal(err)
	}
	var received []OutboundMessage
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		var message OutboundMessage
		if len(data) > 4096 || json.Unmarshal(data, &message) != nil || message.Kind != "php-security" {
			t.Error("invalid live PHP summary")
		}
		for _, private := range []string{"<?php", "risk.php", siteID, "sha256", ".panel-files"} {
			if strings.Contains(string(data), private) {
				t.Error("source evidence leaked", private)
			}
		}
		if r.Header.Get("X-Yunzhan-Signature") != webhookSignature("fixture-signing-secret", r.Header.Get("X-Yunzhan-Delivery-ID"), r.Header.Get("X-Yunzhan-Timestamp"), data) {
			t.Error("invalid live HMAC")
		}
		received = append(received, message)
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	channel, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "owned live PHP QA", URL: receiver.URL, Secret: "fixture-signing-secret", Enabled: true, Kinds: []string{"php-security"}})
	if err != nil {
		t.Fatal(err)
	}
	module := func(action string, in AppModuleInput) map[string]any {
		t.Helper()
		var out map[string]any
		if err := a.Executor.Call(context.Background(), "POST", "/v1/app-modules/php-code-security/"+action, in, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	scan := module("run", AppModuleInput{SiteID: siteID, Search: "risk.php"})
	findings, ok := scan["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatal("no actual scan evidence")
	}
	row := findings[0].(map[string]any)
	path, sha := row["path"].(string), row["sha256"].(string)
	if !strings.HasSuffix(path, "risk.php") {
		t.Fatal("unexpected scanned file")
	}
	q := module("quarantine", AppModuleInput{SiteID: siteID, Path: path, ExpectedSHA: sha, Confirm: "QUARANTINE " + path})["record"].(map[string]any)
	id := q["id"].(string)
	module("restore-quarantine", AppModuleInput{SiteID: siteID, Path: path, ExpectedSHA: sha, ResourceID: id, ExpectedRevision: int64(q["revision"].(float64)), Confirm: "RESTORE PHP " + id})
	for i := 0; i < 2; i++ {
		if err = a.collectOneModuleNotification(context.Background(), "php-code-security"); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(received) < 3 && time.Now().Before(deadline) {
		if err = a.dispatchOutbound(context.Background(), webhookHTTPClient()); err != nil {
			t.Fatal(err)
		}
	}
	if len(received) != 3 {
		t.Fatal("real scan/isolation/restore not delivered once each", len(received))
	}
	history, err := s.NotificationDeliveryHistory(channel.ID)
	if err != nil || len(history) != 3 {
		t.Fatal(history, err)
	}
	for _, row := range history {
		if row["state"] != "succeeded" {
			t.Fatal(row)
		}
	}
	t.Log("real installed PHP scan/quarantine/restore ledger, exact-once collection and 3 verified HMAC HTTP deliveries; source and backups retained")
}
