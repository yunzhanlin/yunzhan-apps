//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

const dailyNativeManifestSHA = "d2206cd73effb24c4d5f744b018dbd820416f1b35e5032c8aa46c7997e976126"

// Exact official package bytes travel through the normal default-key verifier;
// this transport does not pretend to test public GitHub availability.
type dailyNativePackageTransport struct {
	body  []byte
	calls atomic.Int32
}

func (p *dailyNativePackageTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != "GET" || r.URL.String() != appcatalog.DefaultBaseURL+"/dist/apps/daily-report/1.4.0/manifest.json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Context().Err() != nil {
		return nil, errors.New("owned daily fixture refuses unrelated repository traffic")
	}
	p.calls.Add(1)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(p.body)), ContentLength: int64(len(p.body)), Request: r}, nil
}

// One bounded loopback TLS relay acknowledges the real sender's DATA. This
// establishes relay acceptance, not an external provider or inbox delivery.
func dailyNativeSMTP(t *testing.T) (core.SMTPNotificationInput, <-chan string) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned daily QA CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"mail.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	received, done := make(chan string, 1), make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if conn.SetDeadline(time.Now().Add(4*time.Second)) != nil {
			return
		}
		reader := textproto.NewReader(bufio.NewReader(conn))
		write := func(s string) bool { _, err := io.WriteString(conn, s); return err == nil }
		if !write("220 owned TLS relay\r\n") {
			return
		}
		for {
			line, err := reader.ReadLine()
			if err != nil {
				return
			}
			switch strings.ToUpper(strings.SplitN(line, " ", 2)[0]) {
			case "EHLO":
				if !write("250-mail.example.test\r\n250 8BITMIME\r\n") {
					return
				}
			case "MAIL", "RCPT":
				if !write("250 accepted\r\n") {
					return
				}
			case "DATA":
				if !write("354 data\r\n") {
					return
				}
				body, err := io.ReadAll(io.LimitReader(reader.DotReader(), (16<<10)+1))
				if err != nil || len(body) > 16<<10 {
					return
				}
				if !write("250 queued by owned TLS relay\r\n") {
					return
				}
				received <- string(body)
			case "QUIT":
				write("221 bye\r\n")
				return
			default:
				write("500 excluded command\r\n")
				return
			}
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("own TLS relay did not exit")
		}
	})
	return core.SMTPNotificationInput{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, TLSMode: "tls", ServerName: "mail.example.test", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), AuthMode: "none", From: "panel@example.test", To: []string{"recipient@example.test"}}, received
}

func TestDailyReportSignedCoreUnixNative(t *testing.T) {
	if os.Getenv("PANEL_QA_DAILY_NATIVE") != "1" {
		t.Skip("explicit owned private daily fixture required")
	}
	const base = "/run/panel-daily-native24axh"
	var marker struct {
		Format int    `json:"format"`
		Unit   string `json:"unit"`
	}
	if os.Geteuid() != 0 || readAnalyticsHTMLPrivateJSON(filepath.Join(base, "fixture.json"), 2048, &marker) != nil || marker.Format != 1 || !regexp.MustCompile(`^panel-own-daily24axh-[a-f0-9]{8}\.service$`).MatchString(marker.Unit) {
		t.Fatal("unverified owned daily fixture")
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || string(cgroup) != "0::/system.slice/"+marker.Unit+"\n" {
		t.Fatal("not the exact owned daily cgroup", err)
	}
	policy, err := os.ReadFile("/proc/self/status")
	if err != nil || !regexp.MustCompile(`(?m)^CapEff:\s+0000000000000000$`).Match(policy) || !regexp.MustCompile(`(?m)^CapBnd:\s+0000000000000000$`).Match(policy) || !regexp.MustCompile(`(?m)^NoNewPrivs:\s+1$`).Match(policy) {
		t.Fatal("native daily requires C0/NNP1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	first := Snapshot()
	if first["cpu_percent"] != nil || first["cpu_available"] != false || first["memory_available"] != true || first["disk_percent_available"] != true {
		t.Fatal("first actual Linux CPU sample must be unknown, with separately valid memory and disk observations")
	}
	for _, name := range []string{"data", "web", "security", "state", "sites", "conf", "system"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	svc := New(Config{SecurityDir: filepath.Join(base, "security"), StateDir: filepath.Join(base, "state"), SitesDir: filepath.Join(base, "sites"), ConfDir: filepath.Join(base, "conf"), SystemRoot: filepath.Join(base, "system"), Run: func(ctx context.Context, name string, args ...string) (string, error) {
		if name != "/usr/bin/systemctl" || len(args) != 2 || args[0] != "is-active" || args[1] != "nginx" {
			return "", errors.New("owned daily fixture refuses mutations and unrelated commands")
		}
		return RunCommand(ctx, name, args...)
	}})
	store, err := core.OpenStore(filepath.Join(base, "data/panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	socket := filepath.Join(base, "executor.sock")
	panel, err := core.NewServer(store, core.Config{DataDir: filepath.Join(base, "data"), WebDir: filepath.Join(base, "web"), Origin: "http://127.0.0.1:19498", Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(panel.Executor.Client.CloseIdleConnections)
	listener, err := net.Listen("unix", socket)
	if err != nil || os.Chmod(socket, 0600) != nil {
		t.Fatal("actual private daily Unix listener", err)
	}
	var installs, overviews atomic.Int32
	handler := svc.Handler()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := r.Method == "GET" && (r.URL.Path == "/v1/software" || r.URL.Path == "/v1/app-modules/daily-report" || r.URL.Path == "/v1/module-alert-events")
		if r.Method == "GET" && r.URL.Path == "/v1/overview" {
			allowed = true
			overviews.Add(1)
		}
		if r.Method == "POST" && r.URL.Path == "/v1/sites/traffic" {
			allowed = true
		}
		if r.Method == "POST" && r.URL.Path == "/v1/software/daily-report/install" {
			allowed = installs.Add(1) == 1
		}
		if !allowed {
			respond(w, 503, map[string]string{"error": "owned daily fixture excludes unrelated endpoints"})
			return
		}
		handler.ServeHTTP(w, r)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Close() })
	request := func(method, path string, body []byte, csrf, key string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(ctx, method, panel.Config.Origin+path, bytes.NewReader(body))
		r.Header.Set("Origin", panel.Config.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		panel.ServeHTTP(w, r)
		return w
	}
	token, err := os.ReadFile(filepath.Join(base, "data/bootstrap-token"))
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, _ := json.Marshal(map[string]string{"username": "owned-daily-admin", "password": "owned-native-daily-password-long", "token": strings.TrimSpace(string(token))})
	if w := request("POST", "/api/bootstrap", bootstrap, "", "", nil); w.Code != 201 {
		t.Fatal("actual bootstrap", w.Code)
	}
	login := request("POST", "/api/login", []byte(`{"username":"owned-daily-admin","password":"owned-native-daily-password-long"}`), "", "", nil)
	var auth struct {
		CSRF string `json:"csrf"`
	}
	if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &auth) != nil || auth.CSRF == "" || len(login.Result().Cookies()) != 1 {
		t.Fatal("actual login", login.Code)
	}
	cookie := login.Result().Cookies()[0]
	var user string
	if err := store.DB.QueryRow(`SELECT id FROM users WHERE username='owned-daily-admin'`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	menus := func(raw string) {
		t.Helper()
		if _, err := store.DB.Exec(`INSERT INTO app_user_menus VALUES(?,?,1) ON CONFLICT(user_id) DO UPDATE SET menu_ids=excluded.menu_ids,revision=revision+1`, user, raw); err != nil {
			t.Fatal(err)
		}
	}
	menus(`["audit","runtimes","panel-access"]`)
	bundle, err := os.ReadFile(filepath.Join(base, "catalog-v1.bundle.json"))
	if err != nil || core.Hash(string(bundle)) != "c7e4925bb34c7f626e3eefa023be3d939aaae2f865069c6b85ffc6de804e965c" {
		t.Fatal("exact official catalog", err)
	}
	manifest, err := os.ReadFile(filepath.Join(base, "daily-manifest.json"))
	if err != nil || core.Hash(string(manifest)) != dailyNativeManifestSHA {
		t.Fatal("exact official daily manifest", err)
	}
	cache := filepath.Join(base, "data/app-registry/catalog")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(cache, "catalog-v1.bundle.json"), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	transport := &dailyNativePackageTransport{body: manifest}
	panel.AppCatalog = appcatalog.Default()
	panel.AppCatalog.HTTP = &http.Client{Transport: transport, Timeout: 2 * time.Second}
	catalog, info, err := panel.AppCatalog.LoadCatalog(ctx, cache, time.Minute)
	item, found := appcatalog.Find(catalog, "daily-report")
	if err != nil || info.Source != "verified-cache" || len(catalog.Apps) != 50 || !found || item.SHA256 != dailyNativeManifestSHA || item.Version != "1.4.0" || item.Provider != "panel-module" || item.Target != "daily-report" {
		t.Fatal("actual default-key daily catalog", err)
	}
	if svc.moduleInstalled("daily-report") {
		t.Fatal("fresh fixture must not fabricate installation")
	}
	body, _ := json.Marshal(map[string]any{"expected_version": item.Version, "expected_sha256": item.SHA256, "settings": map[string]any{}})
	queued := request("POST", "/api/app-registry/daily-report/install", body, auth.CSRF, "owned-daily-original-install", cookie)
	var job struct {
		ID string `json:"job_id"`
	}
	if queued.Code != 202 || json.Unmarshal(queued.Body.Bytes(), &job) != nil || !core.ValidID(job.ID) {
		t.Fatal("actual signed daily install queue", queued.Code)
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	// Daily modules are control jobs, not native dependency builds. Exercise
	// the same real worker as the panel with an empty private site store.
	go func() { core.RunWorker(workerCtx, store, panel.Executor); close(workerDone) }()
	t.Cleanup(func() {
		stopWorker()
		select {
		case <-workerDone:
		case <-time.After(time.Second):
			t.Error("own install worker did not stop")
		}
	})
	for {
		var state string
		if err := store.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, job.ID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state == "succeeded" {
			break
		}
		if state != "queued" && state != "running" {
			t.Fatal("actual daily installation failed", state)
		}
		select {
		case <-ctx.Done():
			t.Fatal("native daily 15-second context", ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	stopWorker()
	<-workerDone
	// Receipts are reconciled by the actual authenticated registry read;
	// never fabricate one merely because the executor finished its job.
	registryReply := request("GET", "/api/app-registry", nil, auth.CSRF, "", cookie)
	var registry core.AppRegistryPage
	if registryReply.Code != 200 || json.Unmarshal(registryReply.Body.Bytes(), &registry) != nil {
		t.Fatal("actual completed daily registry reconciliation", registryReply.Code)
	}
	known := false
	for _, row := range registry.Status {
		if row.ID == "daily-report" {
			known = row.StateKnown && row.Installed && row.Healthy && row.VersionKnown && row.InstalledVersion == item.Version
		}
	}
	if !known {
		t.Fatal("actual registry did not verify installed daily module")
	}
	var version, digest, target string
	if err := store.DB.QueryRow(`SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='daily-report'`).Scan(&version, &digest, &target); err != nil || version != item.Version || digest != item.SHA256 || target != item.Target || !svc.moduleInstalled("daily-report") || installs.Load() != 1 || transport.calls.Load() != 1 {
		t.Fatal("actual completed signed daily receipt", err)
	}
	if replay := request("POST", "/api/app-registry/daily-report/install", body, auth.CSRF, "owned-daily-original-install", cookie); replay.Code != 202 || installs.Load() != 1 || transport.calls.Load() != 1 {
		t.Fatal("original installation replay reexecuted", replay.Code)
	}
	webhookBody := make(chan []byte, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(b) > 4096 {
			t.Error("unbounded native webhook payload")
			w.WriteHeader(400)
			return
		}
		mac := hmac.New(sha256.New, []byte("owned-daily-webhook-secret"))
		fmt.Fprintf(mac, "%s.%s.", r.Header.Get("X-Yunzhan-Timestamp"), r.Header.Get("X-Yunzhan-Delivery-ID"))
		mac.Write(b)
		if !hmac.Equal([]byte(r.Header.Get("X-Yunzhan-Signature")), []byte("sha256="+hex.EncodeToString(mac.Sum(nil)))) {
			t.Error("native webhook signature mismatch")
			w.WriteHeader(403)
			return
		}
		select {
		case webhookBody <- b:
		default:
			t.Error("duplicate native webhook delivery")
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(receiver.Close)
	webhook, err := store.SaveNotificationChannel("", core.NotificationChannelInput{Name: "owned daily webhook", URL: receiver.URL, Secret: "owned-daily-webhook-secret", Enabled: true, Kinds: []string{"daily"}})
	if err != nil {
		t.Fatal(err)
	}
	smtpInput, smtpBody := dailyNativeSMTP(t)
	smtpChannel, err := store.SaveNotificationChannel("", core.NotificationChannelInput{Name: "owned daily TLS relay", Type: "smtp", SMTP: &smtpInput, Enabled: true, Kinds: []string{"daily"}})
	if err != nil {
		t.Fatal(err)
	}
	// The normal worker also performs a real monitoring read in this private
	// store. Observe it separately; an existing background read is not a
	// generation dispatched by a denied request.
	producerBefore := overviews.Load()
	for _, denied := range []struct {
		csrf   string
		cookie *http.Cookie
		code   int
	}{{"", nil, 401}, {"wrong", cookie, 403}} {
		if w := request("POST", "/api/app-modules/daily-report/run", []byte(`{}`), denied.csrf, "", denied.cookie); w.Code != denied.code || overviews.Load() != producerBefore {
			t.Fatal("denied generation reached actual producer", w.Code)
		}
	}
	menus(`[]`)
	if w := request("POST", "/api/app-modules/daily-report/run", []byte(`{}`), auth.CSRF, "", cookie); w.Code != 403 || overviews.Load() != producerBefore {
		t.Fatal("revoked audit grant generated report", w.Code)
	}
	menus(`["audit","runtimes","panel-access"]`)
	var snapshot map[string]any
	for i := 0; i < 2; i++ {
		w := request("POST", "/api/app-modules/daily-report/run", []byte(`{}`), auth.CSRF, "", cookie)
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &snapshot) != nil {
			t.Fatal("actual Core Unix daily generation", w.Code, w.Body.String())
		}
	}
	resources, ok := snapshot["resources"].(map[string]any)
	if !ok || resources["arch"] == nil || resources["memory_available"] != true || resources["disk_percent_available"] != true || resources["memory_percent"] == nil || resources["disk_percent"] == nil || snapshot["sites"] != float64(0) || snapshot["running_sites"] != float64(0) || overviews.Load()-producerBefore != 2 {
		t.Fatal("actual Linux resource snapshot unavailable")
	}
	var reports, events int
	store.DB.QueryRow(`SELECT count(*) FROM app_daily_reports`).Scan(&reports)
	store.DB.QueryRow(`SELECT count(*) FROM notifications WHERE source='daily-report'`).Scan(&events)
	if reports != 1 || events != 1 {
		t.Fatal("refresh duplicated day or source event", reports, events)
	}
	notifyCtx, stopNotify := context.WithCancel(ctx)
	defer stopNotify()
	panel.StartOutboundNotifications(notifyCtx)
	var received []byte
	var mailBody string
	for received == nil || mailBody == "" {
		select {
		case b := <-webhookBody:
			received = b
		case b := <-smtpBody:
			mailBody = b
		case <-ctx.Done():
			t.Fatal("actual relay acceptance exceeded 15-second context", ctx.Err())
		}
	}
	for {
		var succeeded int
		store.DB.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE state='succeeded' AND channel_id IN (?,?)`, webhook.ID, smtpChannel.ID).Scan(&succeeded)
		if succeeded == 2 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("relay state not committed", ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	stopNotify()
	mailMessage, err := mail.ReadMessage(strings.NewReader(mailBody))
	if err != nil || mailMessage.Header.Get("Content-Transfer-Encoding") != "base64" || !core.ValidID(mailMessage.Header.Get("X-Yunzhan-Delivery-ID")) {
		t.Fatal("actual native SMTP MIME envelope invalid", err)
	}
	decodedMail, err := io.ReadAll(io.LimitReader(base64.NewDecoder(base64.StdEncoding, mailMessage.Body), (16<<10)+1))
	if err != nil || len(decodedMail) > 16<<10 {
		t.Fatal("actual native SMTP body cannot be decoded within budget", err)
	}
	title, err := (&mime.WordDecoder{}).DecodeHeader(mailMessage.Header.Get("Subject"))
	if err != nil || title != "每日运维报告" {
		t.Fatal("native automatic SMTP summary labelled as something else", err)
	}
	var delivered core.OutboundMessage
	if json.Unmarshal(received, &delivered) != nil || delivered.Report == nil || delivered.Test || !delivered.Report.CountAvailable["sites"] || delivered.Report.Sites != 0 || delivered.Report.Resources.Memory == nil || *delivered.Report.Resources.Memory != resources["memory_percent"].(float64) || strings.Contains(string(received), "hostname") || strings.Contains(string(received), "owned-native-daily-password") || !strings.Contains(string(decodedMail), fmt.Sprintf("内存：%.1f%%", *delivered.Report.Resources.Memory)) || !strings.Contains(string(decodedMail), "网站：0（运行 0）") {
		t.Fatal("native sanitized content mismatched actual snapshot")
	}
	var status int
	if err := store.DB.QueryRow(`SELECT http_status FROM notification_deliveries WHERE channel_id=?`, smtpChannel.ID).Scan(&status); err != nil || status != 250 {
		t.Fatal("actual TLS relay acceptance not recorded", status, err)
	}
	// Fresh private fault material, not repair of a production report. The
	// real queue must preserve a bad source, continue a later good event and
	// reconcile only its original public identity through authenticated Core.
	if _, err := store.DB.Exec(`INSERT INTO app_daily_reports VALUES('2001-01-02','{',?)`, core.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueDailyNotification("2001-01-02"); err != nil {
		t.Fatal(err)
	}
	good, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec(`INSERT INTO app_daily_reports VALUES('2001-01-03',?,?)`, string(good), core.Now()); err != nil {
		t.Fatal(err)
	}
	if err = store.QueueDailyNotification("2001-01-03"); err != nil {
		t.Fatal(err)
	}
	if err = store.QueueOutboundNotifications(); err == nil {
		t.Fatal("actual native source block silently hidden")
	}
	var later int
	if err = store.DB.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE json_extract(payload,'$.report.day')='2001-01-03' AND state='pending'`).Scan(&later); err != nil || later != 2 {
		t.Fatal("bad source blocked later native channel delivery", later, err)
	}
	path := "/api/notification-channels/" + webhook.ID + "/deliveries"
	history := request("GET", path, nil, auth.CSRF, "", cookie)
	var sourcePage struct {
		Blocked []struct {
			ID      string `json:"id"`
			EventID string `json:"event_id"`
			SHA     string `json:"source_sha"`
			State   string `json:"state"`
			Day     string `json:"day"`
		} `json:"blocked_sources"`
		Total int `json:"blocked_source_total"`
	}
	if history.Code != 200 || json.Unmarshal(history.Body.Bytes(), &sourcePage) != nil || sourcePage.Total != 1 || len(sourcePage.Blocked) != 1 || sourcePage.Blocked[0].State != "source_blocked" || sourcePage.Blocked[0].Day != "2001-01-02" {
		t.Fatal("actual Core source inventory incomplete", history.Code)
	}
	source := sourcePage.Blocked[0]
	reconcilePath := "/api/notification-channels/" + webhook.ID + "/sources/" + source.ID + "/reconcile"
	reconcileBody, _ := json.Marshal(map[string]any{"revision": webhook.Revision, "expected_sha": source.SHA})
	if w := request("POST", reconcilePath, reconcileBody, "wrong", "", cookie); w.Code != 403 {
		t.Fatal("native source reconciliation accepted bad CSRF", w.Code)
	}
	if w := request("POST", reconcilePath, reconcileBody, auth.CSRF, "", cookie); w.Code != 409 {
		t.Fatal("bad report was reconciled as a valid source", w.Code)
	}
	var retained string
	if err = store.DB.QueryRow(`SELECT report FROM app_daily_reports WHERE day='2001-01-02'`).Scan(&retained); err != nil || retained != "{" {
		t.Fatal("native queue changed bad original source", err)
	}
	if _, err = store.DB.Exec(`UPDATE app_daily_reports SET report=? WHERE day='2001-01-02'`, string(good)); err != nil {
		t.Fatal(err)
	}
	menus(`["audit","runtimes"]`)
	if w := request("POST", reconcilePath, reconcileBody, auth.CSRF, "", cookie); w.Code != 403 {
		t.Fatal("native revoked menu reconciled source", w.Code)
	}
	menus(`["audit","runtimes","panel-access"]`)
	if _, err = store.DB.Exec(`CREATE TRIGGER owned_daily_source_audit_fault BEFORE INSERT ON audit_logs WHEN NEW.action='notification.source.reconcile' BEGIN SELECT RAISE(ABORT,'owned source audit fault'); END`); err != nil {
		t.Fatal(err)
	}
	if w := request("POST", reconcilePath, reconcileBody, auth.CSRF, "", cookie); w.Code != 409 {
		t.Fatal("native source audit failure reported success", w.Code)
	}
	var blocked string
	var originalDeliveries int
	if err = store.DB.QueryRow(`SELECT state,(SELECT count(*) FROM notification_deliveries WHERE event_id=?) FROM notification_source_blocks WHERE id=?`, source.EventID, source.ID).Scan(&blocked, &originalDeliveries); err != nil || blocked != "blocked" || originalDeliveries != 0 {
		t.Fatal("native source audit failure partially committed", blocked, originalDeliveries, err)
	}
	if _, err = store.DB.Exec(`DROP TRIGGER owned_daily_source_audit_fault`); err != nil {
		t.Fatal(err)
	}
	var sourceReceipt map[string]any
	for i := 0; i < 2; i++ {
		w := request("POST", reconcilePath, reconcileBody, auth.CSRF, "", cookie)
		if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &sourceReceipt) != nil || sourceReceipt["id"] != source.ID || sourceReceipt["event_id"] != source.EventID || sourceReceipt["state"] != "resolved" || sourceReceipt["already_resolved"] != (i == 1) {
			t.Fatal("native source original identity replay failed", w.Code)
		}
	}
	if err = store.DB.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE event_id=?`, source.EventID).Scan(&originalDeliveries); err != nil || originalDeliveries != 1 {
		t.Fatal("native source reconcile duplicated delivery", originalDeliveries, err)
	}
	t.Log("PASS actual native authenticated original source isolation, following valid events, CSRF/current menu, audit rollback and idempotent original reconciliation; queued is not sent")
	if err := moduleWrite(filepath.Join(base, "acceptance.json"), map[string]any{
		"passed": true, "actual_core_login_csrf_current_audit_permission": true,
		"actual_signed_default_catalog_worker_install": true, "manifest_sha256": digest, "installed_version": version,
		"manifest_pulls": transport.calls.Load(), "executor_installs": installs.Load(),
		"actual_core_unix_linux_resource_generation": true, "generations": overviews.Load() - producerBefore,
		"actual_first_cpu_observation_unknown":              true,
		"actual_native_source_isolation_keeps_bad_original": true, "actual_native_good_events_follow_blocked_source": true,
		"actual_native_source_reconcile_current_actor_csrf": true, "actual_native_source_reconcile_audit_atomic": true, "actual_native_source_reconcile_original_identity_idempotent": true,
		"separate_background_producer_reads": producerBefore, "one_saved_day_and_one_source_event": true,
		"actual_hmac_webhook_204_acceptance": true, "actual_verified_tls_smtp_250_acceptance": true,
		"smtp_acceptance_is_not_inbox_delivery": true, "observed_zero_counts_have_explicit_availability": true,
		"browser_verified": false, "live_github_verified": false, "cold_boot_verified": false,
		"main_panel_changed": false, "all_50_commercial": false,
	}); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS actual signed daily install, authenticated Core, private Unix Linux resources, HMAC webhook and verified TLS relay acceptance; not public provider or inbox delivery")
}
