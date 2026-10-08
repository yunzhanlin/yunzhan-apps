package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func smtpTestCertificate(t *testing.T, name string, expired bool) (tls.Certificate, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SMTP private QA CA"}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(24 * time.Hour)
	if expired {
		notAfter = time.Now().Add(-time.Hour)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, serverPublic, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: serverKey}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

type smtpTestReceiver struct {
	listener                          net.Listener
	configuration                     *tls.Config
	mode                              string
	noSTARTTLS                        bool
	authCode, dataCode, recipientCode int
	dropAfterAcceptance               bool
	mu                                sync.Mutex
	authAttempts, dataAttempts        int
	messages, submitted               []string
	entered                           chan struct{}
	holdGreeting                      bool
	wg                                sync.WaitGroup
}

func smtpReceiver(t *testing.T, mode, name string, expired bool, options ...func(*smtpTestReceiver)) (*smtpTestReceiver, SMTPNotificationInput) {
	t.Helper()
	certificate, ca := smtpTestCertificate(t, name, expired)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &smtpTestReceiver{listener: listener, configuration: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, mode: mode, entered: make(chan struct{}, 1)}
	for _, option := range options {
		option(r)
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			r.wg.Add(1)
			go func() { defer r.wg.Done(); r.serve(conn) }()
		}
	}()
	t.Cleanup(func() { listener.Close(); r.wg.Wait() })
	port := listener.Addr().(*net.TCPAddr).Port
	return r, SMTPNotificationInput{Host: "127.0.0.1", Port: port, TLSMode: mode, ServerName: "mail.example.test", CAPEM: ca, AuthMode: "plain", Username: "qa-user-not-echoed", Password: "qa-password-not-echoed", From: "sender@example.test", To: []string{"receiver@example.test"}}
}

func (r *smtpTestReceiver) serve(raw net.Conn) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(4 * time.Second))
	var connection net.Conn = raw
	secured := false
	if r.mode == "tls" {
		wrapped := tls.Server(raw, r.configuration)
		if wrapped.Handshake() != nil {
			return
		}
		connection, secured = wrapped, true
	}
	if r.holdGreeting {
		select {
		case r.entered <- struct{}{}:
		default:
		}
		var one [1]byte
		raw.Read(one[:])
		return
	}
	reader := textproto.NewReader(bufio.NewReader(connection))
	write := func(value string) bool { _, err := io.WriteString(connection, value); return err == nil }
	if !write("220 private SMTP QA\r\n") {
		return
	}
	for {
		line, err := reader.ReadLine()
		if err != nil {
			return
		}
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO":
			if !write("250-mail.example.test\r\n") {
				return
			}
			if !secured && !r.noSTARTTLS {
				if !write("250-STARTTLS\r\n") {
					return
				}
			}
			if !write("250 AUTH PLAIN LOGIN\r\n") {
				return
			}
		case "STARTTLS":
			if secured || r.noSTARTTLS {
				write("550 not available\r\n")
				continue
			}
			if !write("220 begin TLS\r\n") {
				return
			}
			wrapped := tls.Server(raw, r.configuration)
			if wrapped.Handshake() != nil {
				return
			}
			connection, secured = wrapped, true
			reader = textproto.NewReader(bufio.NewReader(connection))
		case "AUTH":
			r.mu.Lock()
			r.authAttempts++
			r.mu.Unlock()
			if !secured {
				write("535 unsafe authentication\r\n")
				return
			}
			parts := strings.Fields(line)
			valid := false
			if len(parts) == 3 && parts[1] == "PLAIN" {
				decoded, err := base64.StdEncoding.DecodeString(parts[2])
				valid = err == nil && string(decoded) == "\x00qa-user-not-echoed\x00qa-password-not-echoed"
			} else if len(parts) == 2 && parts[1] == "LOGIN" {
				if !write("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")) + "\r\n") {
					return
				}
				user, err := reader.ReadLine()
				if err != nil {
					return
				}
				if !write("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")) + "\r\n") {
					return
				}
				password, err := reader.ReadLine()
				if err != nil {
					return
				}
				valid = user == base64.StdEncoding.EncodeToString([]byte("qa-user-not-echoed")) && password == base64.StdEncoding.EncodeToString([]byte("qa-password-not-echoed"))
			}
			if !valid || r.authCode != 0 {
				code := r.authCode
				if code == 0 {
					code = 535
				}
				write(fmt.Sprintf("%d private password must not be reported\r\n", code))
				continue
			}
			if !write("235 authenticated\r\n") {
				return
			}
		case "MAIL":
			if !secured {
				return
			}
			if !write("250 sender accepted\r\n") {
				return
			}
		case "RCPT":
			code := r.recipientCode
			if code == 0 {
				code = 250
			}
			if !write(fmt.Sprintf("%d recipient reply with private address\r\n", code)) {
				return
			}
		case "DATA":
			if !secured || !write("354 send body\r\n") {
				return
			}
			data, err := reader.ReadDotBytes()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.dataAttempts++
			r.submitted = append(r.submitted, string(data))
			code := r.dataCode
			if code == 0 {
				code = 250
			}
			if code == 250 {
				r.messages = append(r.messages, string(data))
			}
			r.mu.Unlock()
			if !write(fmt.Sprintf("%d DATA reply with private text\r\n", code)) {
				return
			}
			if code == 250 && r.dropAfterAcceptance {
				return
			}
		case "QUIT":
			write("221 bye\r\n")
			return
		default:
			if !write("500 unsupported\r\n") {
				return
			}
		}
	}
}

func smtpQueuedDelivery(t *testing.T, kind string) outboundDelivery {
	t.Helper()
	message := safeOutboundMessage(Notification{ID: ID(), Kind: kind, Severity: "info", CreatedAt: time.Now().Unix()})
	if kind == "daily" {
		message.Report = &OutboundDailySummary{Day: "2026-10-08", Sites: 5, RunningSites: 4, CertificatesDue: 2}
		value := 40.5
		message.Report.Resources.Memory = &value
	}
	raw, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return outboundDelivery{ID: ID(), Payload: string(raw), Type: "smtp", Attempts: 1}
}

func smtpParsedBody(t *testing.T, raw string) (mail.Header, string) {
	t.Helper()
	message, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, message.Body))
	if err != nil {
		t.Fatal(err)
	}
	return message.Header, string(body)
}

func TestOutboundSMTPRealTLSModesAuthenticationAndPrivacy(t *testing.T) {
	for _, mode := range []string{"tls", "starttls"} {
		for _, authentication := range []string{"plain", "login", "none"} {
			t.Run(mode+"/"+authentication, func(t *testing.T) {
				r, input := smtpReceiver(t, mode, "mail.example.test", false, func(r *smtpTestReceiver) { r.dropAfterAcceptance = true })
				input.AuthMode = authentication
				if authentication == "none" {
					input.Username, input.Password = "", ""
				}
				delivery := smtpQueuedDelivery(t, "daily")
				var injected map[string]any
				json.Unmarshal([]byte(delivery.Payload), &injected)
				injected["title"], injected["message"], injected["private"] = "private secret title", "private secret output", "private credential"
				altered, _ := json.Marshal(injected)
				delivery.Payload = string(altered)
				code, message, _ := sendSMTPNotification(context.Background(), delivery, &input)
				if code != 250 || message != "" {
					t.Fatal("TLS SMTP relay acceptance failed", code, message)
				}
				r.mu.Lock()
				defer r.mu.Unlock()
				if len(r.messages) != 1 || r.dataAttempts != 1 || (authentication != "none" && r.authAttempts != 1) || (authentication == "none" && r.authAttempts != 0) {
					t.Fatal("unexpected actual acceptance/authentication counts")
				}
				header, body := smtpParsedBody(t, r.messages[0])
				decoded, err := (&mime.WordDecoder{}).DecodeHeader(header.Get("Subject"))
				if err != nil || decoded != "每日运维报告" || header.Get("Message-ID") != "<yunzhan."+delivery.ID+"@example.test>" || header.Get("X-Yunzhan-Delivery-ID") != delivery.ID || !strings.Contains(body, "网站：5（运行 4）") || !strings.Contains(body, "内存：40.5%") || strings.Contains(body, "private") || strings.Contains(r.messages[0], "qa-password") {
					t.Fatal("MIME/privacy/stable message identity verification failed")
				}
			})
		}
	}
}

func TestOutboundSMTPInvalidCertificatesNeverSendAuthenticationOrData(t *testing.T) {
	for _, mode := range []string{"tls", "starttls"} {
		for _, invalid := range []string{"unknown-ca", "wrong-name", "expired", "old-tls"} {
			t.Run(mode+"/"+invalid, func(t *testing.T) {
				name := "mail.example.test"
				if invalid == "wrong-name" {
					name = "wrong.example.test"
				}
				r, input := smtpReceiver(t, mode, name, invalid == "expired", func(r *smtpTestReceiver) {
					if invalid == "old-tls" {
						r.configuration.MinVersion, r.configuration.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
					}
				})
				if invalid == "unknown-ca" {
					input.CAPEM = ""
				}
				code, message, _ := sendSMTPNotification(context.Background(), smtpQueuedDelivery(t, "test"), &input)
				if message == "" || code == 250 {
					t.Fatal("invalid TLS accepted", code)
				}
				r.mu.Lock()
				defer r.mu.Unlock()
				if r.authAttempts != 0 || r.dataAttempts != 0 || len(r.messages) != 0 {
					t.Fatal("credentials or message crossed invalid TLS")
				}
			})
		}
	}
}

func TestOutboundSMTPMissingSTARTTLSAndPermanentRejections(t *testing.T) {
	for _, mode := range []string{"missing-starttls", "authentication", "recipient", "data"} {
		t.Run(mode, func(t *testing.T) {
			r, input := smtpReceiver(t, "starttls", "mail.example.test", false, func(r *smtpTestReceiver) {
				r.noSTARTTLS = mode == "missing-starttls"
				if mode == "authentication" {
					r.authCode = 535
				}
				if mode == "recipient" {
					r.recipientCode = 550
				}
				if mode == "data" {
					r.dataCode = 550
				}
			})
			code, message, _ := sendSMTPNotification(context.Background(), smtpQueuedDelivery(t, "test"), &input)
			if code < 500 || message == "" || strings.Contains(message, "private") || strings.Contains(message, "qa-password") {
				t.Fatal("permanent or sanitized SMTP error failed", code, message)
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			if len(r.messages) != 0 || (mode == "missing-starttls" && r.authAttempts != 0) || (mode != "data" && r.dataAttempts != 0) {
				t.Fatal("rejected SMTP operation delivered mail")
			}
		})
	}
}

func TestOutboundSMTPEncryptedConfigurationLegacyCompatibilityAndRevision(t *testing.T) {
	s, _ := outboundFixture(t)
	_, input := smtpReceiver(t, "tls", "mail.example.test", false)
	c, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "SMTP QA", Type: "smtp", SMTP: &input, Enabled: true, Kinds: []string{"daily"}})
	if err != nil || c.Type != "smtp" || c.SMTP == nil || !c.SMTP.PasswordSet || !c.SMTP.UsernameSet {
		t.Fatal("SMTP configuration not readable", err)
	}
	raw, _ := json.Marshal(c)
	if bytes.Contains(raw, []byte(input.Username)) || bytes.Contains(raw, []byte(input.Password)) {
		t.Fatal("public configuration echoed credentials")
	}
	var encrypted []byte
	if err = s.DB.QueryRow(`SELECT credential FROM notification_channels WHERE id=?`, c.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(input.Password)) || bytes.Contains(encrypted, []byte(input.Username)) {
		t.Fatal("SMTP credentials stored plaintext")
	}
	if _, err = decryptCredential(s.encryptionKey, "notification-channel:"+ID(), encrypted); err == nil {
		t.Fatal("credential cipher not bound to channel identity")
	}
	edit := input
	edit.Username, edit.Password = "", ""
	updated, err := s.SaveNotificationChannel(c.ID, NotificationChannelInput{Name: c.Name, SMTP: &edit, Enabled: false, Kinds: c.Kinds, Revision: c.Revision})
	if err != nil || updated.Revision != c.Revision+1 || !updated.SMTP.PasswordSet {
		t.Fatal("blank edit did not preserve encrypted credentials", err)
	}
	if _, err = s.SaveNotificationChannel(c.ID, NotificationChannelInput{Name: c.Name, Enabled: true, Kinds: c.Kinds, Revision: c.Revision}); err == nil {
		t.Fatal("stale SMTP revision accepted")
	}
	if _, err = s.SaveNotificationChannel(c.ID, NotificationChannelInput{Name: c.Name, Type: "webhook", URL: "http://127.0.0.1:12345", Secret: "fixture-signing-secret", Kinds: c.Kinds, Revision: updated.Revision}); err == nil {
		t.Fatal("in-place protocol replacement accepted")
	}
	legacy := outboundCreate(t, s, "http://127.0.0.1:12345")
	old, _ := json.Marshal(struct{ URL, Secret string }{URL: "http://127.0.0.1:12345", Secret: "fixture-signing-secret"})
	oldCipher, err := encryptCredential(s.encryptionKey, "notification-channel:"+legacy.ID, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`UPDATE notification_channels SET credential=? WHERE id=?`, oldCipher, legacy.ID); err != nil {
		t.Fatal(err)
	}
	channels, err := s.NotificationChannels()
	if err != nil || len(channels) != 2 || channels[1].Type != "webhook" || channels[1].SMTP != nil {
		t.Fatal("original URL/Secret-only envelope compatibility lost", err)
	}
}

func TestOutboundSMTPConfigurationRejectsUnsafeInputs(t *testing.T) {
	_, valid := smtpReceiver(t, "tls", "mail.example.test", false)
	for _, alter := range []func(*SMTPNotificationInput){
		func(v *SMTPNotificationInput) { v.TLSMode = "plaintext" },
		func(v *SMTPNotificationInput) { v.Host = "169.254.169.254" },
		func(v *SMTPNotificationInput) { v.Host = "224.0.0.1" },
		func(v *SMTPNotificationInput) { v.Host = "fe80::1%eth0" },
		func(v *SMTPNotificationInput) { v.ServerName = "MAIL.EXAMPLE.TEST" },
		func(v *SMTPNotificationInput) { v.From = "sender@example.test\r\nBcc: other@example.test" },
		func(v *SMTPNotificationInput) { v.To = []string{"Display Name <receiver@example.test>"} },
		func(v *SMTPNotificationInput) { v.To = []string{"receiver@example.test", "receiver@example.test"} },
		func(v *SMTPNotificationInput) { v.To = nil },
		func(v *SMTPNotificationInput) { v.Password = "unsafe\x00password" },
		func(v *SMTPNotificationInput) { v.AuthMode = "none" },
		func(v *SMTPNotificationInput) {
			v.CAPEM = "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----"
		},
	} {
		candidate := valid
		candidate.To = append([]string(nil), valid.To...)
		alter(&candidate)
		if validateSMTPNotification(&candidate) == nil {
			t.Fatal("unsafe SMTP configuration accepted")
		}
	}
	connection := &smtpReadBudgetConn{remaining: 0}
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("unbounded SMTP response budget")
	}
	if _, _, err := (&smtpLoginAuth{username: "user", password: "secret", host: "mail.example.test"}).Start(&smtp.ServerInfo{Name: "mail.example.test", TLS: false}); err == nil {
		t.Fatal("LOGIN accepted plaintext state")
	}
	login := &smtpLoginAuth{username: "user", password: "secret", host: "mail.example.test"}
	if _, err := login.Next([]byte("Password:"), true); err == nil {
		t.Fatal("LOGIN sent secret before expected challenge")
	}
}

func TestOutboundSMTPPersistentRetryUsesSameMessageIdentityAndPermanentFailure(t *testing.T) {
	s, a := outboundFixture(t)
	r, input := smtpReceiver(t, "starttls", "mail.example.test", false, func(r *smtpTestReceiver) { r.dataCode = 451 })
	c, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "SMTP retry QA", Type: "smtp", SMTP: &input, Enabled: true, Kinds: []string{"daily"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO app_daily_reports VALUES('2026-10-08','{"sites":5,"running_sites":4,"private_password":"do-not-forward"}',?)`, Now()); err != nil {
		t.Fatal(err)
	}
	if err = s.QueueDailyNotification("2026-10-08"); err != nil {
		t.Fatal(err)
	}
	if err = s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	if err = a.dispatchOutbound(context.Background(), webhookHTTPClient()); err != nil {
		t.Fatal(err)
	}
	history, err := s.NotificationDeliveryHistory(c.ID)
	if err != nil || len(history) != 1 || history[0]["state"] != "pending" || history[0]["http_status"] != 451 || history[0]["attempts"] != 1 {
		t.Fatal("temporary SMTP failure did not persist retry", history, err)
	}
	id := history[0]["id"].(string)
	var next int64
	s.DB.QueryRow(`SELECT next_attempt_at FROM notification_deliveries WHERE id=?`, id).Scan(&next)
	if next < time.Now().Unix()+13 {
		t.Fatal("SMTP backoff was skipped")
	}
	r.mu.Lock()
	r.dataCode = 0
	r.mu.Unlock()
	if _, err = s.DB.Exec(`UPDATE notification_deliveries SET next_attempt_at=0 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	restarted := &Server{Store: s, accountSecretKey: s.encryptionKey}
	if err = restarted.dispatchOutbound(context.Background(), webhookHTTPClient()); err != nil {
		t.Fatal(err)
	}
	history, err = s.NotificationDeliveryHistory(c.ID)
	if err != nil || history[0]["state"] != "succeeded" || history[0]["http_status"] != 250 || history[0]["attempts"] != 2 || history[0]["id"] != id {
		t.Fatal("restarted SMTP worker lost actual acceptance or identity", history, err)
	}
	r.mu.Lock()
	submitted := append([]string(nil), r.submitted...)
	accepted := len(r.messages)
	r.mu.Unlock()
	if len(submitted) != 2 || submitted[0] != submitted[1] || accepted != 1 || strings.Contains(submitted[0], "do-not-forward") {
		t.Fatal("SMTP retry changed stable message or forwarded private report data")
	}
	for _, code := range []int{535, 550, 554} {
		_, err = s.DB.Exec(`INSERT INTO notification_deliveries(id,channel_id,channel_revision,event_id,payload,state,attempts,created_at) VALUES(?,?,?,?,?,'running',1,?)`, ID(), c.ID, c.Revision, ID(), "{}", time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		var rowID string
		s.DB.QueryRow(`SELECT id FROM notification_deliveries WHERE channel_id=? AND state='running'`, c.ID).Scan(&rowID)
		if err = s.completeOutbound(outboundDelivery{ID: rowID, Revision: c.Revision, Type: "smtp", Attempts: 1}, code, "SMTP 拒绝", 0, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
		var state string
		s.DB.QueryRow(`SELECT state FROM notification_deliveries WHERE id=?`, rowID).Scan(&state)
		if state != "failed" {
			t.Fatal("permanent SMTP code retried", strconv.Itoa(code))
		}
	}
}

func TestOutboundSMTPConnectionCancellationDoesNotWaitForReceiver(t *testing.T) {
	r, input := smtpReceiver(t, "tls", "mail.example.test", false, func(r *smtpTestReceiver) { r.holdGreeting = true })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan string, 1)
	go func() {
		_, message, _ := sendSMTPNotification(ctx, smtpQueuedDelivery(t, "test"), &input)
		done <- message
	}()
	select {
	case <-r.entered:
	case <-time.After(time.Second):
		t.Fatal("SMTP receiver not reached")
	}
	started := time.Now()
	cancel()
	select {
	case message := <-done:
		if message == "" || time.Since(started) > time.Second {
			t.Fatal("SMTP cancellation failed")
		}
	case <-time.After(time.Second):
		t.Fatal("SMTP waited for slow receiver after cancellation")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.authAttempts != 0 || r.dataAttempts != 0 {
		t.Fatal("SMTP cancellation leaked authentication/data")
	}
}

func TestOutboundDamagedCredentialIsolationAndEvidencePreservingPause(t *testing.T) {
	s, a := outboundFixture(t)
	_, input := smtpReceiver(t, "tls", "mail.example.test", false)
	first, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "damaged SMTP QA", Type: "smtp", SMTP: &input, Enabled: true, Kinds: []string{"daily"}})
	if err != nil {
		t.Fatal(err)
	}
	r, otherInput := smtpReceiver(t, "tls", "mail.example.test", false)
	other, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "working SMTP QA", Type: "smtp", SMTP: &otherInput, Enabled: true, Kinds: []string{"daily"}})
	if err != nil {
		t.Fatal(err)
	}
	broken := []byte("retained damaged ciphertext")
	if _, err = s.DB.Exec(`UPDATE notification_channels SET credential=? WHERE id=?`, broken, first.ID); err != nil {
		t.Fatal(err)
	}
	channels, err := s.NotificationChannels()
	if err != nil || len(channels) != 2 || channels[0].Type != "invalid" || channels[0].CredentialError == "" || channels[1].Type != "smtp" {
		t.Fatal("damaged envelope blocked unrelated channel", err)
	}
	if err = s.QueueDailyNotification("2026-10-08"); err != nil {
		t.Fatal(err)
	}
	if err = s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	if err = a.dispatchOutbound(context.Background(), webhookHTTPClient()); err != nil {
		t.Fatal(err)
	}
	history, err := s.NotificationDeliveryHistory(other.ID)
	if err != nil || len(history) != 1 || history[0]["state"] != "succeeded" {
		t.Fatal("damaged channel blocked actual SMTP delivery", history, err)
	}
	paused, err := s.SaveNotificationChannel(first.ID, NotificationChannelInput{Name: first.Name, Kinds: first.Kinds, Enabled: false, Revision: first.Revision})
	if err != nil || paused.Enabled || paused.Revision != first.Revision+1 || paused.CredentialError == "" {
		t.Fatal("damaged channel cannot be paused without replacing evidence", err)
	}
	var retained []byte
	if err = s.DB.QueryRow(`SELECT credential FROM notification_channels WHERE id=?`, first.ID).Scan(&retained); err != nil || !bytes.Equal(retained, broken) {
		t.Fatal("damaged cipher was overwritten", err)
	}
	history, err = s.NotificationDeliveryHistory(first.ID)
	if err != nil || len(history) != 1 || history[0]["state"] != "cancelled" {
		t.Fatal("damaged queue not cancelled on pause", history, err)
	}
	if _, err = s.SaveNotificationChannel(first.ID, NotificationChannelInput{Name: first.Name, Kinds: first.Kinds, Enabled: true, Revision: paused.Revision}); err == nil {
		t.Fatal("damaged channel re-enabled")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.messages) != 1 {
		t.Fatal("unrelated SMTP delivery not actually accepted")
	}
}

func TestOutboundSMTPDailyPreviewAuthenticatedAPIAndActualAcceptance(t *testing.T) {
	s := testStore(t)
	master := accessUser(t, s, "smtp-preview-owner", "", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", path, bytes.NewReader(raw))
		req.Header.Set("Origin", a.Config.Origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		a.ServeHTTP(response, req)
		return response
	}
	login := request("/api/login", map[string]string{"username": master.Username, "password": "access-test-password-long"}, nil, "")
	if login.Code != 200 {
		t.Fatal("authorized SMTP test owner login failed", login.Code)
	}
	var session accountSession
	if json.Unmarshal(login.Body.Bytes(), &session) != nil {
		t.Fatal("unreadable authorized session")
	}
	cookie := login.Result().Cookies()[0]
	r, input := smtpReceiver(t, "tls", "mail.example.test", false)
	c, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "SMTP daily preview", Type: "smtp", SMTP: &input, Enabled: true, Kinds: []string{"daily"}})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/notification-channels/" + c.ID + "/test"
	if reply := request(path, map[string]any{"revision": c.Revision, "daily": true}, nil, ""); reply.Code != 401 {
		t.Fatal("unauthenticated daily preview accepted", reply.Code)
	}
	if reply := request(path, map[string]any{"revision": c.Revision, "daily": true}, cookie, session.CSRF); reply.Code != 409 {
		t.Fatal("empty daily history generated invented report", reply.Code)
	}
	original := `{"sites":5,"running_sites":4,"private_password":"must-not-leave-panel","resources":{"memory_percent":30,"hostname":"private-host"}}`
	if _, err = s.DB.Exec(`INSERT INTO app_daily_reports VALUES('2026-10-08',?,?)`, original, Now()); err != nil {
		t.Fatal(err)
	}
	if reply := request(path, map[string]any{"revision": c.Revision + 1, "daily": true}, cookie, session.CSRF); reply.Code != 409 {
		t.Fatal("stale daily preview revision accepted", reply.Code)
	}
	if reply := request(path, map[string]any{"revision": c.Revision, "daily": true}, cookie, session.CSRF); reply.Code != 202 {
		t.Fatal("actual daily preview not queued", reply.Code, reply.Body.String())
	}
	if err = a.dispatchOutbound(context.Background(), webhookHTTPClient()); err != nil {
		t.Fatal(err)
	}
	history, err := s.NotificationDeliveryHistory(c.ID)
	if err != nil || len(history) != 1 || history[0]["state"] != "succeeded" || history[0]["http_status"] != 250 {
		t.Fatal("daily preview did not reach actual relay acceptance", history, err)
	}
	var retained string
	s.DB.QueryRow(`SELECT report FROM app_daily_reports WHERE day='2026-10-08'`).Scan(&retained)
	var autoEvents int
	s.DB.QueryRow(`SELECT count(*) FROM notifications WHERE source='daily-report'`).Scan(&autoEvents)
	if retained != original || autoEvents != 0 {
		t.Fatal("daily preview modified saved history or invented automatic event")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.messages) != 1 {
		t.Fatal("daily preview message not actually received")
	}
	header, body := smtpParsedBody(t, r.messages[0])
	title, err := (&mime.WordDecoder{}).DecodeHeader(header.Get("Subject"))
	if err != nil || title != "测试 · 每日运维报告" || !strings.Contains(body, "手动发送的测试摘要") || !strings.Contains(body, "网站：5（运行 4）") || strings.Contains(body, "must-not-leave-panel") || strings.Contains(body, "private-host") {
		t.Fatal("daily preview scope/privacy/test labeling failed")
	}
}

func TestOutboundLiveExecutorSMTPDailyReport(t *testing.T) {
	socket := os.Getenv("PANEL_OUTBOUND_SMTP_QA_SOCKET")
	if socket == "" {
		t.Skip("actual Linux resource producer requires explicit isolated QA opt-in")
	}
	if socket != "/run/panel-executor/control.sock" {
		t.Fatal("unrecognized isolated SMTP QA socket")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("SMTP native producer test restricted to the two isolated QA hosts")
	}
	s, a := outboundFixture(t)
	a.Executor = NewExecutorClient(socket)
	r, input := smtpReceiver(t, "starttls", "mail.example.test", false)
	c, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "actual native SMTP report QA", Type: "smtp", SMTP: &input, Enabled: true, Kinds: []string{"daily"}})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err = a.appDailyReport(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.QueueOutboundNotifications(); err != nil {
		t.Fatal(err)
	}
	if err = a.dispatchOutbound(context.Background(), webhookHTTPClient()); err != nil {
		t.Fatal(err)
	}
	history, err := s.NotificationDeliveryHistory(c.ID)
	if err != nil || len(history) != 1 || history[0]["state"] != "succeeded" || history[0]["http_status"] != 250 {
		t.Fatal("native SMTP daily acceptance or daily deduplication failed", history, err)
	}
	var payload string
	if err = s.DB.QueryRow(`SELECT payload FROM notification_deliveries WHERE channel_id=?`, c.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var message OutboundMessage
	if json.Unmarshal([]byte(payload), &message) != nil || message.Test || message.Report == nil || message.Report.Resources.Memory == nil || message.Report.Resources.Disk == nil {
		t.Fatal("native daily producer did not supply actual resource fields")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.messages) != 1 {
		t.Fatal("actual native daily SMTP message not received")
	}
	header, body := smtpParsedBody(t, r.messages[0])
	title, err := (&mime.WordDecoder{}).DecodeHeader(header.Get("Subject"))
	if err != nil || title != "每日运维报告" || !strings.Contains(body, fmt.Sprintf("内存：%.1f%%", *message.Report.Resources.Memory)) || !strings.Contains(body, fmt.Sprintf("磁盘：%.1f%%", *message.Report.Resources.Disk)) || strings.Contains(body, "手动发送的测试摘要") {
		t.Fatal("SMTP content mismatched actual native resource summary")
	}
}

func TestOutboundMalformedTypedSMTPPolicyCanBePausedWithoutRewritingCipher(t *testing.T) {
	s, _ := outboundFixture(t)
	_, input := smtpReceiver(t, "tls", "mail.example.test", false)
	c, err := s.SaveNotificationChannel("", NotificationChannelInput{Name: "malformed policy QA", Type: "smtp", SMTP: &input, Enabled: true, Kinds: []string{"daily"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"missing-password", "unsupported-protocol", "mixed-envelope"} {
		broken := input
		envelope := notificationCredential{Type: "smtp", SMTP: &broken}
		if invalid == "missing-password" {
			broken.Password = ""
		}
		if invalid == "unsupported-protocol" {
			envelope.Type = "future-unknown-protocol"
		}
		if invalid == "mixed-envelope" {
			envelope.URL = "http://127.0.0.1:12345"
		}
		raw, _ := json.Marshal(envelope)
		cipher, err := encryptCredential(s.encryptionKey, "notification-channel:"+c.ID, raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.DB.Exec(`UPDATE notification_channels SET credential=?,enabled=1 WHERE id=?`, cipher, c.ID); err != nil {
			t.Fatal(err)
		}
		channels, err := s.NotificationChannels()
		if err != nil || len(channels) != 1 || channels[0].Type != "invalid" || channels[0].CredentialError == "" {
			t.Fatal("malformed typed policy hidden or globally blocking", invalid, err)
		}
		paused, err := s.SaveNotificationChannel(c.ID, NotificationChannelInput{Name: c.Name, Kinds: c.Kinds, Enabled: false, Revision: c.Revision})
		if err != nil || paused.Enabled || paused.CredentialError == "" {
			t.Fatal("malformed typed policy cannot be safely paused", invalid, err)
		}
		var retained []byte
		s.DB.QueryRow(`SELECT credential FROM notification_channels WHERE id=?`, c.ID).Scan(&retained)
		if !bytes.Equal(retained, cipher) {
			t.Fatal("malformed policy evidence overwritten")
		}
		c = paused
	}
}
