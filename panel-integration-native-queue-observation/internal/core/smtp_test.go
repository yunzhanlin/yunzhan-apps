package core

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSMTPSettingsEncryptPasswordAndValidate(t *testing.T) {
	s := testStore(t)
	s.encryptionKey = []byte(strings.Repeat("k", 32))
	noAuth := smtpSettingsInput{SMTPSettings: SMTPSettings{Host: "127.0.0.1", Port: 465, Mode: "tls", From: "admin@example.test", Enabled: true}}
	if got, e := s.saveSMTPSettings(noAuth, "admin"); e != nil || got.HasPassword {
		t.Fatal("SMTP without authentication should be valid", got, e)
	}
	if got, e := s.saveSMTPSettings(noAuth, "admin"); e != nil || got.HasPassword {
		t.Fatal("updating SMTP without authentication should be valid", got, e)
	}
	in := smtpSettingsInput{SMTPSettings: SMTPSettings{Host: "smtp.example.test", Port: 587, Mode: "starttls", Username: "admin@example.test", From: "admin@example.test", Enabled: true}, Password: "secret-credential"}
	got, e := s.saveSMTPSettings(in, "admin")
	if e != nil || !got.HasPassword || got.Enabled != true {
		t.Fatal(got, e)
	}
	var cipher []byte
	if e = s.DB.QueryRow(`SELECT password_cipher FROM smtp_settings WHERE id=1`).Scan(&cipher); e != nil || strings.Contains(string(cipher), in.Password) {
		t.Fatal("SMTP password stored in plain text", e)
	}
	if pass, e := s.smtpPassword(); e != nil || pass != in.Password {
		t.Fatal("SMTP password not recoverable", e)
	}
	in.Password = ""
	in.Port = 465
	if _, e = s.saveSMTPSettings(in, "admin"); e != nil {
		t.Fatal("blank update should preserve credential", e)
	}
	if pass, e := s.smtpPassword(); e != nil || pass != "secret-credential" {
		t.Fatal("SMTP password changed by blank update", e)
	}
	for _, bad := range []smtpSettingsInput{
		{SMTPSettings: SMTPSettings{Host: "smtp.example.test:25", Port: 587, Mode: "starttls", From: "admin@example.test"}},
		{SMTPSettings: SMTPSettings{Host: "smtp.example.test", Port: 587, Mode: "plain", From: "admin@example.test"}},
		{SMTPSettings: SMTPSettings{Host: "smtp.example.test", Port: 587, Mode: "tls", From: "admin@example.test\r\nBcc: bad@example.test"}},
	} {
		if _, e := s.saveSMTPSettings(bad, "admin"); e == nil {
			t.Fatal("invalid SMTP config accepted", bad)
		}
	}
}

func smtpFileShareTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	keyDer, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool.AddCert(parsed)
	return cert, pool
}

func TestSMTPDeliverOverVerifiedTLS(t *testing.T) {
	for _, mode := range []string{"tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			cert, roots := smtpFileShareTestCertificate(t)
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			messages := make(chan string, 1)
			go func() {
				conn, e := listener.Accept()
				if e != nil {
					messages <- "accept: " + e.Error()
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if mode == "tls" {
					conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				}
				reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
				write := func(line string) { _, _ = writer.WriteString(line); _ = writer.Flush() }
				write("220 local SMTP test\r\n")
				var data strings.Builder
				for {
					line, er := reader.ReadString('\n')
					if er != nil {
						messages <- "read: " + er.Error()
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if mode == "starttls" && data.Len() == 0 {
							write("250-localhost\r\n250 STARTTLS\r\n")
						} else {
							write("250 localhost\r\n")
						}
					case strings.HasPrefix(line, "STARTTLS"):
						write("220 begin TLS\r\n")
						conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
						reader, writer = bufio.NewReader(conn), bufio.NewWriter(conn)
						data.WriteString("secured\n")
					case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
						write("250 accepted\r\n")
					case strings.HasPrefix(line, "DATA"):
						write("354 send body\r\n")
						for {
							part, er := reader.ReadString('\n')
							if er != nil {
								messages <- "data: " + er.Error()
								return
							}
							if part == ".\r\n" {
								break
							}
							data.WriteString(part)
						}
						write("250 queued\r\n")
					case strings.HasPrefix(line, "QUIT"):
						write("221 goodbye\r\n")
						messages <- data.String()
						return
					default:
						write("500 unsupported\r\n")
					}
				}
			}()
			port, _ := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])
			settings := SMTPSettings{Host: "127.0.0.1", Port: port, Mode: mode, From: "sender@example.test", Enabled: true}
			if e = smtpDeliver(context.Background(), settings, "", "reader@example.test", "文件分享：测试", "链接：http://127.0.0.1/share/token", roots); e != nil {
				t.Fatal(e)
			}
			select {
			case msg := <-messages:
				if !strings.Contains(msg, "reader@example.test") || !strings.Contains(msg, "链接：http://127.0.0.1/share/token") || !strings.Contains(msg, "=?utf-8?q?") {
					t.Fatal("SMTP message missing content", msg)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("SMTP fixture did not receive message")
			}
		})
	}
}

func TestFileSharePublicURLIgnoresBrowserHost(t *testing.T) {
	access := PanelAccess{HTTPEnabled: true, HTTPIP: "192.0.2.3", HTTPPort: 27727}
	token := strings.Repeat("A", 43)
	url, e := fileSharePublicURL(access, token)
	if e != nil || url != "http://192.0.2.3:27727/share/"+token {
		t.Fatal(url, e)
	}
	access.HTTPIP = "0.0.0.0"
	if _, e = fileSharePublicURL(access, token); e == nil {
		t.Fatal("wildcard address accepted")
	}
}
