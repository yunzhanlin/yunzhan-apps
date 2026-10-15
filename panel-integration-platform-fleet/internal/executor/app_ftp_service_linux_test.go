//go:build linux

package executor

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func ftpServiceFixture(t *testing.T) (*Service, []byte) {
	t.Helper()
	base := t.TempDir()
	s := New(Config{SystemRoot: base, SecurityDir: filepath.Join(base, "security")})
	dir := s.moduleDir("pure-ftpd")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	cert := executorCertificate(t)
	data := []byte(cert.CertificatePEM + "\n" + cert.PrivateKeyPEM)
	if e := atomicWrite(filepath.Join(dir, "server.pem"), data, 0600); e != nil {
		t.Fatal(e)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) { return "active", nil }
	return s, data
}
func ftpInput(c ftpServiceConfig) core.AppModuleInput {
	return core.AppModuleInput{ExpectedRevision: c.Revision, BindAddress: c.BindAddress, Port: c.Port, PassiveStart: c.PassiveStart, PassiveEnd: c.PassiveEnd, PassiveAddress: c.PassiveAddress, MaxClients: c.MaxClients, MaxPerIP: c.MaxPerIP, IdleMinutes: c.IdleMinutes, CertificateID: c.CertificateID, Domain: c.Domain}
}
func TestFTPServiceStrictConfigBoundsAndNoShell(t *testing.T) {
	if readFTPReply(bufio.NewReader(strings.NewReader("220 "+strings.Repeat("X", 8192)+"\n")), "220") == nil {
		t.Fatal("unbounded FTP banner accepted")
	}
	users, e := ftpPublicUsers([]byte("qa-user:secret-hash:1001:1001::/srv/panel/sites/abcdef0123456789abcdef0123456789/public/./::::::::::::\n"), "/srv/panel/sites")
	if e != nil || len(users) != 1 || users[0]["site_id"] != "abcdef0123456789abcdef0123456789" {
		t.Fatal(users, e)
	}
	public, _ := json.Marshal(users)
	if strings.Contains(string(public), "secret-hash") {
		t.Fatal("password hash leaked")
	}
	if empty, e := ftpPublicUsers(nil, "/srv/panel/sites"); e != nil || len(empty) != 0 {
		t.Fatal("empty account file not supported")
	}
	generated, e := generateLocalFTPCertificate()
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(generated, generated)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	if leaf.VerifyHostname("localhost") != nil || leaf.VerifyHostname("127.0.0.1") != nil {
		t.Fatal("local certificate lacks SAN")
	}
	c := defaultFTPConfig()
	if e := validateFTPConfig(c); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*ftpServiceConfig){func(c *ftpServiceConfig) { c.BindAddress = "0.0.0.0" }, func(c *ftpServiceConfig) { c.BindAddress = "127.0.0.1;id" }, func(c *ftpServiceConfig) { c.BindAddress = "::1" }, func(c *ftpServiceConfig) { c.PassiveAddress = "ftp.example.test" }, func(c *ftpServiceConfig) { c.PassiveAddress = "0.0.0.0" }, func(c *ftpServiceConfig) { c.Port = 22 }, func(c *ftpServiceConfig) { c.Port = c.PassiveStart }, func(c *ftpServiceConfig) { c.PassiveEnd = c.PassiveStart }, func(c *ftpServiceConfig) { c.PassiveEnd = c.PassiveStart + 256 }, func(c *ftpServiceConfig) { c.MaxPerIP = c.MaxClients + 1 }, func(c *ftpServiceConfig) { c.IdleMinutes = 61 }} {
		bad := c
		mutate(&bad)
		if validateFTPConfig(bad) == nil {
			t.Fatal("invalid config accepted", bad)
		}
	}
	args := ftpArguments(c, "/safe/ftp")
	if !strings.Contains(strings.Join(args, " "), "-Y 3") || !strings.Contains(strings.Join(args, " "), "-4 -u 1 -S 127.0.0.1,2121") {
		t.Fatal(args)
	}
	s, _ := ftpServiceFixture(t)
	if e := atomicWrite(filepath.Join(s.moduleDir("pure-ftpd"), "service.json"), []byte(`{"unknown":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ftpConfig(); e == nil {
		t.Fatal("unknown fields silently defaulted")
	}
}
func TestFTPServiceRevisionStoppedStateAndFailureRestore(t *testing.T) {
	s, pemBytes := ftpServiceFixture(t)
	next := defaultFTPConfig()
	next.Port = 22121
	out, e := s.configureFTP(context.Background(), ftpInput(next))
	if e != nil {
		t.Fatal(e)
	}
	config := out.(map[string]any)["config"].(ftpServiceConfig)
	if config.Revision != 1 || config.Port != 22121 {
		t.Fatal(config)
	}
	if _, e = s.configureFTP(context.Background(), ftpInput(next)); e == nil {
		t.Fatal("stale revision accepted")
	}
	before, e := os.ReadFile(filepath.Join(s.moduleDir("pure-ftpd"), "service.json"))
	if e != nil {
		t.Fatal(e)
	}
	attempts := 0
	s.Config.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "restart" {
			attempts++
			if attempts == 1 {
				return "", errors.New("controlled failure")
			}
		}
		return "active", nil
	}
	input := ftpInput(config)
	input.Port = 22122
	if _, e = s.configureFTP(context.Background(), input); e == nil {
		t.Fatal("failed candidate marked successful")
	}
	after, _ := os.ReadFile(filepath.Join(s.moduleDir("pure-ftpd"), "service.json"))
	afterPEM, _ := os.ReadFile(filepath.Join(s.moduleDir("pure-ftpd"), "server.pem"))
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(pemBytes, afterPEM) || attempts != 2 {
		t.Fatal("old config/certificate or service was not restored", attempts)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) { return "inactive", nil }
	out, e = s.configureFTP(context.Background(), input)
	if e != nil || out.(map[string]any)["service_active"] != false {
		t.Fatal("stopped service unexpectedly started", out, e)
	}
	lock, e := s.lockFTP()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if other, e := s.lockFTP(); e == nil {
		other.Close()
		t.Fatal("cross process lock not enforced")
	}
}
func TestFTPServiceInterruptedRecoveryNoOverwriteAndPrivateMaterial(t *testing.T) {
	for _, phase := range []string{"old", "new", "external"} {
		t.Run(phase, func(t *testing.T) {
			s, oldPEM := ftpServiceFixture(t)
			dir := s.moduleDir("pure-ftpd")
			old := defaultFTPConfig()
			old.Revision = 1
			oldBytes, _ := json.Marshal(old)
			if e := atomicWrite(filepath.Join(dir, "service.json"), oldBytes, 0600); e != nil {
				t.Fatal(e)
			}
			next := old
			next.Revision++
			next.Port++
			nextBytes, _ := json.Marshal(next)
			transaction := ftpServiceTransaction{ID: core.ID(), State: "applying", OldConfig: oldBytes, OldConfigExists: true, OldPEM: oldPEM, NextConfigSHA: core.Hash(string(nextBytes)), NextPEMSHA: core.Hash(string(oldPEM)), WasActive: true}
			if phase == "new" {
				atomicWrite(filepath.Join(dir, "service.json"), nextBytes, 0600)
			}
			if phase == "external" {
				atomicWrite(filepath.Join(dir, "service.json"), []byte("outside modification"), 0600)
			}
			if e := moduleWrite(filepath.Join(dir, "pending-service.json"), transaction); e != nil {
				t.Fatal(e)
			}
			_, e := s.recoverFTPTransaction()
			after, _ := os.ReadFile(filepath.Join(dir, "service.json"))
			if phase == "external" {
				if e == nil || string(after) != "outside modification" || !exists(filepath.Join(dir, "pending-service.json")) {
					t.Fatal("unrelated changes overwritten", e)
				}
				return
			}
			if e != nil || !reflect.DeepEqual(oldBytes, after) || exists(filepath.Join(dir, "pending-service.json")) {
				t.Fatal("interrupted operation did not recover", e)
			}
			info, e := os.Stat(filepath.Join(dir, "service-transactions", transaction.ID+".json"))
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal("private recovery backup exposed", e)
			}
			os.Chmod(filepath.Join(dir, "server.pem"), 0644)
			if _, _, e = s.ftpCertificate(old); e == nil {
				t.Fatal("public private-key bundle accepted")
			}
		})
	}
}
