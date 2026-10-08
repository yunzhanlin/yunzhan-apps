//go:build linux

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/core"
)

func lbTLSCertificate(t *testing.T, domain string, expired bool) (tls.Certificate, string) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private entry-only QA CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(time.Hour)
	if expired {
		end = time.Now().Add(-time.Minute)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: private}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}
func lbTLSServer(t *testing.T, certificate tls.Certificate, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
func lbTLSAt(t *testing.T, certificate tls.Certificate, handler http.HandlerFunc, address string) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Listener.Close()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
func lbTLSPort(t *testing.T, server *httptest.Server) int {
	t.Helper()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func TestLoadBalanceHTTPSScopedTrustAndCertificateRejection(t *testing.T) {
	domain := "lb-fixture.example.test"
	certificate, ca := lbTLSCertificate(t, domain, false)
	var requests atomic.Int32
	server := lbTLSServer(t, certificate, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != domain || r.TLS.ServerName != domain || r.URL.RequestURI() != "/ready?check=1" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("HTTPS host/SNI/path changed or credentials leaked")
		}
		w.Write([]byte("READY"))
	})
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	entry := loadBalanceEntry{Domain: domain, HealthCheck: lbHTTPPolicy()}
	entry.HealthCheck.Scheme, entry.HealthCheck.CAPEM = "https", ca
	// Initial system root loading under a resource-bounded emulated VM can
	// exceed 500 ms; this test distinguishes certificate rejection from timeout.
	entry.HealthCheck.TimeoutMS = 5000
	entry.HealthCheck.CheckPort = lbTLSPort(t, server)
	address := strings.TrimPrefix(server.URL, "https://")
	sample := probeLoadBalanceHTTP(context.Background(), entry, address)
	if !sample.LastSuccess || sample.Status != 200 || sample.Reason != "ok" || requests.Load() != 1 {
		t.Fatal(sample)
	}
	for _, name := range []string{"system trust rejects unknown CA", "wrong hostname", "different CA"} {
		t.Run(name, func(t *testing.T) {
			value := entry
			policy := *entry.HealthCheck
			value.HealthCheck = &policy
			switch name {
			case "system trust rejects unknown CA":
				policy.CAPEM = ""
			case "wrong hostname":
				value.Domain = "wrong.example.test"
			case "different CA":
				_, policy.CAPEM = lbTLSCertificate(t, domain, false)
			}
			result := probeLoadBalanceHTTP(context.Background(), value, address)
			if result.LastSuccess || result.Status != 0 || result.Reason != "tls_validation_failed" || requests.Load() != 1 {
				t.Fatal("invalid TLS contacted business handler or was accepted", result)
			}
		})
	}
	expired, expiredCA := lbTLSCertificate(t, domain, true)
	expiredServer := lbTLSServer(t, expired, func(w http.ResponseWriter, r *http.Request) { t.Error("expired TLS contacted business handler") })
	entry.HealthCheck.CAPEM = expiredCA
	entry.HealthCheck.CheckPort = lbTLSPort(t, expiredServer)
	result := probeLoadBalanceHTTP(context.Background(), entry, strings.TrimPrefix(expiredServer.URL, "https://"))
	if result.LastSuccess || result.Status != 0 || result.Reason != "tls_validation_failed" {
		t.Fatal(result)
	}
}
func TestLoadBalanceHTTPSNeverFollowsDowngradeAndKeepsThresholds(t *testing.T) {
	domain := "lb-fixture.example.test"
	certificate, ca := lbTLSCertificate(t, domain, false)
	var otherRequests atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { otherRequests.Add(1) }))
	defer other.Close()
	var redirect atomic.Bool
	handler := func(w http.ResponseWriter, r *http.Request) {
		if redirect.Load() {
			http.Redirect(w, r, other.URL, http.StatusFound)
			return
		}
		w.Write([]byte("READY"))
	}
	first := lbTLSServer(t, certificate, handler)
	port := lbTLSPort(t, first)
	lbTLSAt(t, certificate, handler, net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	s := wafPolicyFixture(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("load-balance"), "installed.json"), map[string]any{"id": "load-balance", "version": "1.5.0", "installed_at": core.Now(), "settings": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	in := lbFixtureInput()
	in.HealthCheck = lbHTTPPolicy()
	in.HealthCheck.Scheme, in.HealthCheck.CAPEM = "https", ca
	in.HealthCheck.CheckPort = port
	in.Nodes = []core.AppUpstream{{Address: "127.0.0.1:41001", Weight: 1}, {Address: "127.0.0.2:41002", Weight: 3}}
	lbSave(t, s, in)
	in.ExpectedRevision = 1
	if rows := lbHTTPCheck(t, s, in); rows[0]["state"] != "unknown" {
		t.Fatal(rows)
	}
	rows := lbHTTPCheck(t, s, in)
	if rows[0]["state"] != "healthy" || rows[0]["scheme"] != "https" || rows[0]["tls_verification"] != "入口专用 CA 与入口域名" {
		t.Fatal(rows)
	}
	configBefore := lbFiles(t, s, in.Domain)
	redirect.Store(true)
	lbHTTPCheck(t, s, in)
	rows = lbHTTPCheck(t, s, in)
	if rows[0]["state"] != "unhealthy" || rows[0]["http_status"] != 302 || rows[0]["reason"] != "status_mismatch" || otherRequests.Load() != 0 {
		t.Fatal("HTTPS downgrade followed or threshold incorrect", rows)
	}
	for name, value := range configBefore {
		after, err := os.ReadFile(name)
		if err != nil || string(after) != string(value) {
			t.Fatal("TLS observer changed routing configuration", name, err)
		}
	}
}
func TestLoadBalanceHTTPSRequiresCompatibleInstalledModule(t *testing.T) {
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("old module attempted network access") })
	in.HealthCheck.Scheme = "https"
	in.HealthCheck.CheckPort = 443
	in.ExpectedRevision = 1
	before := lbFiles(t, s, in.Domain)
	if _, err := s.moduleLoadBalance(context.Background(), "save", in); err == nil || !strings.Contains(err.Error(), "1.5.0") {
		t.Fatal("old module accepted HTTPS", err)
	}
	for name, value := range before {
		after, err := os.ReadFile(name)
		if err != nil || string(after) != string(value) {
			t.Fatal("rejected HTTPS changed entry", name, err)
		}
	}
}

func TestLoadBalanceHTTPSRefusesOldTLSWithoutContactingBusiness(t *testing.T) {
	certificate, ca := lbTLSCertificate(t, "lb-fixture.example.test", false)
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	policy := lbHTTPPolicy()
	policy.Scheme, policy.CAPEM, policy.CheckPort = "https", ca, lbTLSPort(t, server)
	result := probeLoadBalanceHTTP(context.Background(), loadBalanceEntry{Domain: "lb-fixture.example.test", HealthCheck: policy}, strings.TrimPrefix(server.URL, "https://"))
	if result.LastSuccess || result.Status != 0 || calls.Load() != 0 {
		t.Fatal("obsolete TLS accepted or business contacted", result)
	}
}

func TestLoadBalanceIndependentCheckPortTargetsAreClosed(t *testing.T) {
	entry := loadBalanceEntry{Format: 1, Revision: 1, Domain: "lb-fixture.example.test", Port: 41975,
		Nodes: []core.AppUpstream{{Address: "127.0.0.1:41001", Weight: 1}, {Address: "127.0.0.2:41002", Weight: 3}}, HealthCheck: lbHTTPPolicy()}
	entry.HealthCheck.Scheme, entry.HealthCheck.CheckPort = "https", 443
	if err := validateLoadBalanceEntry(entry); err != nil {
		t.Fatal("valid distinct readiness targets rejected", err)
	}
	if target, err := loadBalanceHealthAddress(entry, entry.Nodes[1].Address); err != nil || target != "127.0.0.2:443" {
		t.Fatal("target IP changed", target, err)
	}
	for _, port := range []int{19100, 19102, 19080, entry.Port, 41001} {
		value := entry
		policy := *entry.HealthCheck
		value.HealthCheck = &policy
		policy.CheckPort = port
		if err := validateLoadBalanceEntry(value); err == nil {
			t.Fatal("control/self/forwarding port accepted", port)
		}
	}
	entry.Nodes[1].Address = "127.0.0.1:41002"
	if err := validateLoadBalanceEntry(entry); err == nil {
		t.Fatal("two nodes aliased to one readiness endpoint")
	}
}
