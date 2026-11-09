package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/acme"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestACMEFinalizeWithoutLocationReconcilesWithoutDuplicateCSR(t *testing.T) {
	leaf, _, _ := certificateFixture(t, []string{"acme.example.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), x509.ExtKeyUsageServerAuth)
	block, _ := pem.Decode([]byte(leaf))
	var finalized, fetched atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		switch r.URL.Path {
		case "/directory":
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, server.URL+"/nonce", server.URL+"/account", server.URL+"/new-order")
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/finalize":
			finalized.Add(1)
			// A real Pebble processing response has no Location header.
			fmt.Fprint(w, `{"status":"processing"}`)
		case "/persisted-order":
			w.Header().Set("Location", server.URL+"/persisted-order")
			fmt.Fprintf(w, `{"status":"valid","certificate":%q}`, server.URL+"/certificate")
		case "/certificate":
			fetched.Add(1)
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			fmt.Fprint(w, leaf)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"acme.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse(server.URL)
	httpClient := server.Client()
	httpClient.Transport = acmeTransport{base: httpClient.Transport, origin: origin}
	client := &acme.Client{Key: key, KID: acme.KeyID(server.URL + "/account/1"), DirectoryURL: server.URL + "/directory", HTTPClient: httpClient}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	chain, err := finalizeACMECertificate(ctx, client, server.URL+"/persisted-order", server.URL+"/finalize", csr)
	if err != nil || len(chain) != 1 || string(chain[0]) != string(block.Bytes) {
		t.Fatalf("issued chain not recovered: %v", err)
	}
	if finalized.Load() != 1 || fetched.Load() != 1 {
		t.Fatal("duplicate CSR or certificate fetch")
	}
}

func TestPublicACMERequiresStandardWebsiteIngress(t *testing.T) {
	s, site, in, p := acmeFixture(t)
	if _, err := s.DB.Exec(`UPDATE sites SET domain='www.example.org' WHERE id=?`, site.ID); err != nil {
		t.Fatal(err)
	}
	in.Provider = "letsencrypt"
	p.ID = "letsencrypt"
	if _, err := s.QueueACME(in, p, "closed-ingress", "admin"); err == nil || !strings.Contains(err.Error(), "80") {
		t.Fatal("closed standard ingress accepted", err)
	}
	site.Settings.PublicIngress = true
	if _, err := s.DB.Exec(`UPDATE sites SET settings_json=? WHERE id=?`, marshalString(site.Settings), site.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueueACME(in, p, "open-ingress", "admin"); err != nil {
		t.Fatal(err)
	}
}

func acmeFixture(t *testing.T) (*Store, Site, ACMERequest, ACMEProvider) {
	t.Helper()
	s := testStore(t)
	s.encryptionKey = []byte("0123456789abcdef0123456789abcdef")
	site := settingsSite(t, s, "acme-one")
	in := ACMERequest{SiteID: site.ID, Provider: "pebble", Email: "acceptance@example.test", Terms: "data:text/plain,local-test", AcceptTerms: true, AutoRenew: true, Redirect: true}
	p := ACMEProvider{ID: "pebble", Directory: "https://localhost:14000/dir", Terms: in.Terms, Test: true}
	return s, site, in, p
}
func TestACMEQueueEncryptionIdempotencyAndRecovery(t *testing.T) {
	s, site, in, p := acmeFixture(t)
	id, e := s.QueueACME(in, p, "one", "admin")
	if e != nil {
		t.Fatal(e)
	}
	same, e := s.QueueACME(in, p, "one", "admin")
	if e != nil || id != same {
		t.Fatal("idempotency", e)
	}
	o, e := s.ACMEOrder(id)
	if e != nil || o.State != "queued" || o.Terms != in.Terms || len(o.Domains) != 1 {
		t.Fatal("persisted order", e)
	}
	var accountCipher, orderCipher []byte
	s.DB.QueryRow(`SELECT key_cipher FROM acme_accounts WHERE id=?`, o.AccountID).Scan(&accountCipher)
	s.DB.QueryRow(`SELECT key_cipher FROM acme_orders WHERE id=?`, id).Scan(&orderCipher)
	for _, tc := range []struct {
		cipher  []byte
		purpose string
	}{{accountCipher, "panel-acme-account:" + o.AccountID}, {orderCipher, "panel-acme-order:" + id}} {
		signer, raw, e := decodeACMESigner(s.encryptionKey, tc.purpose, tc.cipher)
		if e != nil || signer == nil {
			t.Fatal("key decrypt", e)
		}
		if _, e = x509.ParsePKCS8PrivateKey(raw); e != nil {
			t.Fatal(e)
		}
		if _, e = decryptCredential(s.encryptionKey, "wrong", tc.cipher); e == nil {
			t.Fatal("cross-purpose secret accepted")
		}
	}
	if _, e = s.QueueACME(in, p, "second", "admin"); e == nil {
		t.Fatal("parallel order accepted")
	}
	changed := in
	changed.Redirect = false
	if _, e = s.QueueACME(changed, p, "one", "admin"); e == nil {
		t.Fatal("different idempotent request accepted")
	}
	rejected := in
	rejected.AcceptTerms = false
	if _, e = s.QueueACME(rejected, p, "no-terms", "admin"); e == nil {
		t.Fatal("terms not accepted")
	}
	rejected.Provider = "letsencrypt"
	p.ID = "letsencrypt"
	rejected.AcceptTerms = true
	if _, e = s.QueueACME(rejected, p, "public", "admin"); e == nil {
		t.Fatal("public CA got development domain")
	}
	s.DB.Exec(`UPDATE acme_orders SET state='running',order_url='https://localhost:14000/order/test' WHERE id=?`, id)
	if e = s.Recover(); e != nil {
		t.Fatal(e)
	}
	o, _ = s.ACMEOrder(id)
	if o.State != "queued" || o.OrderURL == "" {
		t.Fatal("restart lost remote order")
	}
	s.failACME(id, errors.New("test validation failure"))
	if e = s.RetryACME(id, "admin"); e != nil {
		t.Fatal(e)
	}
	o, _ = s.ACMEOrder(id)
	if o.State != "queued" || o.Attempt != 2 || o.OrderURL == "" {
		t.Fatal("retry lost the remote order needed to reconcile issuance")
	}
	jobs, e := s.Jobs()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, j := range jobs {
		if j.ID == id {
			found = true
			if j.Kind != "acme_certificate" || j.SiteID != site.ID {
				t.Fatal("wrong generic task metadata")
			}
		}
	}
	if !found {
		t.Fatal("ACME task absent")
	}
	raw, _ := json.Marshal(o)
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "key_cipher") {
		t.Fatal("private material in API order")
	}
	if _, e = s.accountKey(t.TempDir()); e == nil {
		t.Fatal("regenerated master key over ACME credentials")
	}
}

func TestACMEFailureClearsChildAttentionOnlyForUnchangedTLS(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "baseline", true: "changed"}[changed], func(t *testing.T) {
			s, site, in, provider := acmeFixture(t)
			id, e := s.QueueACME(in, provider, "failure", "admin")
			if e != nil {
				t.Fatal(e)
			}
			if changed {
				site.Settings.TLS = &SiteTLS{CertificateID: ID(), Redirect: true}
				if _, e = s.DB.Exec(`UPDATE sites SET status='needs_attention',settings_json=? WHERE id=?`, marshalString(site.Settings), site.ID); e != nil {
					t.Fatal(e)
				}
			} else if _, e = s.DB.Exec(`UPDATE sites SET status='needs_attention' WHERE id=?`, site.ID); e != nil {
				t.Fatal(e)
			}
			s.failACME(id, errors.New("certificate deployment failed"))
			got, e := s.Site(site.ID)
			if e != nil {
				t.Fatal(e)
			}
			if changed && got.Status != "needs_attention" {
				t.Fatal("changed TLS attention marker cleared", got.Status)
			}
			if !changed && got.Status != "running" {
				t.Fatal("unchanged TLS site remained blocked", got.Status)
			}
		})
	}
}
func TestHTTP01RequiresMatchingLiveDomainOrderAndExpiry(t *testing.T) {
	s, site, in, p := acmeFixture(t)
	id, e := s.QueueACME(in, p, "one", "admin")
	if e != nil {
		t.Fatal(e)
	}
	a := &Server{Store: s}
	m := http.NewServeMux()
	a.acmeRoutes(m)
	a.mux = m
	token := strings.Repeat("a", 43)
	response := token + "." + strings.Repeat("b", 43)
	s.DB.Exec(`INSERT INTO acme_challenges VALUES(?,?,?,?,?)`, id, site.Domain, token, response, time.Now().Add(time.Minute).Unix())
	get := func(host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://panel/.well-known/acme-challenge/"+token, nil)
		r.Host = host
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if get(site.Domain).Code != 404 {
		t.Fatal("challenge exposed before explicit route setting")
	}
	site.Settings.ACME = true
	s.DB.Exec(`UPDATE sites SET settings_json=? WHERE id=?`, marshalString(site.Settings), site.ID)
	w := get(site.Domain)
	if w.Code != 200 || w.Body.String() != response || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("valid challenge", w.Code)
	}
	if get("other.localhost").Code != 404 {
		t.Fatal("wrong Host received challenge")
	}
	s.DB.Exec(`UPDATE acme_challenges SET expires_at=0 WHERE order_id=?`, id)
	if get(site.Domain).Code != 404 {
		t.Fatal("expired challenge exposed")
	}
	s.DB.Exec(`UPDATE acme_challenges SET expires_at=? WHERE order_id=?`, time.Now().Add(time.Minute).Unix(), id)
	s.DB.Exec(`UPDATE acme_orders SET state='failed' WHERE id=?`, id)
	if get(site.Domain).Code != 404 {
		t.Fatal("failed order challenge exposed")
	}
	s.DB.Exec(`UPDATE acme_orders SET state='running' WHERE id=?`, id)
	s.DB.Exec(`UPDATE sites SET status='stopped' WHERE id=?`, site.ID)
	if get(site.Domain).Code != 404 {
		t.Fatal("stopped website challenge exposed")
	}
}

type acmeTestTransport func(*http.Request) (*http.Response, error)

func (f acmeTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestACMEResourcesRemainAtFixedHTTPSOrigin(t *testing.T) {
	origin, _ := url.Parse("https://ca.example.test/directory")
	calls := 0
	base := acmeTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})
	transport := acmeTransport{base: base, origin: origin}
	for _, target := range []string{"http://ca.example.test/order", "https://localhost/order", "https://ca.example.test:8443/order", "https://user@ca.example.test/order"} {
		r, _ := http.NewRequestWithContext(context.Background(), "GET", target, nil)
		if _, e := transport.RoundTrip(r); e == nil {
			t.Fatal("out of bounds resource accepted")
		}
	}
	if calls != 0 {
		t.Fatal("rejected request reached network")
	}
	r, _ := http.NewRequest("GET", "https://ca.example.test/order/1", nil)
	out, e := transport.RoundTrip(r)
	if e != nil {
		t.Fatal(e)
	}
	out.Body.Close()
	if calls != 1 {
		t.Fatal("same-origin resource failed")
	}
}
