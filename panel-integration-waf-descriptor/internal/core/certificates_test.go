package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func certificateFixture(t *testing.T, hosts []string, begin, end time.Time, usage x509.ExtKeyUsage) (string, string, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Panel Test Root"}, NotBefore: begin.Add(-time.Hour), NotAfter: end.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hosts[0]}, NotBefore: begin, NotAfter: end, DNSNames: hosts, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}
func TestCertificateParsingPairingChainAndDomains(t *testing.T) {
	now := time.Now()
	leaf, key, ca := certificateFixture(t, []string{"site.localhost", "*.example.test"}, now.Add(-time.Hour), now.Add(24*time.Hour), x509.ExtKeyUsageServerAuth)
	cert, e := ParseCertificate(leaf+ca, key, now)
	if e != nil {
		t.Fatal(e)
	}
	if cert.Trusted || cert.Algorithm != "ECDSA P-256" || len(cert.Fingerprint) != 64 {
		t.Fatal("certificate metadata")
	}
	if e = cert.ValidateDomains("site.localhost", []string{"www.example.test"}, now); e != nil {
		t.Fatal(e)
	}
	for _, domain := range []string{"other.localhost", "example.test", "deep.sub.example.test"} {
		if cert.ValidateDomains(domain, nil, now) == nil {
			t.Fatal("uncovered hostname accepted", domain)
		}
	}
	_, otherKey, _ := certificateFixture(t, []string{"site.localhost"}, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth)
	for _, v := range [][2]string{{leaf + ca, otherKey}, {ca + leaf, key}, {leaf + key, key}, {"ignored text\n" + leaf, key}, {leaf + ca + leaf, key}} {
		if _, e = ParseCertificate(v[0], v[1], now); e == nil {
			t.Fatal("invalid pair or chain accepted")
		}
	}
	b, _ := json.Marshal(cert)
	if strings.Contains(string(b), "PRIVATE KEY") || strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Fatal("material leaked in certificate metadata")
	}
}
func TestCertificateRejectsTimeAndPurpose(t *testing.T) {
	now := time.Now()
	for _, v := range []struct {
		begin, end time.Time
		usage      x509.ExtKeyUsage
	}{{now.Add(time.Hour), now.Add(2 * time.Hour), x509.ExtKeyUsageServerAuth}, {now.Add(-2 * time.Hour), now.Add(-time.Hour), x509.ExtKeyUsageServerAuth}, {now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth}} {
		leaf, key, ca := certificateFixture(t, []string{"site.localhost"}, v.begin, v.end, v.usage)
		if _, e := ParseCertificate(leaf+ca, key, now); e == nil {
			t.Fatal("invalid time/purpose certificate accepted")
		}
	}
}

func TestCertificateEncryptionAndIdempotentUpload(t *testing.T) {
	s := testStore(t)
	key, e := s.accountKey(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s.encryptionKey = key
	now := time.Now()
	leaf, private, ca := certificateFixture(t, []string{"site.localhost"}, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth)
	cert, e := s.SaveCertificate("site", leaf+ca, private, "first", "admin")
	if e != nil {
		t.Fatal(e)
	}
	same, e := s.SaveCertificate("site", leaf+ca, private, "first", "admin")
	if e != nil || same.ID != cert.ID {
		t.Fatal("duplicate upload", e)
	}
	if _, e = s.SaveCertificate("other", leaf+ca, private, "first", "admin"); e == nil {
		t.Fatal("different upload reused idempotency key")
	}
	material, e := s.CertificateMaterial(cert.ID)
	if e != nil || material.PrivateKeyPEM != private {
		t.Fatal("encrypted key roundtrip", e)
	}
	var encrypted []byte
	s.DB.QueryRow(`SELECT key_cipher FROM certificates WHERE id=?`, cert.ID).Scan(&encrypted)
	if strings.Contains(string(encrypted), "PRIVATE KEY") {
		t.Fatal("private key stored as plaintext")
	}
	if _, e = decryptAccountSecret(key, cert.ID, encrypted); e == nil {
		t.Fatal("TLS ciphertext crossed credential purpose")
	}
	list, e := s.Certificates()
	if e != nil || len(list) != 1 {
		t.Fatal("inventory", e)
	}
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), private) || strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Fatal("certificate inventory exposes material")
	}
	if e = s.validateSiteCertificate("other.localhost", SiteSettings{TLS: &SiteTLS{CertificateID: cert.ID}}); e == nil {
		t.Fatal("certificate bound to uncovered site")
	}
	s.encryptionKey = make([]byte, 32)
	if _, e = s.CertificateMaterial(cert.ID); e == nil {
		t.Fatal("wrong master key accepted")
	}
}
