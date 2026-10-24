package core

import (
	"crypto/ed25519"
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

func TestLoadBalanceHealthPublicCAOnly(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeCertificate := func(ca bool) string {
		t.Helper()
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "entry scoped QA CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	certificate := makeCertificate(true)
	for _, value := range []string{certificate, strings.Repeat(certificate, 4)} {
		pool, err := LoadBalanceHealthRoots(value)
		if err != nil || pool == nil {
			t.Fatal("valid public CA rejected", err)
		}
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"leaf": makeCertificate(false), "key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
		"garbage prefix": "unexpected\n" + certificate, "garbage suffix": certificate + "unexpected",
		"five certificates": strings.Repeat(certificate, 5), "large": strings.Repeat("a", 16385), "whitespace": "  \n",
		"invalid certificate": "-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBalanceHealthRoots(value); err == nil {
				t.Fatal("invalid public CA accepted")
			}
		})
	}
	policy := &LoadBalanceHTTPHealth{Path: "/ready", Interval: 30, TimeoutMS: 500, ExpectedStatus: 200, Failures: 2, Successes: 2, Scheme: "https", CAPEM: certificate, CheckPort: 443}
	if ValidateLoadBalanceHTTPHealth(policy) != nil {
		t.Fatal("valid scoped HTTPS policy rejected")
	}
	policy.Scheme = "http"
	if ValidateLoadBalanceHTTPHealth(policy) == nil {
		t.Fatal("CA policy accepted for cleartext")
	}
}

func TestLoadBalanceLegacyHTTPPolicyJSONIsUnchanged(t *testing.T) {
	policy := LoadBalanceHTTPHealth{Path: "/ready", Interval: 30, TimeoutMS: 500, ExpectedStatus: 200, BodyContains: "READY", Failures: 2, Successes: 2}
	body, err := json.Marshal(policy)
	if err != nil || string(body) != `{"path":"/ready","interval":30,"timeout_ms":500,"expected_status":200,"body_contains":"READY","failures":2,"successes":2}` {
		t.Fatal("legacy entry policy fingerprint changed", string(body), err)
	}
	policy.Scheme = "https"
	policy.CheckPort = 443
	if ValidateLoadBalanceHTTPHealth(&policy) != nil {
		t.Fatal("HTTPS system trust policy rejected")
	}
}
