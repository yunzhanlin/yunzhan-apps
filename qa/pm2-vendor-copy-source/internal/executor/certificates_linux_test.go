//go:build linux

package executor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"local/panel/internal/core"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func executorCertificate(t *testing.T) core.CertificateMaterial {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	spec := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "tls.localhost"}, DNSNames: []string{"tls.localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, spec, spec, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return core.CertificateMaterial{ID: core.ID(), CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))}
}
func TestCertificatePublicationAndTamperChecks(t *testing.T) {
	f := certificateFS{root: filepath.Join(t.TempDir(), "certificates")}
	in := executorCertificate(t)
	first, e := f.install(in)
	if e != nil {
		t.Fatal(e)
	}
	again, e := f.install(in)
	if e != nil || first.Fingerprint != again.Fingerprint {
		t.Fatal("idempotent install", e)
	}
	changed := executorCertificate(t)
	changed.ID = in.ID
	if _, e = f.install(changed); e == nil {
		t.Fatal("overwrote certificate ID")
	}
	for path, mode := range map[string]os.FileMode{f.root: 0700, filepath.Join(f.root, in.ID): 0700, filepath.Join(f.root, in.ID, "key.pem"): 0600, filepath.Join(f.root, in.ID, "manifest.json"): 0600} {
		info, e := os.Stat(path)
		if e != nil || info.Mode().Perm() != mode {
			t.Fatal("unexpected permissions", path, e)
		}
	}
	raw, e := os.ReadFile(filepath.Join(f.root, in.ID, "manifest.json"))
	if e != nil || strings.Contains(string(raw), "BEGIN") {
		t.Fatal("manifest leaked key or certificate", e)
	}
	keyPath := filepath.Join(f.root, in.ID, "key.pem")
	if e = os.Chmod(keyPath, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = f.load(in.ID); e == nil {
		t.Fatal("public private key accepted")
	}
	os.Chmod(keyPath, 0600)
	chain := filepath.Join(f.root, in.ID, "chain.pem")
	os.WriteFile(chain, []byte(changed.CertificatePEM), 0644)
	if _, e = f.load(in.ID); e == nil {
		t.Fatal("changed chain accepted")
	}
	os.WriteFile(chain, []byte(in.CertificatePEM), 0644)
	os.Remove(keyPath)
	os.Symlink(filepath.Join(t.TempDir(), "absent"), keyPath)
	if _, e = f.load(in.ID); e == nil {
		t.Fatal("linked private key accepted")
	}
	// Never publish into a broadly readable root, even if its owner is correct.
	os.Chmod(f.root, 0755)
	if _, e = f.install(executorCertificate(t)); e == nil {
		t.Fatal("insecure root accepted")
	}
}
