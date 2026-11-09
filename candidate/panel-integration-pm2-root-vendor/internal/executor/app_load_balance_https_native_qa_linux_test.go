//go:build linux

package executor

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"
)

// This opt-in private companion generates isolated public CA/leaf fixtures.
// It does not install trust roots, configure Nginx or claim API acceptance.
func TestLoadBalanceHTTPSPrepareNativeQA(t *testing.T) {
	id := os.Getenv("PANEL_LB_TLS_QA_ID")
	if id == "" {
		t.Skip("isolated TLS QA fixture generation is opt-in")
	}
	host, err := os.Hostname()
	if err != nil || (host != "lima-panel-compat-ubuntu24" && host != "lima-panel-store-apps-debian13") || os.Geteuid() != 0 || !regexp.MustCompile("^[0-9a-f]{32}$").MatchString(id) {
		t.Fatal("private TLS fixture preparation requires the named isolated VM/root/exact ID")
	}
	parent := "/var/lib/panel-executor/lb-https-qa"
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("private TLS fixture parent identity", err)
	}
	stage := filepath.Join(parent, id)
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal("do not overwrite a retained TLS fixture", err)
	}
	domain := "lb-tls-" + id[:12] + ".example.test"
	var roots string
	for _, mode := range []string{"good", "wrong", "expired"} {
		name := domain
		if mode == "wrong" {
			name = "wrong-" + id[:12] + ".example.test"
		}
		certificate, ca := lbTLSCertificate(t, name, mode == "expired")
		roots += ca
		var chain []byte
		for _, der := range certificate.Certificate {
			chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		for leaf, data := range map[string][]byte{mode + ".crt": chain, mode + ".key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
			if err := os.WriteFile(filepath.Join(stage, leaf), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(stage, "ca.crt"), []byte(roots), 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("private TLS QA certificates retained at " + stage + "; no host trust changes")
}
