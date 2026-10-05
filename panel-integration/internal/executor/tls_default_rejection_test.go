package executor

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEmptyDefaultTLSRequiresExactCertificateAndNoHTTP(t *testing.T) {
	for _, test := range []struct {
		name, domain             string
		wrongCert, content, want bool
	}{
		{name: "empty close", domain: "disabled.example.test", want: true},
		{name: "wrong certificate", domain: "disabled.example.test", wrongCert: true},
		{name: "HTTP content", domain: "disabled.example.test", content: true},
		{name: "host injection", domain: "disabled.example.test\r\nInjected: true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.content {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
			}))
			defer server.Close()
			conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			trusted := server.Certificate().Raw
			if test.wrongCert {
				trusted = []byte("not the default certificate")
			}
			if got := proveEmptyDefaultTLS(conn, test.domain, trusted); got != test.want {
				t.Fatalf("rejection=%v, want %v", got, test.want)
			}
		})
	}
}

func TestEmptyDefaultTLSDoesNotAcceptTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer server.Close()
	defer close(release)
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	if proveEmptyDefaultTLS(conn, "disabled.example.test", server.Certificate().Raw) {
		t.Fatal("a stalled TLS listener is not a confirmed rejection")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("probe did not respect its deadline")
	}
}
