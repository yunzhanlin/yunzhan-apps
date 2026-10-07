//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWAFEngineDownloadSourceAndRedirectBoundaries(t *testing.T) {
	for _, raw := range []string{"https://nginx.org/download/nginx-1.24.0.tar.gz", "https://github.com/owasp-modsecurity/ModSecurity/releases/download/v3.0.17/modsecurity-v3.0.17.tar.gz", "https://github.com/coreruleset/coreruleset/releases/download/v4.30.0/coreruleset-4.30.0-minimal.tar.gz", "https://release-assets.githubusercontent.com/github-production-release-asset/123/456?temporary-token=opaque"} {
		u, _ := url.Parse(raw)
		if !wafSourceRedirectAllowed(u, 1) {
			t.Fatal("rejected official redirect", u.Host)
		}
	}
	for _, raw := range []string{"http://nginx.org/download/nginx-1.24.0.tar.gz", "https://nginx.org:443/download/nginx-1.24.0.tar.gz", "https://user@nginx.org/download/nginx-1.24.0.tar.gz", "https://nginx.org/download/nginx-1.24.0.tar.gz#fragment", "https://127.0.0.1/private", "https://github.com/attacker/plugin/releases/download/main/run.sh", "https://release-assets.githubusercontent.com.evil.invalid/github-production-release-asset/a", "https://release-assets.githubusercontent.com/private"} {
		u, _ := url.Parse(raw)
		if wafSourceRedirectAllowed(u, 1) {
			t.Fatal("accepted forbidden redirect", raw)
		}
	}
	u, _ := url.Parse("https://nginx.org/download/nginx-1.24.0.tar.gz")
	if wafSourceRedirectAllowed(u, 4) || wafSourceRedirectAllowed(nil, 0) {
		t.Fatal("redirect cap missing")
	}
	source := wafEngineSources()[0]
	source.SHA256 = strings.Repeat("0", 64)
	if err := downloadWAFEngineSource(context.Background(), source, filepath.Join(t.TempDir(), "source")); err == nil {
		t.Fatal("accepted modified source before network")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := downloadWAFEngineSource(ctx, wafEngineSources()[0], "/nonexistent"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled download continued", err)
	}
}

func TestWAFSourceRetryClassificationDoesNotRetrySecurityOrDiskFailures(t *testing.T) {
	for _, err := range []error{errWAFSourceTransport, io.ErrUnexpectedEOF} {
		if !wafSourceRetryable(err) {
			t.Fatal("transient source error not recognized", err)
		}
	}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, errors.New("源码 SHA-256 不匹配"), errors.New("源码目标已存在"), errors.New("disk full")} {
		if wafSourceRetryable(err) {
			t.Fatal("security/local failure retried", err)
		}
	}
}

func TestWAFSourcePublicationRejectsDigestOverflowAndClobber(t *testing.T) {
	data := "reviewed source fixture"
	sum := sha256.Sum256([]byte(data))
	want := hex.EncodeToString(sum[:])
	dir := t.TempDir()
	destination := filepath.Join(dir, "source.tar.gz")
	if err := streamVerifiedWAFSource(strings.NewReader(data), want, destination); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(destination)
	if err != nil || string(b) != data {
		t.Fatal("verified publication failed", err)
	}
	if st, _ := os.Stat(destination); st.Mode().Perm() != 0600 {
		t.Fatal("source cache is not private")
	}
	if err := streamVerifiedWAFSource(strings.NewReader(data), want, destination); err == nil {
		t.Fatal("overwrote existing source")
	}
	for name, body := range map[string]io.Reader{"wrong-digest": strings.NewReader("untrusted bytes"), "overflow": io.LimitReader(wafQAZeroReader{}, wafNativeSourceBytes+1)} {
		path := filepath.Join(dir, name)
		if err := streamVerifiedWAFSource(body, want, path); err == nil {
			t.Fatal("accepted", name)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("published unverified source", name)
		}
	}
	link := filepath.Join(dir, "link")
	if err = os.Symlink(destination, link); err != nil {
		t.Fatal(err)
	}
	if err = streamVerifiedWAFSource(strings.NewReader(data), want, link); err == nil {
		t.Fatal("replaced a symbolic link")
	}
	b, _ = os.ReadFile(destination)
	if string(b) != data {
		t.Fatal("original verified source changed")
	}
}

type wafQAZeroReader struct{}

func (wafQAZeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }
