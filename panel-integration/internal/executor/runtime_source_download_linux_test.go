//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/runtimecatalog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeSourceDownloadOfficialArchiveBudget(t *testing.T) {
	r, ok := runtimecatalog.Find("apache-2.4.68")
	if !ok {
		t.Fatal("catalogue absent")
	}
	for _, status := range []int{404, 410} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			err := downloadRuntimeSourceWith(context.Background(), r, "fixed-source", func(_ context.Context, url, sha, dst string, l sourceDownloadLimits) error {
				calls++
				if dst != "fixed-source" || sha != r.SHA256 || l.BodyIdle != 45*time.Second {
					t.Fatal("identity or idle policy changed")
				}
				if calls == 1 {
					if url != r.URL || l.Total != 8*time.Minute {
						t.Fatal("primary budget changed")
					}
					return sourceHTTPError{Status: status}
				}
				if calls != 2 || url != runtimecatalog.SourceArchiveURL(r) || l.Total != 20*time.Minute {
					t.Fatal("unreviewed fallback/budget")
				}
				return nil
			})
			if err != nil || calls != 2 {
				t.Fatalf("fallback: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestRuntimeSourceDownloadNoUntrustedFallback(t *testing.T) {
	r, _ := runtimecatalog.Find("apache-2.4.68")
	for _, failure := range []error{nil, sourceHTTPError{Status: 403}, sourceHTTPError{Status: 429}, sourceHTTPError{Status: 500}, sourceHTTPError{Status: 503}, context.DeadlineExceeded, context.Canceled, x509.UnknownAuthorityError{}, errors.New("源码 SHA-256 不匹配"), io.ErrUnexpectedEOF} {
		t.Run(fmt.Sprintf("%T-%v", failure, failure), func(t *testing.T) {
			calls := 0
			err := downloadRuntimeSourceWith(context.Background(), r, "fixed-source", func(context.Context, string, string, string, sourceDownloadLimits) error { calls++; return failure })
			if calls != 1 || err != failure {
				t.Fatalf("non-relocation error changed: calls=%d err=%v", calls, err)
			}
		})
	}
	php := runtimecatalog.PHP[0]
	calls := 0
	err := downloadRuntimeSourceWith(context.Background(), php, "fixed-source", func(context.Context, string, string, string, sourceDownloadLimits) error {
		calls++
		return sourceHTTPError{Status: 404}
	})
	if calls != 1 || err == nil {
		t.Fatal("Apache archive policy escaped into PHP")
	}
}

func TestRuntimeSourceDownloadCancelledBeforeOrBetweenRequests(t *testing.T) {
	r, _ := runtimecatalog.Find("apache-2.4.68")
	for _, before := range []bool{false, true} {
		t.Run(fmt.Sprint(before), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if before {
				cancel()
			}
			calls := 0
			err := downloadRuntimeSourceWith(ctx, r, "fixed-source", func(context.Context, string, string, string, sourceDownloadLimits) error {
				calls++
				cancel()
				return sourceHTTPError{Status: 404}
			})
			want := 1
			if before {
				want = 0
			}
			if !errors.Is(err, context.Canceled) || calls != want {
				t.Fatalf("cancelled source contacted again: %d %v", calls, err)
			}
		})
	}
}

func TestRuntimeSourceDownloadRejectsChangedCatalogueBeforeNetwork(t *testing.T) {
	r, _ := runtimecatalog.Find("apache-2.4.68")
	for _, field := range []string{"id", "url", "sha", "version"} {
		t.Run(field, func(t *testing.T) {
			wrong := r
			switch field {
			case "id":
				wrong.ID = "unknown"
			case "url":
				wrong.URL = "https://unreviewed.example/source"
			case "sha":
				wrong.SHA256 = strings.Repeat("0", 64)
			case "version":
				wrong.Version = "999"
			}
			calls := 0
			err := downloadRuntimeSourceWith(context.Background(), wrong, "fixed-source", func(context.Context, string, string, string, sourceDownloadLimits) error { calls++; return nil })
			if err == nil || calls != 0 {
				t.Fatal("unreviewed source reached network")
			}
		})
	}
}

func runtimeSourceTestDigest(data []byte) string {
	b := sha256.Sum256(data)
	return hex.EncodeToString(b[:])
}

func TestRuntimeSourceDownloadSlowProgressStillVerifiesEveryByte(t *testing.T) {
	data := []byte("exact-reviewed-source")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, b := range data {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
			if _, err := w.Write([]byte{b}); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer server.Close()
	dst := filepath.Join(t.TempDir(), "source")
	start := time.Now()
	err := downloadVerifiedWithLimits(context.Background(), server.URL, runtimeSourceTestDigest(data), dst, sourceDownloadLimits{Total: 2 * time.Second, BodyIdle: 120 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != string(data) || time.Since(start) < 300*time.Millisecond {
		t.Fatal("slow body was not actually streamed")
	}
	st, _ := os.Stat(dst)
	if st.Mode().Perm() != 0600 {
		t.Fatal("source cache not private")
	}
}

func TestRuntimeSourceDownloadNoProgressAndPartialProgressFailClosed(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if partial {
					w.Write([]byte("partial"))
				} else {
					w.WriteHeader(200)
				}
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer server.Close()
			dst := filepath.Join(t.TempDir(), "source")
			start := time.Now()
			err := downloadVerifiedWithLimits(context.Background(), server.URL, strings.Repeat("0", 64), dst, sourceDownloadLimits{Total: 2 * time.Second, BodyIdle: 70 * time.Millisecond})
			if !errors.Is(err, errRuntimeSourceBodyIdle) || time.Since(start) > time.Second {
				t.Fatalf("idle did not stop bounded body read: %v", err)
			}
			got, _ := os.ReadFile(dst)
			want := ""
			if partial {
				want = "partial"
			}
			if string(got) != want {
				t.Fatal("original partial evidence lost")
			}
		})
	}
}

func TestRuntimeSourceDownloadTotalBudgetEvenWithContinuousProgress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for {
			if _, err := w.Write([]byte("progress")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(15 * time.Millisecond):
			}
		}
	}))
	defer server.Close()
	dst := filepath.Join(t.TempDir(), "source")
	start := time.Now()
	err := downloadVerifiedWithLimits(context.Background(), server.URL, strings.Repeat("0", 64), dst, sourceDownloadLimits{Total: 120 * time.Millisecond, BodyIdle: 80 * time.Millisecond})
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || errors.Is(err, errRuntimeSourceBodyIdle) || time.Since(start) > time.Second {
		t.Fatalf("continuous progress escaped total deadline: %v", err)
	}
}

func TestRuntimeSourceDownloadDigestMismatchHasNoSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("wrong-source")) }))
	defer server.Close()
	dst := filepath.Join(t.TempDir(), "source")
	err := downloadVerifiedWithLimits(context.Background(), server.URL, strings.Repeat("0", 64), dst, sourceDownloadLimits{Total: time.Second, BodyIdle: 500 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("unverified source was accepted: %v", err)
	}
}

func TestRuntimeSourceDownloadStrictTLSBeforeCreatingSource(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("untrusted certificate")) }))
	defer server.Close()
	dst := filepath.Join(t.TempDir(), "source")
	err := downloadVerifiedWithLimits(context.Background(), server.URL, strings.Repeat("0", 64), dst, sourceDownloadLimits{Total: time.Second, BodyIdle: 500 * time.Millisecond})
	var authority x509.UnknownAuthorityError
	if !errors.As(err, &authority) {
		t.Fatalf("strict TLS missing: %v", err)
	}
	if _, err := os.Lstat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("untrusted TLS created a source file")
	}
}

func TestRuntimeSourceDownloadRedirectCannotChooseOtherHostOrDowngrade(t *testing.T) {
	for _, target := range []string{"http://archive.apache.org/dist/httpd/source.tar.gz", "https://unreviewed.example/source.tar.gz"} {
		t.Run(target, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target, 302) }))
			defer server.Close()
			dst := filepath.Join(t.TempDir(), "source")
			err := downloadVerifiedWithLimits(context.Background(), server.URL, strings.Repeat("0", 64), dst, sourceDownloadLimits{Total: time.Second, BodyIdle: 500 * time.Millisecond})
			if err == nil || !strings.Contains(err.Error(), "重定向超出允许来源") {
				t.Fatalf("redirect policy escaped: %v", err)
			}
			if _, err := os.Lstat(dst); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected redirect created source")
			}
		})
	}
}

func TestRuntimeSourceDownloadRejectsInvalidBudgetsBeforeNetwork(t *testing.T) {
	limits := []sourceDownloadLimits{{}, {Total: 21 * time.Minute, BodyIdle: time.Second}, {Total: time.Second, BodyIdle: 46 * time.Second}, {Total: -time.Second, BodyIdle: time.Second}}
	for _, limit := range limits {
		if err := downloadVerifiedWithLimits(context.Background(), "https://unused.example/source", strings.Repeat("0", 64), filepath.Join(t.TempDir(), "source"), limit); err == nil {
			t.Fatal("unbounded transfer budget accepted")
		}
	}
}

func TestRuntimeSourceDownloadBodyCapacityStillBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		block := make([]byte, 64<<10)
		for i := 0; i < 1025; i++ {
			if _, err := w.Write(block); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	dst := filepath.Join(t.TempDir(), "source")
	err := downloadVerifiedWithLimits(context.Background(), server.URL, strings.Repeat("0", 64), dst, sourceDownloadLimits{Total: 10 * time.Second, BodyIdle: time.Second})
	if err == nil || !strings.Contains(err.Error(), "超过限制") {
		t.Fatalf("body byte bound missing: %v", err)
	}
	st, err := os.Stat(dst)
	if err != nil || st.Size() != 64*1024*1024+1 {
		t.Fatal("size was not actually bounded")
	}
}
