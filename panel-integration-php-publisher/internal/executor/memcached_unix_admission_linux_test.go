//go:build linux

package executor

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestMemcachedUnixAdmissionUntrustedTransportNeverCreatesDefaultNamespace(t *testing.T) {
	_, raw, head := memcachedUnixJournalFixture(t)
	for _, kind := range []string{"unsigned", "duplicate", "alias", "extra", "oversize", "foreign-job", "query"} {
		t.Run(kind, func(t *testing.T) {
			body := append([]byte(nil), raw...)
			path := "/v1/docker/memcached-unix/installs/" + head.Operation.JobID
			want := 400
			switch kind {
			case "unsigned":
				want = 409
			case "duplicate":
				body = append([]byte(`{"operation":null,`), body[1:]...)
			case "alias":
				body = bytes.Replace(body, []byte(`"operation"`), []byte(`"Operation"`), 1)
			case "extra":
				body = append([]byte(`{"verified":true,`), body[1:]...)
			case "oversize":
				body = bytes.Repeat([]byte(" "), core.MaxMemcachedUnixInstallSubmissionBytes+1)
			case "foreign-job":
				path = "/v1/docker/memcached-unix/installs/" + strings.Repeat("f", 32)
			case "query":
				path += "?retry=true"
				want = 404
			}
			before, be := os.Lstat(memcachedUnixInstallJobsRoot)
			mux := http.NewServeMux()
			New(Config{}).memcachedUnixInstallAdmissionRoutes(mux)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
			after, ae := os.Lstat(memcachedUnixInstallJobsRoot)
			if w.Code != want || os.IsNotExist(be) != os.IsNotExist(ae) || be == nil && (ae != nil || !geoStoreStableInfo(before, after)) {
				t.Fatal("untrusted default admission wrote/replayed native work", kind, w.Code, w.Body.String())
			}
		})
	}
}

func TestMemcachedUnixAccountEntryAndOriginalRunCannotBorrowCallerJobOrForeignUnit(t *testing.T) {
	if RunMemcachedUnixAccountJob("../foreign") == nil || RunMemcachedUnixAccountJob(strings.Repeat("a", 32)) == nil {
		t.Fatal("foreign/invalid fixed dependency scope reached NSS changes")
	}
	if _, err := memcachedUnixAccountInstance("bad"); err == nil {
		t.Fatal("invalid account unit instance")
	}
	if _, err := memcachedUnixFindOriginalRun(nil, nil); err == nil {
		t.Fatal("nil original run authority")
	}
	if (&memcachedUnixOriginalRun{}).current(context.Background()) == nil {
		t.Fatal("empty run witness became authority")
	}
	if _, err := acquireMemcachedUnixRuntime(nil); err == nil {
		t.Fatal("nil shared lifetime capability")
	}
}
