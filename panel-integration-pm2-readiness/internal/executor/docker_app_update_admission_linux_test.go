//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestMemcachedAdmissionUnsignedOrAmbiguousSubmissionNeverCreatesOriginalJob(t *testing.T) {
	for _, scenario := range []string{"unsigned", "duplicate", "extra-field", "case-alias", "wrong-path", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			_, seed := memcachedJournalFixture(t)
			var in core.MemcachedUpdateSubmission
			in.Record = seed.Record
			if json.Unmarshal(seed.Envelope, &in.Envelope) != nil {
				t.Fatal("fixture envelope")
			}
			body, _ := json.Marshal(in)
			want := 400
			path := "/v1/docker/projects/" + seed.Record.Dispatch.ProjectID + "/app-updates/" + seed.Record.Dispatch.JobID
			switch scenario {
			case "unsigned":
				want = 409
			case "duplicate":
				body = append([]byte(`{"record":null,`), body[1:]...)
			case "extra-field":
				body = append([]byte(`{"verified":true,`), body[1:]...)
			case "case-alias":
				body = bytes.Replace(body, []byte(`"record"`), []byte(`"Record"`), 1)
			case "wrong-path":
				path = strings.Replace(path, seed.Record.Dispatch.ProjectID, strings.Repeat("f", 32), 1)
			case "oversize":
				body = bytes.Repeat([]byte(" "), core.MaxMemcachedUpdateSubmissionBytes+1)
			}
			before, be := os.Lstat(memcachedUpdateJobsRoot)
			mux := http.NewServeMux()
			New(Config{}).memcachedAppUpdateAdmissionRoutes(mux)
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			after, ae := os.Lstat(memcachedUpdateJobsRoot)
			if w.Code != want || os.IsNotExist(be) != os.IsNotExist(ae) || be == nil && (ae != nil || !geoStoreStableInfo(before, after)) {
				t.Fatal("untrusted admission touched native store", w.Code, w.Body.String())
			}
		})
	}
}
