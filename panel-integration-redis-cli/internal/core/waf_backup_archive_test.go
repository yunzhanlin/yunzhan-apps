package core

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestWAFBackupArchiveInputOnlyAcceptsBoundOriginalIdentityAndExactConsent(t *testing.T) {
	in := WAFBackupArchiveInput{ID: strings.Repeat("1", 32), SHA: strings.Repeat("a", 64), Confirm: "ARCHIVE NGINX CONFIG " + strings.Repeat("1", 32)}
	raw, _ := json.Marshal(in)
	if got, err := DecodeWAFBackupArchive(raw); err != nil || got != in {
		t.Fatal(got, err)
	}
	for _, bad := range []string{
		string(raw) + " {}", strings.Replace(string(raw), `"confirm":`, `"path":"/etc/shadow","confirm":`, 1),
		strings.Replace(string(raw), `"resource_id":`, `"resource_id":null,"resource_id":`, 1),
		strings.Replace(string(raw), `"expected_sha":`, `"expec\u0074ed_sha":null,"expected_sha":`, 1),
		strings.Replace(string(raw), `"confirm":`, `"Confirm":`, 1), strings.Replace(string(raw), "ARCHIVE NGINX CONFIG", "DELETE", 1),
	} {
		if _, err := DecodeWAFBackupArchive([]byte(bad)); err == nil {
			t.Fatal("unreviewed archive input accepted", bad)
		}
	}
}

func wafBackupArchiveCoreFixture() (WAFBackupArchiveInput, WAFBackupArchiveResult) {
	row := wafInventoryCoreFixture().Entries[0]
	in := WAFBackupArchiveInput{ID: row.ID, SHA: row.SHA, Confirm: "ARCHIVE NGINX CONFIG " + row.ID}
	return in, WAFBackupArchiveResult{Snapshot: row, Archived: true, RecordsRetained: true}
}

func TestWAFBackupArchiveResultIsClosedAndBoundToOriginalFullDigest(t *testing.T) {
	in, out := wafBackupArchiveCoreFixture()
	raw, _ := json.Marshal(out)
	if got, err := DecodeWAFBackupArchiveResult(raw, in); err != nil || !reflect.DeepEqual(got, out) {
		t.Fatal(got, err)
	}
	for _, bad := range []string{
		string(raw) + " {}", strings.Replace(string(raw), `"archived":true`, `"archived":null`, 1),
		strings.Replace(string(raw), `"archived":true`, `"Archived":true`, 1), strings.Replace(string(raw), `"replayed":false`, `"replayed":false,"repl\u0061yed":true`, 1),
		strings.Replace(string(raw), `"records_retained":true`, `"records_retained":false`, 1), strings.Replace(string(raw), `"configuration_changed":false`, `"configuration_changed":true`, 1),
		strings.Replace(string(raw), in.ID, strings.Repeat("2", 32), 1), strings.Replace(string(raw), in.SHA, strings.Repeat("b", 64), 1),
		strings.Replace(string(raw), `"files":5`, `"files":5,"source":"/private/config"`, 1), strings.Replace(string(raw), `"bytes":123`, `"bytes":null`, 1),
	} {
		if _, err := DecodeWAFBackupArchiveResult([]byte(bad), in); err == nil {
			t.Fatal("unverified archive result accepted", bad)
		}
	}
}

func wafBackupArchiveCorePost(a *Server, path, body string, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", origin)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func wafBackupArchiveCoreCSRF(t *testing.T, a *Server, cookie *http.Cookie) string {
	t.Helper()
	w := wafTaskTestRead(a, "/api/me", cookie)
	var out struct {
		CSRF string `json:"csrf"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CSRF == "" {
		t.Fatal("actual session CSRF", w.Code)
	}
	return out.CSRF
}

func TestWAFBackupArchiveActualAuthStrictForwardingAndDurableAuditPair(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	in, result := wafBackupArchiveCoreFixture()
	raw, _ := json.Marshal(in)
	response, _ := json.Marshal(result)
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.RequestURI() != "/v1/software/nginx-waf/archive-config-backup" {
			t.Fatal("unbound executor operation", r.Method, r.URL)
		}
		body, err := io.ReadAll(r.Body)
		got, decodeErr := DecodeWAFBackupArchive(body)
		if err != nil || decodeErr != nil || got != in {
			t.Fatal("original consent changed", string(body), err, decodeErr)
		}
		var requested int
		if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.config-backup.archive-requested' AND target=?`, in.ID).Scan(&requested); err != nil || requested < 1 {
			t.Fatal("operation preceded request audit", requested, err)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(response))), Request: r}, nil
	})}}
	path := "/api/software/nginx-waf/archive-config-backup"
	cookie := login("waf-admin")
	csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
	if w := wafBackupArchiveCorePost(a, path, string(raw), nil, csrf, a.Config.Origin); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, name := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		c := login(name)
		token := wafBackupArchiveCoreCSRF(t, a, c)
		if w := wafBackupArchiveCorePost(a, path, string(raw), c, token, a.Config.Origin); w.Code != 403 {
			t.Fatal("authority expanded", name, w.Code)
		}
	}
	for _, v := range []struct{ token, origin string }{{"wrong", a.Config.Origin}, {csrf, "https://foreign.invalid"}} {
		if w := wafBackupArchiveCorePost(a, path, string(raw), cookie, v.token, v.origin); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	for _, v := range []struct{ path, body string }{{path + "?", string(raw)}, {path + "?source=/private", string(raw)}, {path, strings.Repeat(" ", 4097)}, {path, string(raw) + " {}"}, {path, strings.Replace(string(raw), `"confirm":`, `"path":"/private","confirm":`, 1)}, {path, strings.Replace(string(raw), "ARCHIVE NGINX CONFIG", "DELETE", 1)}} {
		if w := wafBackupArchiveCorePost(a, v.path, v.body, cookie, csrf, a.Config.Origin); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if calls != 0 {
		t.Fatal("invalid/unauthorized input reached executor", calls)
	}
	w := wafBackupArchiveCorePost(a, path, string(raw), cookie, csrf, a.Config.Origin)
	if w.Code != 200 || calls != 1 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String(), calls)
	}
	if _, err := DecodeWAFBackupArchiveResult(w.Body.Bytes(), in); err != nil {
		t.Fatal(err)
	}
	var audit int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action IN ('waf.config-backup.archive-requested','waf.config-backup.archive-confirmed') AND target=?`, in.ID).Scan(&audit); err != nil || audit != 2 {
		t.Fatal("audit pair", audit, err)
	}
	for _, global := range []string{"/api/sites", "/api/jobs/" + ID(), "/api/sites/" + ID() + "/files"} {
		if w := wafTaskTestRead(a, global, cookie); w.Code != 403 {
			t.Fatal("extra authority granted", global, w.Code)
		}
	}
}

func TestWAFBackupArchiveUncertainReplyAndAuditFailureNeverClaimNoHandoff(t *testing.T) {
	for _, kind := range []string{"lost-reply", "private-reply", "wrong-digest", "request-audit", "confirmed-audit"} {
		t.Run(kind, func(t *testing.T) {
			s, a, login := wafTaskTestServer(t)
			cookie := login("waf-admin")
			csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
			in, result := wafBackupArchiveCoreFixture()
			raw, _ := json.Marshal(in)
			response, _ := json.Marshal(result)
			calls := 0
			if kind == "request-audit" || kind == "confirmed-audit" {
				action := "waf.config-backup.archive-requested"
				if kind == "confirmed-audit" {
					action = "waf.config-backup.archive-confirmed"
				}
				if _, err := s.DB.Exec(`CREATE TRIGGER refuse_owned_archive_audit BEFORE INSERT ON audit_logs WHEN NEW.action='` + action + `' BEGIN SELECT RAISE(ABORT,'owned fixture audit failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if kind == "lost-reply" {
					return nil, errors.New("private socket connection lost after unknown operation")
				}
				body := string(response)
				if kind == "private-reply" {
					body = strings.Replace(body, `"files":5`, `"files":5,"source":"/private/original"`, 1)
				}
				if kind == "wrong-digest" {
					body = strings.Replace(body, in.SHA, strings.Repeat("b", 64), 1)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}}
			w := wafBackupArchiveCorePost(a, "/api/software/nginx-waf/archive-config-backup", string(raw), cookie, csrf, a.Config.Origin)
			if kind == "request-audit" {
				if w.Code != 500 || calls != 0 || !strings.Contains(w.Body.String(), "未发送") {
					t.Fatal("audit failure sent operation", w.Code, calls)
				}
			} else {
				if w.Code != 503 || calls != 1 || strings.Contains(w.Body.String(), "/private") || strings.Contains(w.Body.String(), `"archived":true`) || strings.Contains(w.Body.String(), "尚未归档") {
					t.Fatal("unknown became success/no-handoff", w.Code, w.Body.String(), calls)
				}
			}
			var confirmed int
			if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='waf.config-backup.archive-confirmed'`).Scan(&confirmed); err != nil || confirmed != 0 {
				t.Fatal("uncertain response wrote confirmed audit", confirmed, err)
			}
		})
	}
}

func TestWAFBackupArchiveReadOnlyNamespaceAndSelectedIdentityUseExistingAuthorization(t *testing.T) {
	_, a, login := wafTaskTestServer(t)
	value := wafInventoryCoreFixture()
	whole, _ := json.Marshal(value)
	row, _ := json.Marshal(value.Entries[0])
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.Body != nil || r.URL.RawQuery != "" {
			t.Fatal("read mutated operation")
		}
		body := whole
		switch r.URL.Path {
		case "/v1/software/nginx-waf/config-backup-archive":
		case "/v1/software/nginx-waf/config-backup-archive/" + value.Entries[0].ID:
			body = row
		default:
			t.Fatal("namespace changed", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
	})}}
	base := "/api/software/nginx-waf/config-backup-archive"
	for _, name := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		if w := wafTaskTestRead(a, base, login(name)); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	cookie := login("waf-admin")
	for _, bad := range []string{base + "?", base + "?namespace=/private", base + "/BAD", base + "/" + value.Entries[0].ID + "?"} {
		if w := wafTaskTestRead(a, bad, cookie); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if calls != 0 {
		t.Fatal(calls)
	}
	for _, path := range []string{base, base + "/" + value.Entries[0].ID} {
		w := wafTaskTestRead(a, path, cookie)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code)
		}
		if path == base {
			if !strings.Contains(w.Body.String(), "归档索引") {
				t.Fatal("active/archived mislabeled")
			}
		} else {
			if _, err := DecodeWAFBackupSnapshot(w.Body.Bytes()); err != nil {
				t.Fatal(err)
			}
		}
	}
	row = []byte(strings.Replace(string(row), value.Entries[0].ID, strings.Repeat("2", 32), 1))
	if w := wafTaskTestRead(a, base+"/"+value.Entries[0].ID, cookie); w.Code != 503 {
		t.Fatal("foreign selected archive accepted", w.Code)
	}
}
