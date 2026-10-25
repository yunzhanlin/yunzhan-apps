package core

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestFail2banUnbanAuthenticatedHTTPRejectsUnauthorizedBeforeExecutor(t *testing.T) {
	_, a, login := wafTaskTestServer(t)
	for _, name := range []string{"anonymous", "runtime-admin", "audit-admin", "reader", "operator", "no-csrf", "foreign-origin"} {
		t.Run(name, func(t *testing.T) {
			var cookie *http.Cookie
			csrf, origin := "", a.Config.Origin
			status := 403
			if name == "anonymous" {
				status = 401
			} else {
				user := name
				if name == "no-csrf" || name == "foreign-origin" {
					user = "waf-admin"
				}
				cookie = login(user)
				csrf = wafBackupArchiveCoreCSRF(t, a, cookie)
				if name == "no-csrf" {
					csrf = ""
				}
				if name == "foreign-origin" {
					origin = "https://untrusted.invalid"
				}
			}
			w := wafBackupArchiveCorePost(a, "/api/security/fail2ban/unban", `{"jail":"sshd","ip":"192.0.2.2"}`, cookie, csrf, origin)
			if w.Code != status {
				t.Fatal("unauthorized unban", name, w.Code, w.Body.String())
			}
		})
	}
}

func TestFail2banUnbanAuthenticatedHTTPCanonicalAddressAndActualAudit(t *testing.T) {
	for _, item := range []struct{ input, canonical string }{{"::ffff:192.0.2.2", "192.0.2.2"}, {"2001:0DB8:1::0002", "2001:db8:1::2"}} {
		t.Run(item.canonical, func(t *testing.T) {
			s, a, login := wafTaskTestServer(t)
			cookie := login("waf-admin")
			csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
			calls, replyStatus := 0, 200
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var input map[string]string
				if r.Method != "POST" || r.URL.Path != "/v1/security/fail2ban/unban" || json.NewDecoder(r.Body).Decode(&input) != nil || len(input) != 2 || input["jail"] != "sshd" || input["ip"] != item.canonical {
					t.Fatal("unexpected typed unban", r.Method, r.URL.Path, input)
				}
				body := `{"jail":"sshd","ip":"` + item.canonical + `","unbanned":true}`
				if replyStatus != 200 {
					body = `{"error":"original transaction pending; not unbanned"}`
				}
				return &http.Response{StatusCode: replyStatus, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			for _, bad := range []string{`{"jail":"sshd;exit","ip":"192.0.2.2"}`, `{"jail":"sshd","ip":"invalid"}`, `{"jail":"sshd","ip":"192.0.2.2","command":"reload"}`, `{"jail":"sshd","ip":"192.0.2.2"}{}`} {
				if w := wafBackupArchiveCorePost(a, "/api/security/fail2ban/unban", bad, cookie, csrf, a.Config.Origin); w.Code != 400 || calls != 0 {
					t.Fatal("invalid request reached executor", w.Code, calls)
				}
			}
			for index, status := range []int{200, 409} {
				replyStatus = status
				w := wafBackupArchiveCorePost(a, "/api/security/fail2ban/unban", `{"jail":"sshd","ip":"`+item.input+`"}`, cookie, csrf, a.Config.Origin)
				if w.Code != status || calls != index+1 {
					t.Fatal("unban result or retry", w.Code, calls, w.Body.String())
				}
			}
			for _, state := range []string{"success", "failed"} {
				var count int
				if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE actor='waf-admin' AND action='security.fail2ban.unban' AND target=? AND result=?`, "sshd:"+item.canonical, state).Scan(&count); err != nil || count != 1 {
					t.Fatal("actual authenticated unban audit", state, count, err)
				}
			}
		})
	}
}
