package core

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRedisACLAuthenticationModeValidation(t *testing.T) {
	v := RedisInstance{ID: ID(), Name: "ACL auth", ReleaseID: "redis-8.2.10", Port: 16379, MaxMemoryMB: 128, CreatedAt: Now()}
	for _, mode := range []string{"", RedisACLAuthMode, RedisLegacyACLAuthMode} {
		v.AuthMode = mode
		if err := ValidateRedisInstance(v); err != nil {
			t.Fatal("valid existing/new mode refused", err)
		}
	}
	for _, mode := range []string{"none", "legacy", "password", "\nacl-password-v1"} {
		v.AuthMode = mode
		if ValidateRedisInstance(v) == nil {
			t.Fatal("unknown auth mode admitted")
		}
	}
}

func TestRedisACLCreateAlwaysSelectsSecureIdentity(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	accessUser(t, s, "database-admin", "admin", []string{"databases"})
	cookie := login("database-admin")
	csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
	for _, mode := range []string{"", "legacy", "forged-mode", RedisACLAuthMode} {
		calls := 0
		a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			var instance RedisInstance
			if r.Method != "POST" || r.URL.Path != "/v1/redis/instances" || json.NewDecoder(r.Body).Decode(&instance) != nil {
				t.Fatal("unexpected creation contract")
			}
			if instance.AuthMode != RedisACLAuthMode || !ValidID(instance.ID) || instance.CreatedAt == "" {
				t.Fatal("new instance could opt out of ACL")
			}
			raw, _ := json.Marshal(instance)
			return &http.Response{StatusCode: 201, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
		})}}
		raw, _ := json.Marshal(RedisInstance{Name: "new secure cache", ReleaseID: "redis-8.2.10", Port: 16379, MaxMemoryMB: 128, AuthMode: mode})
		response := wafBackupArchiveCorePost(a, "/api/redis/instances", string(raw), cookie, csrf, a.Config.Origin)
		if response.Code != 201 || calls != 1 || !strings.Contains(response.Body.String(), RedisACLAuthMode) {
			t.Fatal("normal secure create", response.Code, calls, response.Body.String())
		}
	}
}

func TestRedisACLCredentialsRequireCurrentDatabaseAdminCSRFAndOrigin(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	accessUser(t, s, "database-admin", "admin", []string{"databases"})
	path := "/api/redis/instances/" + strings.Repeat("a", 32) + "/credentials"
	for _, name := range []string{"anonymous", "runtime-admin", "audit-admin", "waf-admin", "reader", "operator", "no-csrf", "foreign-origin"} {
		var cookie *http.Cookie
		csrf := ""
		origin := a.Config.Origin
		want := 403
		if name == "anonymous" {
			want = 401
		} else {
			user := name
			if name == "no-csrf" || name == "foreign-origin" {
				user = "database-admin"
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
		result := wafBackupArchiveCorePost(a, path, "{}", cookie, csrf, origin)
		if result.Code != want {
			t.Fatal("unauthorized credential read", name, result.Code)
		}
	}
	cookie := login("database-admin")
	csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
	for _, body := range []string{"{\"password\":\"invented\"}", "{}{}", "{\"command\":\"ACL LIST\"}"} {
		if result := wafBackupArchiveCorePost(a, path, body, cookie, csrf, a.Config.Origin); result.Code != 400 {
			t.Fatal("unclosed credential request admitted", result.Code)
		}
	}
}

func TestRedisACLCredentialsReturnOnlyAppIdentityWithDurableAudit(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	accessUser(t, s, "database-admin", "admin", []string{"databases"})
	cookie := login("database-admin")
	csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
	id := strings.Repeat("a", 32)
	password := strings.Repeat("bc", 32)
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var body map[string]any
		if r.Method != "POST" || r.URL.Path != "/v1/redis/instances/"+id+"/credentials" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 0 {
			t.Fatal("credential forwarding changed")
		}
		raw, _ := json.Marshal(RedisCredentials{Host: "127.0.0.1", Port: 16379, Username: "app-" + id[:12], Password: password, AuthMode: RedisACLAuthMode})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	result := wafBackupArchiveCorePost(a, "/api/redis/instances/"+id+"/credentials", "{}", cookie, csrf, a.Config.Origin)
	if result.Code != 200 || calls != 1 || result.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential read/cache policy", result.Code)
	}
	var value map[string]any
	if json.Unmarshal(result.Body.Bytes(), &value) != nil || len(value) != 5 || value["password"] != password || value["username"] != "app-"+id[:12] {
		t.Fatal("wrong public credential schema")
	}
	var target string
	if err := s.DB.QueryRow("SELECT target FROM audit_logs WHERE action='redis.credentials.read' AND actor='database-admin' AND result='succeeded'").Scan(&target); err != nil || target != id {
		t.Fatal("credential read audit missing", err)
	}
	var leak int
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE target LIKE ?", "%"+password+"%").Scan(&leak); err != nil || leak != 0 {
		t.Fatal("credential audit leaked password")
	}
}

func TestRedisACLCredentialsRevocationDuringReadDoesNotReturnPassword(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	user := accessUser(t, s, "database-admin", "admin", []string{"databases"})
	cookie := login("database-admin")
	csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
	id := strings.Repeat("a", 32)
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if _, err := s.DB.Exec("UPDATE app_user_menus SET menu_ids='[]',revision=revision+1 WHERE user_id=?", user.ID); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(RedisCredentials{Host: "127.0.0.1", Port: 16379, Username: "app-" + id[:12], Password: strings.Repeat("bc", 32), AuthMode: RedisACLAuthMode})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	result := wafBackupArchiveCorePost(a, "/api/redis/instances/"+id+"/credentials", "{}", cookie, csrf, a.Config.Origin)
	if result.Code != 403 || strings.Contains(result.Body.String(), strings.Repeat("bc", 32)) {
		t.Fatal("revoked response disclosed private credential", result.Code)
	}
	var n int
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='redis.credentials.read'").Scan(&n); err != nil || n != 0 {
		t.Fatal("revoked read was reported successful")
	}
}

func TestRedisACLCredentialsInvalidSinkAndFailedAuditNeverDisclose(t *testing.T) {
	for _, scenario := range []string{"wrong-host", "wrong-user", "nonhex-password", "wrong-auth-mode", "audit-failure", "old-instance-refusal"} {
		t.Run(scenario, func(t *testing.T) {
			s, a, login := wafTaskTestServer(t)
			accessUser(t, s, "database-admin", "admin", []string{"databases"})
			cookie := login("database-admin")
			csrf := wafBackupArchiveCoreCSRF(t, a, cookie)
			id := strings.Repeat("a", 32)
			password := strings.Repeat("bc", 32)
			if scenario == "audit-failure" {
				if _, err := s.DB.Exec("CREATE TRIGGER deny_redis_credential_audit BEFORE INSERT ON audit_logs WHEN NEW.action='redis.credentials.read' BEGIN SELECT RAISE(ABORT,'fixture refused audit'); END"); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				value := RedisCredentials{Host: "127.0.0.1", Port: 16379, Username: "app-" + id[:12], Password: password, AuthMode: RedisACLAuthMode}
				switch scenario {
				case "wrong-host":
					value.Host = "public.invalid"
				case "wrong-user":
					value.Username = "panel-admin"
				case "nonhex-password":
					value.Password = strings.Repeat("z", 64)
				case "wrong-auth-mode":
					value.AuthMode = "legacy"
				}
				raw, _ := json.Marshal(value)
				status := 200
				if scenario == "old-instance-refusal" {
					status = 409
					raw = []byte("{\"error\":\"do-not-echo-legacy-error\"}")
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			result := wafBackupArchiveCorePost(a, "/api/redis/instances/"+id+"/credentials", "{}", cookie, csrf, a.Config.Origin)
			want := 503
			if scenario == "old-instance-refusal" {
				want = 409
			}
			if result.Code != want || calls != 1 || strings.Contains(result.Body.String(), password) || strings.Contains(result.Body.String(), "do-not-echo") {
				t.Fatal("invalid/unaudited credential escaped", scenario, result.Code, calls)
			}
		})
	}
}
