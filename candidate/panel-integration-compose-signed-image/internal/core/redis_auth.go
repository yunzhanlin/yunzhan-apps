package core

import (
	"encoding/hex"
	"net/http"
	"reflect"
)

// V2 never transmits the management credential to a TCP listener. V1 is
// recognized only to preserve old records and require explicit migration.
const RedisACLAuthMode = "acl-password-v2"
const RedisLegacyACLAuthMode = "acl-password-v1"

// RedisCredentials deliberately has no panel-management credential. Only the
// least-privilege application identity may cross the authenticated Core API.
type RedisCredentials struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	AuthMode string `json:"auth_mode"`
}

func redisCredentialsAccess(access UserAccess) bool {
	return access.Role == "admin" && containsMenu(access.MenuIDs, "databases")
}

func (a *Server) redisAuthRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/redis/instances/{id}/credentials", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		id := r.PathValue("id")
		var empty struct{}
		if !ValidID(id) {
			fail(w, 400, "Redis 实例标识无效")
			return
		}
		if !decode(w, r, &empty) {
			return
		}
		before, err := a.Store.UserAccess(u.ID)
		if err != nil || !redisCredentialsAccess(before) {
			fail(w, 403, "仅有数据库授权的管理员可以查看 Redis 应用凭据")
			return
		}
		var out RedisCredentials
		defer func() { out.Password = "" }()
		if err = a.Executor.Call(r.Context(), http.MethodPost, "/v1/redis/instances/"+id+"/credentials", struct{}{}, &out); err != nil {
			fail(w, 409, "无法读取 Redis 应用凭据；旧实例不会被自动改密")
			return
		}
		after, err := a.Store.UserAccess(u.ID)
		if err != nil || !redisCredentialsAccess(after) || !reflect.DeepEqual(before, after) {
			fail(w, 403, "授权已变化，Redis 凭据未返回")
			return
		}
		decoded, passwordErr := hex.DecodeString(out.Password)
		if out.Host != "127.0.0.1" || out.Port < 16379 || out.Port > 16999 || out.AuthMode != RedisACLAuthMode || out.Username != "app-"+id[:12] || len(out.Password) != 64 || passwordErr != nil || len(decoded) != 32 {
			fail(w, 503, "Redis 应用凭据格式无效")
			return
		}
		if err = a.Store.Audit(u.Username, "redis.credentials.read", id, "succeeded"); err != nil {
			fail(w, 503, "Redis 凭据审计失败，未返回密码")
			return
		}
		send(w, 200, out)
	}))
}
