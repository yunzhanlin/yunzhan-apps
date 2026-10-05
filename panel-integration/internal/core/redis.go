package core

import (
	"errors"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var redisInstanceName = regexp.MustCompile(`^[\p{Han}A-Za-z0-9][\p{Han}A-Za-z0-9_. -]{0,39}$`)

type RedisInstance struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	ReleaseID   string           `json:"release_id"`
	Port        int              `json:"port"`
	MaxMemoryMB int              `json:"max_memory_mb"`
	CreatedAt   string           `json:"created_at"`
	Status      string           `json:"status,omitempty"`
	Clients     int              `json:"clients,omitempty"`
	UsedMemory  int64            `json:"used_memory,omitempty"`
	LogicalDBs  []RedisLogicalDB `json:"logical_dbs,omitempty"`
}
type RedisLogicalDB struct {
	Index      int   `json:"index"`
	Keys       int64 `json:"keys"`
	Expires    int64 `json:"expires"`
	AverageTTL int64 `json:"avg_ttl"`
}

func ValidateRedisInstance(v RedisInstance) error {
	if !ValidID(v.ID) || !redisInstanceName.MatchString(v.Name) || v.Port < 16379 || v.Port > 16999 || v.MaxMemoryMB < 32 || v.MaxMemoryMB > 16384 {
		return errors.New("Redis 实例名称、端口或内存限制无效")
	}
	r, ok := runtimecatalog.Find(v.ReleaseID)
	if !ok || r.Family != "redis" {
		return errors.New("请选择已安装的 Redis 版本")
	}
	return nil
}

func (a *Server) redisRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/redis/instances/{id}/keys/hash-field", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		name, field := r.URL.Query().Get("name"), r.URL.Query().Get("field")
		if err != nil || !ValidID(id) || db < 0 || db > 15 || !validRedisHashNames(name, field) {
			fail(w, 400, "Redis 哈希字段参数无效")
			return
		}
		query := url.Values{"db": {strconv.Itoa(db)}, "name": {name}, "field": {field}}
		var out any
		if err = a.Executor.Call(r.Context(), http.MethodGet, "/v1/redis/instances/"+id+"/keys/hash-field?"+query.Encode(), nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("PUT /api/redis/instances/{id}/keys/hash-field", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			DB       int    `json:"db"`
			Name     string `json:"name"`
			Field    string `json:"field"`
			OldValue string `json:"old_value"`
			Value    string `json:"value"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || in.DB < 0 || in.DB > 15 || !validRedisHashNames(in.Name, in.Field) || len(in.OldValue) > 4096 || len(in.Value) > 4096 || !utf8.ValidString(in.OldValue) || !utf8.ValidString(in.Value) || strings.ContainsRune(in.OldValue, '\x00') || strings.ContainsRune(in.Value, '\x00') {
			fail(w, 400, "Redis 哈希字段内容无效")
			return
		}
		var out map[string]any
		if err := a.Executor.Call(r.Context(), http.MethodPut, "/v1/redis/instances/"+id+"/keys/hash-field", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "redis.hash.field.update", id+":db"+strconv.Itoa(in.DB)+":"+Hash(in.Name + "\x00" + in.Field)[:12], "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/redis/instances/{id}/keys/hash-field", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			DB           int    `json:"db"`
			Name         string `json:"name"`
			Field        string `json:"field"`
			OldValue     string `json:"old_value"`
			ConfirmField string `json:"confirm_field"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || in.DB < 0 || in.DB > 15 || !validRedisHashNames(in.Name, in.Field) || in.ConfirmField != in.Field || len(in.OldValue) > 4096 || !utf8.ValidString(in.OldValue) || strings.ContainsRune(in.OldValue, '\x00') {
			fail(w, 400, "Redis 哈希字段删除参数无效")
			return
		}
		var out map[string]any
		if err := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/redis/instances/"+id+"/keys/hash-field", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "redis.hash.field.delete", id+":db"+strconv.Itoa(in.DB)+":"+Hash(in.Name + "\x00" + in.Field)[:12], "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/redis/instances/{id}/keys/hash-field", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			DB    int    `json:"db"`
			Name  string `json:"name"`
			Field string `json:"field"`
			Value string `json:"value"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || in.DB < 0 || in.DB > 15 || !validRedisHashNames(in.Name, in.Field) || len(in.Value) > 4096 || !utf8.ValidString(in.Value) || strings.ContainsRune(in.Value, '\x00') {
			fail(w, 400, "Redis 哈希新字段参数无效")
			return
		}
		var out map[string]any
		if err := a.Executor.Call(r.Context(), http.MethodPost, "/v1/redis/instances/"+id+"/keys/hash-field", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "redis.hash.field.add", id+":db"+strconv.Itoa(in.DB)+":"+Hash(in.Name + "\x00" + in.Field)[:12], "succeeded")
		send(w, 201, out)
	}))
	m.HandleFunc("GET /api/redis/instances/{id}/keys/preview", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		name := r.URL.Query().Get("name")
		if err != nil || !ValidID(id) || db < 0 || db > 15 || len(name) == 0 || len(name) > 256 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			fail(w, 400, "Redis 键预览参数无效")
			return
		}
		query := url.Values{"db": {strconv.Itoa(db)}, "name": {name}}
		var out any
		if err = a.Executor.Call(r.Context(), http.MethodGet, "/v1/redis/instances/"+id+"/keys/preview?"+query.Encode(), nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/redis/instances/{id}/keys", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		cursor := r.URL.Query().Get("cursor")
		pattern := r.URL.Query().Get("pattern")
		if cursor == "" {
			cursor = "0"
		}
		if pattern == "" {
			pattern = "*"
		}
		if !ValidID(id) || db < 0 || db > 15 || len(cursor) > 20 || len(pattern) > 128 || !utf8.ValidString(pattern) || strings.ContainsAny(pattern, "\x00\r\n") {
			fail(w, 400, "Redis 键查询参数无效")
			return
		}
		if _, err = strconv.ParseUint(cursor, 10, 64); err != nil {
			fail(w, 400, "Redis 扫描游标无效")
			return
		}
		query := url.Values{"db": {strconv.Itoa(db)}, "cursor": {cursor}, "pattern": {pattern}}
		var out any
		if err = a.Executor.Call(r.Context(), http.MethodGet, "/v1/redis/instances/"+id+"/keys?"+query.Encode(), nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/redis/instances/{id}/keys/info", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		name := r.URL.Query().Get("name")
		if !ValidID(id) || db < 0 || db > 15 || len(name) == 0 || len(name) > 256 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			fail(w, 400, "Redis 键详情参数无效")
			return
		}
		query := url.Values{"db": {strconv.Itoa(db)}, "name": {name}}
		var out any
		if err = a.Executor.Call(r.Context(), http.MethodGet, "/v1/redis/instances/"+id+"/keys/info?"+query.Encode(), nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/redis/instances/{id}/keys/value", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		name := r.URL.Query().Get("name")
		if !ValidID(id) || db < 0 || db > 15 || len(name) == 0 || len(name) > 256 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			fail(w, 400, "Redis 键内容参数无效")
			return
		}
		query := url.Values{"db": {strconv.Itoa(db)}, "name": {name}}
		var out any
		if err = a.Executor.Call(r.Context(), http.MethodGet, "/v1/redis/instances/"+id+"/keys/value?"+query.Encode(), nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("PUT /api/redis/instances/{id}/keys/value", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			DB       int    `json:"db"`
			Name     string `json:"name"`
			OldValue string `json:"old_value"`
			Value    string `json:"value"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || in.DB < 0 || in.DB > 15 || len(in.Name) == 0 || len(in.Name) > 256 || !utf8.ValidString(in.Name) || strings.ContainsAny(in.Name, "\x00\r\n") || len(in.OldValue) > 4096 || len(in.Value) > 4096 || !utf8.ValidString(in.OldValue) || !utf8.ValidString(in.Value) || strings.ContainsRune(in.OldValue, '\x00') || strings.ContainsRune(in.Value, '\x00') {
			fail(w, 400, "Redis 文本键参数无效")
			return
		}
		var out map[string]any
		if err := a.Executor.Call(r.Context(), http.MethodPut, "/v1/redis/instances/"+id+"/keys/value", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "redis.key.value.update", id+":db"+strconv.Itoa(in.DB)+":"+Hash(in.Name)[:12], "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("PUT /api/redis/instances/{id}/keys/ttl", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			DB         int    `json:"db"`
			Name       string `json:"name"`
			TTLSeconds int64  `json:"ttl_seconds"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || in.DB < 0 || in.DB > 15 || len(in.Name) == 0 || len(in.Name) > 256 || !utf8.ValidString(in.Name) || strings.ContainsAny(in.Name, "\x00\r\n") || (in.TTLSeconds != -1 && (in.TTLSeconds < 1 || in.TTLSeconds > 31536000)) {
			fail(w, 400, "Redis 键有效期参数无效")
			return
		}
		var out map[string]any
		if err := a.Executor.Call(r.Context(), http.MethodPut, "/v1/redis/instances/"+id+"/keys/ttl", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "redis.key.ttl.update", id+":db"+strconv.Itoa(in.DB)+":"+Hash(in.Name)[:12], "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/redis/instances/{id}/keys", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			DB          int    `json:"db"`
			Name        string `json:"name"`
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || in.DB < 0 || in.DB > 15 || len(in.Name) == 0 || len(in.Name) > 256 || !utf8.ValidString(in.Name) || strings.ContainsAny(in.Name, "\x00\r\n") || in.ConfirmName != in.Name {
			fail(w, 400, "Redis 键删除参数或确认名称无效")
			return
		}
		var out map[string]any
		if err := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/redis/instances/"+id+"/keys", in, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "redis.key.delete", id+":db"+strconv.Itoa(in.DB)+":"+Hash(in.Name)[:12], "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/redis/instances", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/redis/instances", nil, &out); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/redis/instances", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in RedisInstance
		if !decode(w, r, &in) {
			return
		}
		in.ID = ID()
		in.CreatedAt = Now()
		in.LogicalDBs = nil
		if e := ValidateRedisInstance(in); e != nil {
			fail(w, 400, e.Error())
			return
		}
		var out RedisInstance
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/redis/instances", in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "redis.instance.create", in.Name, "succeeded")
		send(w, 201, out)
	}))
	m.HandleFunc("POST /api/redis/instances/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id, action := r.PathValue("id"), r.PathValue("action")
		if !ValidID(id) || (action != "start" && action != "stop" && action != "restart") {
			fail(w, 400, "Redis 实例操作无效")
			return
		}
		var out RedisInstance
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/redis/instances/"+id+"/"+action, map[string]any{}, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "redis.instance."+action, id, "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/redis/instances/{id}/logs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !ValidID(r.PathValue("id")) {
			fail(w, 400, "Redis 实例标识无效")
			return
		}
		var out map[string]string
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/redis/instances/"+r.PathValue("id")+"/logs", nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/redis/instances/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || !redisInstanceName.MatchString(in.ConfirmName) {
			fail(w, 400, "Redis 删除确认无效")
			return
		}
		var out map[string]bool
		if e := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/redis/instances/"+id, in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "redis.instance.delete", in.ConfirmName, "succeeded")
		send(w, 200, out)
	}))
}

func validRedisHashNames(name, field string) bool {
	return len(name) > 0 && len(name) <= 256 && utf8.ValidString(name) && !strings.ContainsAny(name, "\x00\r\n") && len(field) > 0 && len(field) < 512 && utf8.ValidString(field) && !strings.ContainsAny(field, "\x00\r\n")
}
