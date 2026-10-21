//go:build linux

package executor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

type redisKeysPage struct {
	DB      int      `json:"db"`
	Cursor  string   `json:"cursor"`
	Keys    []string `json:"keys"`
	Omitted int      `json:"omitted"`
}

type redisKeyInfo struct {
	DB         int    `json:"db"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	TTLSeconds int64  `json:"ttl_seconds"`
	Size       int64  `json:"size"`
}

type redisKeyPreviewItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type redisKeyPreview struct {
	DB        int                   `json:"db"`
	Name      string                `json:"name"`
	Kind      string                `json:"kind"`
	Total     int64                 `json:"total"`
	Sampled   bool                  `json:"sampled"`
	Truncated bool                  `json:"truncated"`
	Items     []redisKeyPreviewItem `json:"items"`
}

func redisCLIJSON(ctx context.Context, instance core.RedisInstance, db int, out any, command ...string) error {
	if db < 0 || db > 15 {
		return errors.New("Redis 逻辑库无效")
	}
	if inspectRedis(ctx, instance).Status != "running" {
		return errors.New("Redis 实例未运行")
	}
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "redis" {
		return errors.New("Redis 版本不在固定目录")
	}
	args := append([]string{"--json", "-h", "127.0.0.1", "-p", strconv.Itoa(instance.Port), "-n", strconv.Itoa(db)}, command...)
	raw, err := RunCommand(ctx, release.Prefix()+"/bin/redis-cli", args...)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(strings.TrimSpace(raw)), out)
}

const redisTextUpdateScript = `local p=cjson.decode(ARGV[1]); local t=redis.call('TYPE',KEYS[1]).ok; if t=='none' then return 'missing' end; if t~='string' then return 'wrong-type' end; if redis.call('GET',KEYS[1])~=p.old then return 'changed' end; redis.call('SET',KEYS[1],p.value,'KEEPTTL'); return 'updated'`
const redisHexReadScript = `local t=redis.call('TYPE',KEYS[1]).ok; if t~=ARGV[1] then return {'wrong-type'} end; local v; if t=='hash' then v=redis.call('HGET',KEYS[1],ARGV[2]) else v=redis.call('GET',KEYS[1]) end; if not v then return {'missing'} end; if #v>4096 then return {'large'} end; local out={}; for i=1,#v do out[i]=string.format('%02x',string.byte(v,i)) end; return {'ok',table.concat(out)}`
const redisHashFieldUpdateScript = `local p=cjson.decode(ARGV[1]); if redis.call('TYPE',KEYS[1]).ok~='hash' then return 'wrong-type' end; local old=redis.call('HGET',KEYS[1],p.field); if not old then return 'missing' end; if old~=p.old then return 'changed' end; redis.call('HSET',KEYS[1],p.field,p.value); return 'updated'`
const redisHashFieldDeleteScript = `local p=cjson.decode(ARGV[1]); if redis.call('TYPE',KEYS[1]).ok~='hash' then return 'wrong-type' end; local old=redis.call('HGET',KEYS[1],p.field); if not old then return 'missing' end; if old~=p.old then return 'changed' end; redis.call('HDEL',KEYS[1],p.field); if redis.call('EXISTS',KEYS[1])==0 then return 'deleted-key' end; return 'deleted'`
const redisHashFieldAddScript = `local p=cjson.decode(ARGV[1]); if redis.call('TYPE',KEYS[1]).ok~='hash' then return 'wrong-type' end; if redis.call('HEXISTS',KEYS[1],p.field)==1 then return 'exists' end; redis.call('HSET',KEYS[1],p.field,p.value); return 'added'`
const redisTTLUpdateScript = `if redis.call('EXISTS',KEYS[1])==0 then return 'missing' end; if tonumber(ARGV[1])==-1 then redis.call('PERSIST',KEYS[1]) else redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return 'updated'`

// Limit every item before it reaches redis-cli. Random samples avoid a blocking
// full traversal of large hashes and sets; lists and sorted sets use the first page.
const redisStructuredPreviewScript = `local t=redis.call('TYPE',KEYS[1]).ok; local n=0; local a={}; if t=='list' then n=redis.call('LLEN',KEYS[1]); a=redis.call('LRANGE',KEYS[1],0,19) elseif t=='hash' then n=redis.call('HLEN',KEYS[1]); a=redis.call('HRANDFIELD',KEYS[1],20,'WITHVALUES') elseif t=='set' then n=redis.call('SCARD',KEYS[1]); a=redis.call('SRANDMEMBER',KEYS[1],20) elseif t=='zset' then n=redis.call('ZCARD',KEYS[1]); a=redis.call('ZRANGE',KEYS[1],0,19,'WITHSCORES') end; local out={t,tostring(n)}; for i=1,math.min(#a,40) do out[#out+1]=string.sub(a[i],1,512) end; return out`

func parseRedisStructuredPreview(raw []string, db int, name string) (redisKeyPreview, error) {
	result := redisKeyPreview{DB: db, Name: name, Items: []redisKeyPreviewItem{}}
	if len(raw) < 2 {
		return result, errors.New("Redis 键预览格式无效")
	}
	result.Kind = raw[0]
	if result.Kind != "list" && result.Kind != "hash" && result.Kind != "set" && result.Kind != "zset" {
		return result, errors.New("此键类型暂不支持内容预览")
	}
	var err error
	result.Total, err = strconv.ParseInt(raw[1], 10, 64)
	if err != nil || result.Total < 0 || len(raw) > 42 || (result.Kind == "set" && len(raw) > 22) || (result.Kind != "set" && result.Kind != "list" && len(raw)%2 != 0) || (result.Kind == "list" && len(raw) > 22) {
		return result, errors.New("Redis 键预览格式无效")
	}
	clean := func(value string) string {
		if !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') || strings.ContainsRune(value, '\uFFFD') {
			return "[二进制内容]"
		}
		return value
	}
	for i := 2; i < len(raw); {
		item := redisKeyPreviewItem{}
		switch result.Kind {
		case "list":
			item.Name, item.Value = strconv.Itoa(i-2), clean(raw[i])
			i++
		case "set":
			item.Value = clean(raw[i])
			i++
		default:
			item.Name, item.Value = clean(raw[i]), clean(raw[i+1])
			i += 2
		}
		result.Items = append(result.Items, item)
	}
	if int64(len(result.Items)) > result.Total {
		return result, errors.New("Redis 键预览条数无效")
	}
	result.Sampled = result.Kind == "hash" || result.Kind == "set"
	result.Truncated = result.Total > int64(len(result.Items))
	return result, nil
}

func decodeRedisTextHex(raw []string) (string, string) {
	if len(raw) == 1 && (raw[0] == "missing" || raw[0] == "large" || raw[0] == "wrong-type") {
		return "", raw[0]
	}
	if len(raw) != 2 || raw[0] != "ok" || len(raw[1]) > 8192 {
		return "", "invalid"
	}
	value, err := hex.DecodeString(raw[1])
	if err != nil || !utf8.Valid(value) || strings.ContainsRune(string(value), '\x00') || len(value) > 4096 {
		return "", "binary"
	}
	return string(value), "ok"
}

func redisCLIJSONInput(ctx context.Context, instance core.RedisInstance, db int, input []byte, out any, command ...string) error {
	if db < 0 || db > 15 {
		return errors.New("Redis 逻辑库无效")
	}
	if inspectRedis(ctx, instance).Status != "running" {
		return errors.New("Redis 实例未运行")
	}
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "redis" {
		return errors.New("Redis 版本不在固定目录")
	}
	args := append([]string{"--json", "-x", "-h", "127.0.0.1", "-p", strconv.Itoa(instance.Port), "-n", strconv.Itoa(db)}, command...)
	raw, err := runCommandInput(ctx, input, release.Prefix()+"/bin/redis-cli", args...)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(strings.TrimSpace(raw)), out)
}

func parseRedisScan(raw []json.RawMessage, db int) (redisKeysPage, error) {
	page := redisKeysPage{DB: db, Keys: []string{}}
	if len(raw) != 2 {
		return page, errors.New("Redis 扫描结果格式无效")
	}
	if err := json.Unmarshal(raw[0], &page.Cursor); err != nil {
		return page, errors.New("Redis 扫描游标格式无效")
	}
	if len(page.Cursor) > 20 {
		return page, errors.New("Redis 扫描游标过长")
	}
	if _, err := strconv.ParseUint(page.Cursor, 10, 64); err != nil {
		return page, errors.New("Redis 扫描游标无效")
	}
	var keys []string
	if err := json.Unmarshal(raw[1], &keys); err != nil {
		return page, errors.New("Redis 键列表格式无效")
	}
	if len(keys) > 200 {
		return page, errors.New("Redis 单批键数超出限制，请缩小搜索范围")
	}
	for _, key := range keys {
		if len(key) == 0 || len(key) > 256 || !utf8.ValidString(key) || strings.ContainsAny(key, "\x00\r\n") {
			page.Omitted++
			continue
		}
		page.Keys = append(page.Keys, key)
	}
	return page, nil
}

func (s *Service) redisKeyRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/redis/instances/{id}/keys/hash-field", func(w http.ResponseWriter, r *http.Request) {
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		name, field := r.URL.Query().Get("name"), r.URL.Query().Get("field")
		if err != nil || db < 0 || db > 15 || !validRedisHashNames(name, field) {
			respond(w, 400, map[string]string{"error": "Redis 哈希字段参数无效"})
			return
		}
		var result []string
		if err = redisCLIJSON(r.Context(), instance, db, &result, "EVAL", redisHexReadScript, "1", name, "hash", field); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		value, status := decodeRedisTextHex(result)
		if status == "large" {
			respond(w, 413, map[string]string{"error": "字段内容超过 4 KiB，仅可预览摘要"})
			return
		}
		if status == "missing" {
			respond(w, 404, map[string]string{"error": "Redis 字段已不存在"})
			return
		}
		if status != "ok" {
			respond(w, 409, map[string]string{"error": "字段不是可编辑的文本"})
			return
		}
		respond(w, 200, map[string]any{"db": db, "name": name, "field": field, "value": value, "bytes": len(value)})
	})
	m.HandleFunc("PUT /v1/redis/instances/{id}/keys/hash-field", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DB       int    `json:"db"`
			Name     string `json:"name"`
			Field    string `json:"field"`
			OldValue string `json:"old_value"`
			Value    string `json:"value"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		if in.DB < 0 || in.DB > 15 || !validRedisHashNames(in.Name, in.Field) || len(in.OldValue) > 4096 || len(in.Value) > 4096 || !utf8.ValidString(in.OldValue) || !utf8.ValidString(in.Value) || strings.ContainsRune(in.OldValue, '\x00') || strings.ContainsRune(in.Value, '\x00') {
			respond(w, 400, map[string]string{"error": "Redis 哈希字段内容无效"})
			return
		}
		input, _ := json.Marshal(map[string]string{"field": in.Field, "old": in.OldValue, "value": in.Value})
		var result string
		if err = redisCLIJSONInput(r.Context(), instance, in.DB, input, &result, "EVAL", redisHashFieldUpdateScript, "1", in.Name); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if result != "updated" {
			respond(w, 409, map[string]string{"error": "Redis 字段已变化或类型不符，请刷新后重试"})
			return
		}
		respond(w, 200, map[string]bool{"updated": true})
	})
	m.HandleFunc("DELETE /v1/redis/instances/{id}/keys/hash-field", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DB           int    `json:"db"`
			Name         string `json:"name"`
			Field        string `json:"field"`
			OldValue     string `json:"old_value"`
			ConfirmField string `json:"confirm_field"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		if in.DB < 0 || in.DB > 15 || !validRedisHashNames(in.Name, in.Field) || in.ConfirmField != in.Field || len(in.OldValue) > 4096 || !utf8.ValidString(in.OldValue) || strings.ContainsRune(in.OldValue, '\x00') {
			respond(w, 400, map[string]string{"error": "Redis 哈希字段删除参数无效"})
			return
		}
		input, _ := json.Marshal(map[string]string{"field": in.Field, "old": in.OldValue})
		var result string
		if err = redisCLIJSONInput(r.Context(), instance, in.DB, input, &result, "EVAL", redisHashFieldDeleteScript, "1", in.Name); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if result != "deleted" && result != "deleted-key" {
			respond(w, 409, map[string]string{"error": "Redis 字段已变化或类型不符，请刷新后重试"})
			return
		}
		respond(w, 200, map[string]bool{"deleted": true, "key_exists": result == "deleted"})
	})
	m.HandleFunc("POST /v1/redis/instances/{id}/keys/hash-field", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DB    int    `json:"db"`
			Name  string `json:"name"`
			Field string `json:"field"`
			Value string `json:"value"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		if in.DB < 0 || in.DB > 15 || !validRedisHashNames(in.Name, in.Field) || len(in.Value) > 4096 || !utf8.ValidString(in.Value) || strings.ContainsRune(in.Value, '\x00') {
			respond(w, 400, map[string]string{"error": "Redis 哈希新字段参数无效"})
			return
		}
		input, _ := json.Marshal(map[string]string{"field": in.Field, "value": in.Value})
		var result string
		if err = redisCLIJSONInput(r.Context(), instance, in.DB, input, &result, "EVAL", redisHashFieldAddScript, "1", in.Name); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if result != "added" {
			respond(w, 409, map[string]string{"error": "哈希键不存在或字段已存在，未覆盖原值"})
			return
		}
		respond(w, 201, map[string]bool{"added": true})
	})
	m.HandleFunc("GET /v1/redis/instances/{id}/keys/preview", func(w http.ResponseWriter, r *http.Request) {
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		name := r.URL.Query().Get("name")
		if err != nil || db < 0 || db > 15 || len(name) == 0 || len(name) > 256 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			respond(w, 400, map[string]string{"error": "Redis 键名或逻辑库无效"})
			return
		}
		var raw []string
		if err = redisCLIJSON(r.Context(), instance, db, &raw, "EVAL", redisStructuredPreviewScript, "1", name); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		preview, err := parseRedisStructuredPreview(raw, db, name)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, preview)
	})
	m.HandleFunc("PUT /v1/redis/instances/{id}/keys/ttl", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DB         int    `json:"db"`
			Name       string `json:"name"`
			TTLSeconds int64  `json:"ttl_seconds"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		if in.DB < 0 || in.DB > 15 || len(in.Name) == 0 || len(in.Name) > 256 || !utf8.ValidString(in.Name) || strings.ContainsAny(in.Name, "\x00\r\n") || (in.TTLSeconds != -1 && (in.TTLSeconds < 1 || in.TTLSeconds > 31536000)) {
			respond(w, 400, map[string]string{"error": "Redis 键有效期参数无效"})
			return
		}
		var result string
		if err = redisCLIJSON(r.Context(), instance, in.DB, &result, "EVAL", redisTTLUpdateScript, "1", in.Name, strconv.FormatInt(in.TTLSeconds, 10)); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if result != "updated" {
			respond(w, 404, map[string]string{"error": "Redis 键已不存在"})
			return
		}
		respond(w, 200, map[string]bool{"updated": true})
	})
	m.HandleFunc("PUT /v1/redis/instances/{id}/keys/value", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DB       int    `json:"db"`
			Name     string `json:"name"`
			OldValue string `json:"old_value"`
			Value    string `json:"value"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		if in.DB < 0 || in.DB > 15 || len(in.Name) == 0 || len(in.Name) > 256 || !utf8.ValidString(in.Name) || strings.ContainsAny(in.Name, "\x00\r\n") || len(in.OldValue) > 4096 || len(in.Value) > 4096 || !utf8.ValidString(in.OldValue) || !utf8.ValidString(in.Value) || strings.ContainsRune(in.OldValue, '\x00') || strings.ContainsRune(in.Value, '\x00') {
			respond(w, 400, map[string]string{"error": "Redis 文本键参数无效"})
			return
		}
		input, _ := json.Marshal(map[string]string{"old": in.OldValue, "value": in.Value})
		var result string
		if err = redisCLIJSONInput(r.Context(), instance, in.DB, input, &result, "EVAL", redisTextUpdateScript, "1", in.Name); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if result != "updated" {
			respond(w, 409, map[string]string{"error": "Redis 键已变化或不再是文本字符串，请刷新后重试"})
			return
		}
		respond(w, 200, map[string]bool{"updated": true})
	})
	m.HandleFunc("GET /v1/redis/instances/{id}/keys/value", func(w http.ResponseWriter, r *http.Request) {
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		name := r.URL.Query().Get("name")
		if err != nil || db < 0 || db > 15 || len(name) == 0 || len(name) > 256 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			respond(w, 400, map[string]string{"error": "Redis 键名或逻辑库无效"})
			return
		}
		var raw []string
		if err = redisCLIJSON(r.Context(), instance, db, &raw, "EVAL", redisHexReadScript, "1", name, "string"); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		value, status := decodeRedisTextHex(raw)
		if status == "large" {
			respond(w, 413, map[string]string{"error": "键内容超过 4 KiB，仅显示长度"})
			return
		}
		if status != "ok" {
			respond(w, 409, map[string]string{"error": "键内容不是可显示的文本"})
			return
		}
		respond(w, 200, map[string]any{"db": db, "name": name, "value": value, "bytes": len(value)})
	})
	m.HandleFunc("DELETE /v1/redis/instances/{id}/keys", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DB          int    `json:"db"`
			Name        string `json:"name"`
			ConfirmName string `json:"confirm_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		if in.DB < 0 || in.DB > 15 || len(in.Name) == 0 || len(in.Name) > 256 || !utf8.ValidString(in.Name) || strings.ContainsAny(in.Name, "\x00\r\n") || in.ConfirmName != in.Name {
			respond(w, 400, map[string]string{"error": "Redis 键删除参数或确认名称无效"})
			return
		}
		var deleted int64
		if err = redisCLIJSON(r.Context(), instance, in.DB, &deleted, "UNLINK", in.Name); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if deleted != 1 {
			respond(w, 404, map[string]string{"error": "Redis 键已不存在"})
			return
		}
		respond(w, 200, map[string]bool{"deleted": true})
	})
	m.HandleFunc("GET /v1/redis/instances/{id}/keys", func(w http.ResponseWriter, r *http.Request) {
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		cursor := r.URL.Query().Get("cursor")
		pattern := r.URL.Query().Get("pattern")
		if pattern == "" {
			pattern = "*"
		}
		if db < 0 || db > 15 || len(cursor) == 0 || len(cursor) > 20 || len(pattern) > 128 || !utf8.ValidString(pattern) || strings.ContainsAny(pattern, "\x00\r\n") {
			respond(w, 400, map[string]string{"error": "Redis 扫描参数无效"})
			return
		}
		if _, err = strconv.ParseUint(cursor, 10, 64); err != nil {
			respond(w, 400, map[string]string{"error": "Redis 游标无效"})
			return
		}
		var raw []json.RawMessage
		if err = redisCLIJSON(r.Context(), instance, db, &raw, "SCAN", cursor, "MATCH", pattern, "COUNT", "50"); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		page, err := parseRedisScan(raw, db)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, page)
	})
	m.HandleFunc("GET /v1/redis/instances/{id}/keys/info", func(w http.ResponseWriter, r *http.Request) {
		instance, err := readRedis(r.PathValue("id"))
		if err != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		db, err := strconv.Atoi(r.URL.Query().Get("db"))
		name := r.URL.Query().Get("name")
		if db < 0 || db > 15 || len(name) == 0 || len(name) > 256 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			respond(w, 400, map[string]string{"error": "Redis 键名或逻辑库无效"})
			return
		}
		var kind string
		if err = redisCLIJSON(r.Context(), instance, db, &kind, "TYPE", name); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if kind == "none" {
			respond(w, 404, map[string]string{"error": "Redis 键已不存在"})
			return
		}
		var ttl int64
		if err = redisCLIJSON(r.Context(), instance, db, &ttl, "TTL", name); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		result := redisKeyInfo{DB: db, Name: name, Kind: kind, TTLSeconds: ttl, Size: -1}
		sizeCommands := map[string]string{"string": "STRLEN", "hash": "HLEN", "list": "LLEN", "set": "SCARD", "zset": "ZCARD", "stream": "XLEN"}
		if command := sizeCommands[kind]; command != "" {
			if err = redisCLIJSON(r.Context(), instance, db, &result.Size, command, name); err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
		}
		respond(w, 200, result)
	})
}

func validRedisHashNames(name, field string) bool {
	return len(name) > 0 && len(name) <= 256 && utf8.ValidString(name) && !strings.ContainsAny(name, "\x00\r\n") && len(field) > 0 && len(field) < 512 && utf8.ValidString(field) && !strings.ContainsAny(field, "\x00\r\n")
}
