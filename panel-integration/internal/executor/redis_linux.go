//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const redisRoot = "/etc/panel/redis"

func redisConfig(id string) string { return filepath.Join(redisRoot, id) }
func redisData(id string) string   { return filepath.Join("/srv/panel/redis", id) }
func redisUnit(id string) string   { return "panel-redis@" + id + ".service" }

func readRedis(id string) (core.RedisInstance, error) {
	var instance core.RedisInstance
	if !core.ValidID(id) {
		return instance, errors.New("Redis 实例标识无效")
	}
	b, e := os.ReadFile(filepath.Join(redisConfig(id), "instance.json"))
	if e == nil {
		e = json.Unmarshal(b, &instance)
	}
	if e == nil && (instance.ID != id || core.ValidateRedisInstance(instance) != nil) {
		e = errors.New("Redis 实例清单不匹配")
	}
	return instance, e
}

func ServeRedis(id string) error {
	lock, e := runtimeUseLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	instance, e := readRedis(id)
	if e != nil {
		return e
	}
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "redis" {
		return errors.New("Redis 版本不在固定目录")
	}
	if _, e = LoadRuntime(release.ID); e != nil {
		return e
	}
	u, e := user.Lookup("panel-redis")
	if e != nil {
		return e
	}
	uid, e := strconv.Atoi(u.Uid)
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(u.Gid)
	if e != nil {
		return e
	}
	if e = os.Chown("/run/panel-redis-"+id, uid, gid); e != nil {
		return e
	}
	if e = syscall.Setgroups([]int{gid}); e != nil {
		return e
	}
	if e = syscall.Setgid(gid); e != nil {
		return e
	}
	if e = syscall.Setuid(uid); e != nil {
		return e
	}
	binary := release.Prefix() + "/bin/redis-server"
	return syscall.Exec(binary, []string{binary, filepath.Join(redisConfig(id), "redis.conf")}, []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"})
}

func redisPing(ctx context.Context, instance core.RedisInstance) error {
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok {
		return errors.New("Redis 版本不存在")
	}
	for i := 0; i < 50; i++ {
		out, e := RunCommand(ctx, release.Prefix()+"/bin/redis-cli", "-h", "127.0.0.1", "-p", strconv.Itoa(instance.Port), "PING")
		if e == nil && strings.TrimSpace(out) == "PONG" {
			info, er := RunCommand(ctx, release.Prefix()+"/bin/redis-cli", "-h", "127.0.0.1", "-p", strconv.Itoa(instance.Port), "INFO", "server")
			if er == nil && strings.Contains(info, "redis_version:"+release.Version) {
				return nil
			}
			if er == nil {
				return errors.New("Redis 实际版本与实例清单不匹配")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("Redis 未在期限内通过 PING 与版本检查")
}

func createRedis(ctx context.Context, instance core.RedisInstance) (ret error) {
	if e := core.ValidateRedisInstance(instance); e != nil {
		return e
	}
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "redis" {
		return errors.New("Redis 版本不在固定目录")
	}
	if _, e := LoadRuntime(release.ID); e != nil {
		return errors.New("请先安装所选 Redis 版本")
	}
	entries, e := os.ReadDir(redisRoot)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		other, er := readRedis(entry.Name())
		if er != nil {
			continue
		}
		count++
		if other.Name == instance.Name {
			return errors.New("Redis 实例名称已被使用")
		}
		if other.Port == instance.Port {
			return errors.New("Redis 实例端口已被使用")
		}
	}
	if count >= 32 {
		return errors.New("Redis 实例数量已达到 32 个上限")
	}
	listener, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", instance.Port))
	if e != nil {
		return errors.New("Redis 实例端口已被其他服务使用")
	}
	listener.Close()
	u, e := user.Lookup("panel-redis")
	if e != nil {
		return errors.New("Redis 服务账户不存在，请重新运行安装程序")
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	cfg, data := redisConfig(instance.ID), redisData(instance.ID)
	if _, e = os.Lstat(cfg); !errors.Is(e, os.ErrNotExist) {
		return errors.New("Redis 实例目录已存在")
	}
	if _, e = os.Lstat(data); !errors.Is(e, os.ErrNotExist) {
		return errors.New("Redis 数据目录已存在")
	}
	created := false
	defer func() {
		if ret != nil && !created {
			_, _ = RunCommand(context.Background(), "/usr/bin/systemctl", "disable", "--now", redisUnit(instance.ID))
			_ = os.RemoveAll(cfg)
			_ = os.RemoveAll(data)
		}
	}()
	if e = os.MkdirAll(cfg, 0750); e != nil {
		return e
	}
	if e = os.Chown(cfg, 0, gid); e != nil {
		return e
	}
	if e = os.MkdirAll(data, 0700); e != nil {
		return e
	}
	if e = os.Chown(data, uid, gid); e != nil {
		return e
	}
	config := fmt.Sprintf("bind 127.0.0.1\nprotected-mode yes\nport %d\ntcp-backlog 128\ntimeout 0\ntcp-keepalive 300\ndaemonize no\nsupervised no\npidfile /run/panel-redis-%s/redis.pid\nloglevel notice\nlogfile \"\"\ndatabases 16\nalways-show-logo no\ndir %s\ndbfilename dump.rdb\nappendonly yes\nappenddirname appendonlydir\nmaxmemory %dmb\nmaxmemory-policy allkeys-lru\nrename-command CONFIG \"\"\n", instance.Port, instance.ID, data, instance.MaxMemoryMB)
	if e = atomicWrite(filepath.Join(cfg, "redis.conf"), []byte(config), 0640); e != nil {
		return e
	}
	if e = os.Chown(filepath.Join(cfg, "redis.conf"), 0, gid); e != nil {
		return e
	}
	b, _ := json.Marshal(instance)
	if e = atomicWrite(filepath.Join(cfg, "instance.json"), b, 0600); e != nil {
		return e
	}
	if _, e = RunCommand(ctx, "/usr/bin/systemctl", "enable", "--now", redisUnit(instance.ID)); e != nil {
		return e
	}
	if e = redisPing(ctx, instance); e != nil {
		return e
	}
	created = true
	return nil
}

func inspectRedis(ctx context.Context, instance core.RedisInstance) core.RedisInstance {
	instance.LogicalDBs = []core.RedisLogicalDB{{Index: 0}}
	instance.Status = "stopped"
	state, _ := RunCommand(ctx, "/usr/bin/systemctl", "is-active", redisUnit(instance.ID))
	if strings.TrimSpace(state) != "active" {
		return instance
	}
	instance.Status = "running"
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok {
		instance.Status = "needs_attention"
		return instance
	}
	info, e := RunCommand(ctx, release.Prefix()+"/bin/redis-cli", "-h", "127.0.0.1", "-p", strconv.Itoa(instance.Port), "INFO")
	if e != nil {
		instance.Status = "needs_attention"
		return instance
	}
	clientsFound := false
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "connected_clients:") {
			clients, parseErr := strconv.Atoi(strings.TrimPrefix(line, "connected_clients:"))
			if parseErr != nil || clients < 0 || clients > 1000000 {
				instance.Status = "needs_attention"
				return instance
			}
			instance.Clients = clients
			clientsFound = true
		}
		if strings.HasPrefix(line, "used_memory:") {
			instance.UsedMemory, _ = strconv.ParseInt(strings.TrimPrefix(line, "used_memory:"), 10, 64)
		}
	}
	if !clientsFound {
		instance.Status = "needs_attention"
		return instance
	}
	instance.LogicalDBs = parseRedisKeyspace(info)
	return instance
}

func parseRedisKeyspace(info string) []core.RedisLogicalDB {
	out := []core.RedisLogicalDB{{Index: 0}}
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		name, fields, ok := strings.Cut(line, ":")
		if !ok || !strings.HasPrefix(name, "db") {
			continue
		}
		index, e := strconv.Atoi(strings.TrimPrefix(name, "db"))
		if e != nil || index < 0 || index > 15 {
			continue
		}
		db := core.RedisLogicalDB{Index: index}
		valid := false
		for _, field := range strings.Split(fields, ",") {
			key, raw, found := strings.Cut(strings.TrimSpace(field), "=")
			if !found {
				continue
			}
			value, er := strconv.ParseInt(raw, 10, 64)
			if er != nil || value < 0 {
				continue
			}
			switch key {
			case "keys":
				db.Keys = value
				valid = true
			case "expires":
				db.Expires = value
			case "avg_ttl":
				db.AverageTTL = value
			}
		}
		if !valid {
			continue
		}
		if index == 0 {
			out[0] = db
		} else {
			out = append(out, db)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func listRedis(ctx context.Context) ([]core.RedisInstance, error) {
	entries, e := os.ReadDir(redisRoot)
	if errors.Is(e, os.ErrNotExist) {
		return []core.RedisInstance{}, nil
	}
	if e != nil {
		return nil, e
	}
	out := []core.RedisInstance{}
	for _, entry := range entries {
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			continue
		}
		instance, er := readRedis(entry.Name())
		if er == nil {
			out = append(out, inspectRedis(ctx, instance))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (s *Service) redisRoutes(m *http.ServeMux) {
	s.redisKeyRoutes(m)
	m.HandleFunc("GET /v1/redis/instances", func(w http.ResponseWriter, r *http.Request) {
		items, e := listRedis(r.Context())
		if e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"instances": items})
	})
	m.HandleFunc("POST /v1/redis/instances", func(w http.ResponseWriter, r *http.Request) {
		var in core.RedisInstance
		if !readJSON(w, r, &in) {
			return
		}
		if e := createRedis(r.Context(), in); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, inspectRedis(r.Context(), in))
	})
	m.HandleFunc("POST /v1/redis/instances/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		instance, e := readRedis(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		action := r.PathValue("action")
		if action != "start" && action != "stop" && action != "restart" {
			respond(w, 400, map[string]string{"error": "Redis 操作无效"})
			return
		}
		if _, e = RunCommand(r.Context(), "/usr/bin/systemctl", action, redisUnit(instance.ID)); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		if action != "stop" {
			if e = redisPing(r.Context(), instance); e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
		}
		respond(w, 200, inspectRedis(r.Context(), instance))
	})
	m.HandleFunc("GET /v1/redis/instances/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		if _, e := readRedis(r.PathValue("id")); e != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		out, e := RunCommand(r.Context(), "/usr/bin/journalctl", "-u", redisUnit(r.PathValue("id")), "-n", "200", "--no-pager", "--output=short-iso")
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]string{"content": out})
	})
	m.HandleFunc("DELETE /v1/redis/instances/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		instance, e := readRedis(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "Redis 实例不存在"})
			return
		}
		if in.ConfirmName != instance.Name {
			respond(w, 409, map[string]string{"error": "请输入实例名称确认删除"})
			return
		}
		if _, e = RunCommand(r.Context(), "/usr/bin/systemctl", "disable", "--now", redisUnit(instance.ID)); e != nil && !strings.Contains(e.Error(), "not loaded") {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		for _, dir := range []string{redisConfig(instance.ID), redisData(instance.ID)} {
			if e = ordinary(dir, true); e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
		}
		if e = os.RemoveAll(redisConfig(instance.ID)); e == nil {
			e = os.RemoveAll(redisData(instance.ID))
		}
		if e != nil {
			respond(w, 500, map[string]string{"error": "删除 Redis 实例目录失败"})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
}
