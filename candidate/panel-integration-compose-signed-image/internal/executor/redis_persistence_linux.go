//go:build linux

package executor

import (
	"errors"
	"local/panel/internal/core"
	"net/http"
	"strconv"
	"strings"
)

func parseRedisPersistence(instance string, info string) (core.RedisPersistence, error) {
	out := core.RedisPersistence{InstanceID: instance}
	fields := make(map[string]string)
	for _, line := range strings.Split(info, "\n") {
		name, value, found := strings.Cut(strings.TrimRight(line, "\r"), ":")
		if found {
			fields[name] = value
		}
	}
	numbers := map[string]*int64{
		"rdb_last_save_time":          &out.LastSnapshot,
		"rdb_changes_since_last_save": &out.ChangesSinceLastSave,
	}
	for name, target := range numbers {
		value, err := strconv.ParseInt(fields[name], 10, 64)
		if err != nil || value < 0 {
			return out, errors.New("Redis 持久化数值无效")
		}
		*target = value
	}
	flags := map[string]*bool{
		"rdb_bgsave_in_progress":  &out.SnapshotRunning,
		"aof_enabled":             &out.AOFEnabled,
		"aof_rewrite_in_progress": &out.AOFRewriteRunning,
		"aof_rewrite_scheduled":   &out.AOFRewriteScheduled,
	}
	for name, target := range flags {
		switch fields[name] {
		case "0":
		case "1":
			*target = true
		default:
			return out, errors.New("Redis 持久化标志无效")
		}
	}
	duration, err := strconv.ParseInt(fields["rdb_last_bgsave_time_sec"], 10, 64)
	if err != nil || duration < -1 {
		return out, errors.New("Redis 快照耗时无效")
	}
	out.SnapshotDuration = duration
	if duration < 0 {
		out.LastSnapshot = 0
	}
	out.SnapshotStatus = fields["rdb_last_bgsave_status"]
	out.AOFWriteStatus = fields["aof_last_write_status"]
	if (out.SnapshotStatus != "ok" && out.SnapshotStatus != "err") ||
		(out.AOFWriteStatus != "ok" && out.AOFWriteStatus != "err") {
		return out, errors.New("Redis 持久化状态无效")
	}
	return out, nil
}

func redisPersistenceRoutes(m *http.ServeMux) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		m.HandleFunc(method+" /v1/redis/instances/{id}/persistence", func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			instance, err := readRedis(id)
			if err != nil || instance.AuthMode != core.RedisACLAuthMode {
				respond(w, http.StatusConflict, map[string]string{"error": "持久化操作需要当前 ACL 认证的受管 Redis 实例"})
				return
			}
			if method == http.MethodPost {
				var input struct {
					ConfirmID string `json:"confirm_id"`
				}
				r.Body = http.MaxBytesReader(w, r.Body, 512)
				if !readJSON(w, r, &input) {
					return
				}
				if input.ConfirmID != id {
					respond(w, http.StatusBadRequest, map[string]string{"error": "Redis 快照确认与实例不一致"})
					return
				}
				// Redis serializes background saves and rewrites. Do not queue a
				// second save behind work already running on this instance.
				result, err := redisSecureValue(r.Context(), instance, 0, "BGSAVE")
				if err != nil || result != "Background saving started" {
					respond(w, http.StatusConflict, map[string]string{"error": "Redis 快照未确认启动，请先刷新持久化状态"})
					return
				}
				respond(w, http.StatusAccepted, map[string]string{"instance_id": id})
				return
			}
			info, err := redisInfoText(r.Context(), instance, "INFO", "persistence")
			if err == nil {
				out, parseErr := parseRedisPersistence(id, info)
				if parseErr == nil {
					respond(w, http.StatusOK, out)
					return
				}
			}
			respond(w, http.StatusConflict, map[string]string{"error": "无法读取当前 Redis 持久化状态"})
		})
	}
}
