//go:build linux

package executor

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func (s *Service) archiveApacheCCLog(ctx context.Context, in core.ApacheCCArchiveRequest) (apacheCCArchiveEntry, error) {
	var empty apacheCCArchiveEntry
	logs := s.apacheNumericLogService()
	lock, err := logs.lockWAFConfiguration()
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	if err := logs.verifyApacheNumericLock(lock); err != nil {
		return empty, err
	}
	if _, _, err := logs.readApacheCCArchiveClosed(in.RequestID); err == nil {
		return empty, errors.New("CC 原请求已明确关闭，拒绝迟到提交")
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	// An already completed original request is observed even after a later
	// policy save. Its parameters and every sealed byte must still match; the
	// current policy revision cannot authorize replaying its name exchange.
	prior, priorErr := logs.readApacheCCArchive(ctx, in.RequestID)
	if priorErr == nil {
		if prior.Intent == nil || prior.Intent.Request != in || prior.State != "completed" {
			return prior, errors.New("CC 原请求未确认完成或参数不同；仅核对，不重复执行")
		}
		return prior, nil
	}
	if !errors.Is(priorErr, os.ErrNotExist) {
		return empty, priorErr
	}
	if _, err := os.Lstat(logs.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return empty, errors.New("Apache 有未完成的配置事务，CC 原日志未动")
	}
	installed, err := s.moduleInstalledRecord("apache-waf")
	if err != nil || installed["version"] != core.ApacheWAFCCLogArchiveVersion {
		return empty, errors.New("CC 归档需要完整的 Apache2.5.1 原签名应用安装")
	}
	settings, ok := installed["settings"].(map[string]any)
	if !ok {
		return empty, errors.New("Apache 原配置缺失，未采用默认值")
	}
	cfg, err := core.DecodeApacheWAFVersionConfig(settings, core.ApacheWAFCCLogArchiveVersion)
	if err != nil {
		return empty, err
	}
	if cfg.Policy.Revision != in.ExpectedRevision {
		return empty, errors.New("Apache 配置修订已变化，请刷新后核对")
	}
	if cfg.ApacheCC == nil || !core.ValidID(cfg.ApacheCC.EngineJobID) {
		return empty, errors.New("CC 归档需要明确选择已核验的本机 CC 引擎")
	}
	if err := verifyApacheCCBuildContext(ctx, cfg.ApacheCC.EngineJobID); err != nil {
		return empty, err
	}
	if err := s.verifyApacheWAFHealth(ctx, core.ApacheWAFCCLogArchiveVersion, settings); err != nil {
		return empty, err
	}
	return logs.archiveApacheCCLogRequestAt(ctx, in, nil)
}

func (s *Service) apacheCCArchiveChunk(ctx context.Context, id string, part int) (map[string]any, error) {
	if !core.ValidID(id) || part < 0 || part >= core.ApacheCCArchiveParts {
		return nil, errors.New("CC 分段身份无效")
	}
	entry, err := s.readApacheCCArchive(ctx, id)
	if err != nil {
		return nil, err
	}
	var original *apacheCCArchiveFile
	var tail any
	if entry.State == "completed" && entry.Completed != nil && entry.Intent != nil {
		original = &entry.Completed.Archive
		tail = entry.Intent.TailIncomplete
	}
	if entry.State == "retained-unknown" && entry.Retained != nil {
		original = entry.Retained.Archive
	}
	if original == nil {
		return nil, errors.New("CC 原数据文件尚未封存或不存在，未虚构原日志")
	}
	const chunkBytes = core.ApacheCCArchiveChunkBytes
	offset := int64(part) * chunkBytes
	if offset >= original.Bytes {
		return nil, errors.New("CC 下载分段超出原封存大小")
	}
	dir, _, err := s.apacheCCArchiveEntryDirectory(id)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "data.log")
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	identity, err := apacheCCArchiveStat(before, os.Geteuid(), os.Getegid())
	want := *original
	want.SHA256 = ""
	if err != nil || identity != want {
		return nil, errors.New("CC 原封存文件身份变化，未导出分段")
	}
	data := make([]byte, min(int64(chunkBytes), identity.Bytes-offset))
	if _, err := f.ReadAt(data, offset); err != nil {
		return nil, err
	}
	after, statErr := f.Stat()
	named, nameErr := os.Lstat(path)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if statErr != nil || nameErr != nil || !apacheBodyEventsSameFile(before, after) || !apacheBodyEventsSameFile(after, named) {
		return nil, errors.New("CC 原封存文件在下载时变化，未返回分段")
	}
	return map[string]any{"archive_id": id, "part": part, "offset": offset, "bytes": len(data), "total_bytes": identity.Bytes, "sha256": original.SHA256, "data_base64": base64.StdEncoding.EncodeToString(data), "raw_original_private_log": true, "tail_incomplete": tail, "original_outcome_unknown": entry.State == "retained-unknown"}, nil
}

func (s *Service) apacheCCArchiveRoutes(m *http.ServeMux) {
	register := func(pattern string, write bool, run func(context.Context, *Service, *http.Request) (any, error)) {
		m.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || os.Geteuid() != 0 {
				respond(w, 503, map[string]string{"error": "CC 归档仅允许固定真实受管环境"})
				return
			}
			if len(r.URL.Query()) != 0 {
				respond(w, 400, map[string]string{"error": "CC 归档不接受路径或查询参数"})
				return
			}
			if id := r.PathValue("id"); id != "" && !core.ValidID(id) {
				respond(w, 400, map[string]string{"error": "CC 归档标识无效"})
				return
			}
			installed, err := s.moduleInstalledRecord("apache-waf")
			version, _ := installed["version"].(string)
			if err != nil || !core.ApacheWAFCCVersion(version) || write && version != core.ApacheWAFCCLogArchiveVersion {
				respond(w, 409, map[string]string{"error": "CC 归档需要对应原签名 Apache 应用，日志未创建或接管"})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			logs := s.apacheNumericLogService()
			if write {
				s.mu.Lock()
				defer s.mu.Unlock()
			}
			if !write {
				lock, err := logs.lockWAFObservation()
				if err != nil {
					respond(w, 409, map[string]string{"error": err.Error()})
					return
				}
				defer lock.Close()
			}
			out, err := run(ctx, logs, r)
			if err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
			respond(w, 200, out)
		})
	}
	register("GET /v1/software/apache-waf/cc-log/archives", false, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		entries, err := logs.apacheCCArchiveInventory(ctx)
		if err != nil {
			return nil, err
		}
		installed, err := s.moduleInstalledRecord("apache-waf")
		if err != nil {
			return nil, err
		}
		settings, ok := installed["settings"].(map[string]any)
		if !ok {
			return nil, errors.New("Apache 原配置缺失，未猜测日志状态")
		}
		version, _ := installed["version"].(string)
		cfg, err := core.DecodeApacheWAFVersionConfig(settings, version)
		if err != nil {
			return nil, err
		}
		current, err := logs.readApacheCCArchiveCurrent(ctx, apacheCCPolicyMayLog(cfg))
		if err != nil {
			return nil, err
		}
		history, err := logs.apacheCCArchiveHistoryInventory(ctx)
		if err != nil {
			return nil, err
		}
		healthy := true
		for _, entry := range append(append([]apacheCCArchiveEntry{}, entries...), history...) {
			healthy = healthy && (entry.State == "completed" || entry.State == "retained-unknown")
		}
		return map[string]any{"archives": entries, "history": history, "max_history": apacheCCArchiveHistoryCount, "current": current, "inventory_complete": true, "maintenance_healthy": healthy, "max_archives": apacheCCArchiveCount, "max_archive_bytes": apacheCCLogMaxBytes, "read_only": true, "atomic_name_exchange": true, "reloads_apache": false}, nil
	})
	register("GET /v1/software/apache-waf/cc-log/archives/{id}", false, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		return logs.readApacheCCArchive(ctx, r.PathValue("id"))
	})
	register("GET /v1/software/apache-waf/cc-log/archives/{id}/recovery", false, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		id := r.PathValue("id")
		entry, err := logs.readApacheCCArchive(ctx, id)
		if err != nil {
			return nil, err
		}
		if entry.State == "completed" {
			return nil, errors.New("CC 原归档已完成，没有可保留的未知结果")
		}
		var snapshot apacheCCArchiveSnapshot
		if entry.State == "retained-unknown" && entry.Retained != nil {
			snapshot = entry.Retained.Snapshot
		} else {
			snapshot, err = logs.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil {
				return nil, err
			}
		}
		return map[string]any{"record": entry, "snapshot": snapshot, "snapshot_sha256": apacheCCArchiveSnapshotSHA(snapshot), "read_only": true, "automatic_replay_allowed": false}, nil
	})
	register("POST /v1/software/apache-waf/cc-log/archives/{id}/retain", true, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil {
			return nil, err
		}
		in, err := core.DecodeApacheCCArchiveRetention(raw)
		if err != nil {
			return nil, err
		}
		lock, err := logs.lockWAFConfiguration()
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		return logs.retainApacheCCArchiveUnderLock(ctx, lock, r.PathValue("id"), in.SHA, nil)
	})
	register("GET /v1/software/apache-waf/cc-log/archives/{id}/history", false, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		id := r.PathValue("id")
		entry, err := logs.readApacheCCArchive(ctx, id)
		if err != nil {
			return nil, err
		}
		if entry.State == "unknown" {
			return nil, errors.New("CC 原结果尚未保留，未将未知库存转存")
		}
		snapshot, err := logs.apacheCCRecoverySnapshot(ctx, id, "", nil)
		if err != nil {
			return nil, err
		}
		_, history, err := logs.apacheCCArchiveEntryDirectory(id)
		if err != nil {
			return nil, err
		}
		return map[string]any{"record": entry, "snapshot": snapshot, "snapshot_sha256": apacheCCArchiveSnapshotSHA(snapshot), "history": history, "read_only": true, "no_delete": true}, nil
	})
	register("POST /v1/software/apache-waf/cc-log/archives/{id}/history", true, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil {
			return nil, err
		}
		in, err := core.DecodeApacheCCArchiveHistory(raw)
		if err != nil {
			return nil, err
		}
		lock, err := logs.lockWAFConfiguration()
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		entry, err := logs.preserveApacheCCArchiveHistoryUnderLock(ctx, lock, r.PathValue("id"), in.SHA, nil)
		if err != nil {
			return nil, err
		}
		return map[string]any{"record": entry, "snapshot_sha256": in.SHA, "history": true, "current_log_untouched": true, "no_delete": true}, nil
	})
	register("GET /v1/software/apache-waf/cc-log/requests/{id}", false, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		id := r.PathValue("id")
		closed, digest, err := logs.readApacheCCArchiveClosed(id)
		if err == nil {
			return map[string]any{"kind": "closed", "record": closed, "sha256": digest, "read_only": true}, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		entry, err := logs.readApacheCCArchive(ctx, id)
		if err == nil {
			return map[string]any{"kind": "archive", "record": entry, "read_only": true}, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return map[string]any{"kind": "not-recorded", "request_id": id, "read_only": true, "automatic_retry_allowed": false}, nil
	})
	register("POST /v1/software/apache-waf/cc-log/requests/{id}/close", true, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil {
			return nil, err
		}
		in, err := core.DecodeApacheCCArchiveRequest(raw)
		if err != nil {
			return nil, err
		}
		if in.RequestID != r.PathValue("id") {
			return nil, errors.New("CC 原请求路径与对象不一致")
		}
		lock, err := logs.lockWAFConfiguration()
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		record, err := logs.closeUnstartedApacheCCArchiveUnderLock(ctx, lock, in)
		if err != nil {
			return nil, err
		}
		observed, digest, err := logs.readApacheCCArchiveClosed(in.RequestID)
		if err != nil || observed != record {
			return nil, errors.New("CC 原关闭回执未核实，请按原标识观察")
		}
		return map[string]any{"kind": "closed", "record": record, "sha256": digest, "late_dispatch_refused": true, "current_log_untouched": true}, nil
	})
	register("GET /v1/software/apache-waf/cc-log/archives/{id}/chunks/{part}", false, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		part, err := core.ApacheCCArchivePart(r.PathValue("part"))
		if err != nil {
			return nil, err
		}
		return logs.apacheCCArchiveChunk(ctx, r.PathValue("id"), part)
	})
	register("POST /v1/software/apache-waf/cc-log/archive", true, func(ctx context.Context, logs *Service, r *http.Request) (any, error) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil {
			return nil, err
		}
		in, err := core.DecodeApacheCCArchiveRequest(raw)
		if err != nil {
			return nil, err
		}
		return s.archiveApacheCCLog(ctx, in)
	})
}
