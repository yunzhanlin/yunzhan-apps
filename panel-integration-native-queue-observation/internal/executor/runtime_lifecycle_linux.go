//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const runtimeBase = "/opt/panel/runtimes"
const lifecycleJobs = "/var/lib/panel-executor/runtime-lifecycle/jobs"

type lifecycleRecord struct {
	CopyID    string           `json:"copy_id,omitempty"`
	JobID     string           `json:"job_id"`
	ReleaseID string           `json:"release_id"`
	Action    string           `json:"action"`
	State     string           `json:"state"`
	Error     string           `json:"error,omitempty"`
	Result    core.ApplyResult `json:"result"`
}
type retiredRuntime struct {
	ReleaseID    string `json:"id"`
	Architecture string `json:"architecture"`
	RetireJobID  string `json:"retire_job_id"`
	RestoreJobID string `json:"restore_job_id,omitempty"`
	RetiredAt    string `json:"retired_at"`
	ManifestSHA  string `json:"manifest_sha256"`
	TreeSHA      string `json:"tree_sha256"`
}
type lifecycleFS struct {
	base, jobs string
	references func(string) ([]core.RuntimeReference, error)
	verify     func(context.Context, runtimecatalog.Release) error
	checkpoint func(string) error // In-process fault injection, never exposed through the API.
}

func realLifecycle() lifecycleFS {
	return lifecycleFS{base: runtimeBase, jobs: lifecycleJobs, references: runtimeReferences, verify: verifyRuntimeVersion}
}
func runtimeFileLock(path string, mode int) (*os.File, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), mode); e != nil {
		f.Close()
		return nil, fmt.Errorf("运行环境正在构建或变更，请稍后重试: %w", e)
	}
	return f, nil
}
func runtimeMutationLock(ctx context.Context) (*os.File, error) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		f, e := runtimeFileLock("/var/lib/panel-executor/runtime-lifecycle.lock", syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return f, nil
		}
		if !errors.Is(e, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			return nil, e
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func runtimeUseLock() (*os.File, error) {
	// Startup units keep /var/lib read-only. flock(LOCK_SH) only needs a read descriptor.
	f, e := os.OpenFile("/var/lib/panel-executor/runtime-lifecycle.lock", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_SH); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

func (s *Service) lockRuntimeUse() (func(), error) {
	if s.Config.SitesDir != "/srv/panel/sites" {
		return func() {}, nil
	}
	f, e := runtimeUseLock()
	if e != nil {
		return nil, e
	}
	return func() { f.Close() }, nil
}
func ownedRuntimePath(path string, dir bool) error {
	if e := ordinary(path, dir); e != nil {
		return e
	}
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("运行环境路径所有者或权限异常: %s", path)
	}
	return nil
}
func privateRuntimeDir(path string) error {
	if e := os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	return ownedRuntimePath(path, true)
}
func (l lifecycleFS) paths(r runtimecatalog.Release) (string, string, string) {
	prefix := filepath.Join(l.base, r.Family, r.Version)
	archive := filepath.Join(l.base, ".retired", r.ID)
	return prefix, archive, filepath.Join(archive, "program")
}
func readRetired(path, release string) (retiredRuntime, error) {
	var m retiredRuntime
	if e := ownedRuntimePath(path, false); e != nil {
		return m, e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return m, e
	}
	if len(b) > 8192 {
		return m, errors.New("恢复元数据超限")
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, e
	}
	if m.ReleaseID != release || m.Architecture != runtime.GOARCH || !core.ValidID(m.RetireJobID) || len(m.TreeSHA) != 64 || len(m.ManifestSHA) != 64 {
		return m, errors.New("恢复副本元数据与版本或架构不匹配")
	}
	if m.RestoreJobID != "" && !core.ValidID(m.RestoreJobID) {
		return m, errors.New("恢复任务标识异常")
	}
	return m, nil
}

// Hash paths, types, modes, owners, link targets and every regular byte without following links.
func runtimeTreeSHA(ctx context.Context, dir, original string) (string, error) {
	h := sha256.New()
	var count int
	var total int64
	e := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		count++
		if count > 100000 {
			return errors.New("程序目录条目超限")
		}
		st, e := os.Lstat(path)
		if e != nil {
			return e
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSymlink == 0 {
			return errors.New("程序文件权限或所有者异常")
		}
		rel, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		fmt.Fprintf(h, "%q %o %d %d %d\n", rel, st.Mode(), s.Uid, s.Gid, st.Size())
		switch {
		case st.Mode()&os.ModeSymlink != 0:
			link, e := os.Readlink(path)
			if e != nil {
				return e
			}
			target := link
			if !filepath.IsAbs(target) {
				target = filepath.Join(original, filepath.Dir(rel), link)
			}
			target = filepath.Clean(target)
			if target != original && !strings.HasPrefix(target, original+"/") {
				return errors.New("程序链接指向安装目录之外")
			}
			fmt.Fprintf(h, "%q\n", link)
		case st.Mode().IsRegular():
			total += st.Size()
			if total > 8<<30 {
				return errors.New("程序目录大小超限")
			}
			f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if e != nil {
				return e
			}
			n, e := io.Copy(h, io.LimitReader(f, st.Size()+1))
			f.Close()
			if e != nil {
				return e
			}
			if n != st.Size() {
				return errors.New("校验时程序文件发生变化")
			}
		case st.IsDir():
		default:
			return errors.New("程序目录包含特殊文件")
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil)), e
}
func manifestDigest(dir string, r runtimecatalog.Release) (string, error) {
	path := filepath.Join(dir, ".panel-runtime.json")
	if e := ownedRuntimePath(path, false); e != nil {
		return "", e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	if len(b) > 65536 {
		return "", errors.New("运行环境清单超限")
	}
	var m RuntimeManifest
	if e = json.Unmarshal(b, &m); e != nil {
		return "", e
	}
	if m.Release != r || m.Architecture != runtime.GOARCH {
		return "", errors.New("安装清单与固定目录不匹配")
	}
	return core.Hash(string(b)), nil
}
func verifyRetiredTree(ctx context.Context, dir, original string, r runtimecatalog.Release, m retiredRuntime) error {
	digest, e := manifestDigest(dir, r)
	if e != nil {
		return e
	}
	if digest != m.ManifestSHA {
		return errors.New("恢复副本清单校验失败")
	}
	digest, e = runtimeTreeSHA(ctx, dir, original)
	if e != nil {
		return e
	}
	if digest != m.TreeSHA {
		return errors.New("恢复副本完整性校验失败")
	}
	return nil
}
func syncRuntimeDirs(paths ...string) error {
	for _, p := range paths {
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func (l lifecycleFS) move(src, dst string) error {
	root, e := os.OpenRoot(l.base)
	if e != nil {
		return e
	}
	defer root.Close()
	a, e := filepath.Rel(l.base, src)
	if e != nil {
		return e
	}
	b, e := filepath.Rel(l.base, dst)
	if e != nil {
		return e
	}
	if e = renameNoReplace(root, a, b); e != nil {
		return e
	}
	return syncRuntimeDirs(filepath.Dir(src), filepath.Dir(dst))
}
func (l lifecycleFS) check(point string) error {
	if l.checkpoint != nil {
		return l.checkpoint(point)
	}
	return nil
}
func archiveProcesses(prefix string) error {
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		exe, e := os.Readlink("/proc/" + entry.Name() + "/exe")
		if e == nil && strings.HasPrefix(exe, prefix+"/") {
			return errors.New("恢复副本仍有运行进程，不能清理")
		}
	}
	return nil
}
func (l lifecycleFS) apply(ctx context.Context, id, release, action string) (result core.ApplyResult, ret error) {
	result.Steps = []core.Step{}
	result.Status = "unchanged"
	r, ok := runtimecatalog.Find(release)
	if !ok || !core.ValidID(id) || (action != "retire" && action != "restore" && action != "purge") {
		return result, errors.New("生命周期任务参数不在允许范围")
	}
	if e := ownedRuntimePath(l.base, true); e != nil {
		return result, e
	}
	if e := ownedRuntimePath(filepath.Join(l.base, r.Family), true); e != nil {
		return result, e
	}
	if e := os.MkdirAll(l.jobs, 0700); e != nil {
		return result, e
	}
	if e := ownedRuntimePath(l.jobs, true); e != nil {
		return result, e
	}
	recordPath := filepath.Join(l.jobs, id+".json")
	existed := false
	copyID := ""
	if b, e := os.ReadFile(recordPath); e == nil {
		if e = ownedRuntimePath(recordPath, false); e != nil {
			return result, e
		}
		var old lifecycleRecord
		if e = json.Unmarshal(b, &old); e != nil {
			return result, e
		}
		if old.JobID != id || old.ReleaseID != release || old.Action != action {
			return result, errors.New("持久任务参数不匹配")
		}
		if old.State == "succeeded" {
			return old.Result, nil
		}
		if old.State == "running" || old.Result.Status == "needs_attention" {
			result.Status = "needs_attention"
		}
		existed = true
		copyID = old.CopyID
	} else if !os.IsNotExist(e) {
		return result, e
	}
	record := lifecycleRecord{JobID: id, ReleaseID: release, Action: action, State: "running", CopyID: copyID}
	if e := writeJSON(recordPath, record); e != nil {
		return result, e
	}
	defer func() {
		if ret != nil && result.Status != "unchanged" {
			result.Status = "needs_attention"
		}
		record.Result = result
		record.State = "succeeded"
		if ret != nil {
			record.State = "failed"
			record.Error = ret.Error()
		}
		if e := writeJSON(recordPath, record); e != nil && ret == nil {
			ret = e
		}
	}()
	add := func(s string) { result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: s}) }
	if e := privateRuntimeDir(filepath.Join(l.base, ".retired")); e != nil {
		return result, e
	}
	prefix, archive, program := l.paths(r)
	metaPath := filepath.Join(archive, "metadata.json")
	if action == "purge" {
		if _, e := os.Lstat(archive); os.IsNotExist(e) && existed && copyID != "" {
			result.Status = "purged"
			add("核对上次清理已完成")
			return result, nil
		}
		if e := ownedRuntimePath(archive, true); e != nil {
			return result, e
		}
		m, e := readRetired(metaPath, release)
		if e != nil {
			return result, e
		}
		if copyID != "" && copyID != m.RetireJobID {
			return result, errors.New("恢复副本已被后续任务替换，不能重试旧操作")
		}
		record.CopyID = m.RetireJobID
		if e = writeJSON(recordPath, record); e != nil {
			return result, e
		}
		if e := archiveProcesses(archive); e != nil {
			return result, e
		}
		result.Status = "needs_attention"
		if e := os.RemoveAll(archive); e != nil {
			return result, e
		}
		if e := syncRuntimeDirs(filepath.Dir(archive)); e != nil {
			return result, e
		}
		if e := l.check("after-purge"); e != nil {
			return result, e
		}
		result.Status = "purged"
		add("已永久清理选定版本的恢复副本")
		return result, nil
	}
	if action == "retire" {
		refs, e := l.references(release)
		if e != nil {
			return result, e
		}
		if len(refs) > 0 {
			return result, fmt.Errorf("版本仍被引用，禁止卸载（%s：%s）", refs[0].Kind, refs[0].Name)
		}
		add("持锁复核站点、数据库、启动意图、回滚记录与实际进程，无引用")
		if e = privateRuntimeDir(archive); e != nil {
			return result, e
		}
		if _, e = os.Lstat(program); e == nil {
			m, e := readRetired(metaPath, release)
			if e != nil {
				return result, e
			}
			if m.RetireJobID != id {
				return result, errors.New("已有恢复副本，请先恢复或清理")
			}
			if _, e = os.Lstat(prefix); !os.IsNotExist(e) {
				return result, errors.New("安装目录已重新出现，拒绝覆盖现有安装")
			}
			if e = verifyRetiredTree(ctx, program, prefix, r, m); e != nil {
				return result, e
			}
			result.Status = "quarantined"
			add("已核对中断前的目录移动与恢复副本")
			return result, nil
		} else if !os.IsNotExist(e) {
			return result, e
		}
		if e = ownedRuntimePath(prefix, true); e != nil {
			return result, e
		}
		manifest, e := manifestDigest(prefix, r)
		if e != nil {
			return result, e
		}
		digest, e := runtimeTreeSHA(ctx, prefix, prefix)
		if e != nil {
			return result, e
		}
		m := retiredRuntime{ReleaseID: release, Architecture: runtime.GOARCH, RetireJobID: id, RetiredAt: core.Now(), ManifestSHA: manifest, TreeSHA: digest}
		if _, e = os.Lstat(metaPath); e == nil {
			if _, e = readRetired(metaPath, release); e != nil {
				return result, e
			}
		}
		if e = writeJSON(metaPath, m); e != nil {
			return result, e
		}
		result.Status = "needs_attention"
		if e = l.move(prefix, program); e != nil {
			return result, e
		}
		if e = l.check("after-retire"); e != nil {
			return result, e
		}
		result.Status = "quarantined"
		add("精确版本程序目录已移入私有恢复副本，网站与数据库数据保持不动")
		return result, nil
	}
	if e := ownedRuntimePath(archive, true); e != nil {
		return result, e
	}
	m, e := readRetired(metaPath, release)
	if e != nil {
		return result, e
	}
	if copyID != "" && copyID != m.RetireJobID {
		return result, errors.New("恢复副本已被后续任务替换，不能重试旧操作")
	}
	record.CopyID = m.RetireJobID
	if e = writeJSON(recordPath, record); e != nil {
		return result, e
	}
	if _, e = os.Lstat(prefix); e == nil {
		if m.RestoreJobID != id {
			return result, errors.New("原安装目录已存在，恢复不会覆盖")
		}
		if _, e = os.Lstat(program); !os.IsNotExist(e) {
			return result, errors.New("原目录和恢复副本同时存在，需要核对")
		}
		if e = verifyRetiredTree(ctx, prefix, prefix, r, m); e != nil {
			return result, e
		}
		if e = l.verify(ctx, r); e != nil {
			return result, e
		}
		result.Status = "installed"
		add("核对中断前的恢复结果与实际程序版本通过")
		return result, nil
	} else if !os.IsNotExist(e) {
		return result, e
	}
	if e = verifyRetiredTree(ctx, program, prefix, r, m); e != nil {
		return result, e
	}
	add("恢复副本版本、架构、清单与全部程序文件校验通过")
	m.RestoreJobID = id
	if e = writeJSON(metaPath, m); e != nil {
		return result, e
	}
	result.Status = "needs_attention"
	if e = l.move(program, prefix); e != nil {
		return result, e
	}
	if e = l.check("after-restore"); e != nil {
		return result, e
	}
	if e = l.verify(ctx, r); e != nil {
		if rollback := l.move(prefix, program); rollback != nil {
			return result, fmt.Errorf("版本验证失败且回退失败，需要核对: %v / %v", e, rollback)
		}
		result.Status = "unchanged"
		return result, fmt.Errorf("程序版本验证失败，已移回恢复副本: %w", e)
	}
	result.Status = "installed"
	add("原子恢复安装目录，实际程序版本验证通过")
	return result, nil
}
func (s *Service) lifecycleRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/runtimes/lifecycle", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			JobID     string `json:"job_id"`
			ReleaseID string `json:"release_id"`
			Action    string `json:"action"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		lock, e := nginxLock()
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error(), "status": "unchanged"})
			return
		}
		defer lock.Close()
		use, e := runtimeMutationLock(r.Context())
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error(), "status": "unchanged"})
			return
		}
		defer use.Close()
		build, e := runtimeFileLock("/var/lib/panel-executor/build.lock", syscall.LOCK_EX|syscall.LOCK_NB)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error(), "status": "unchanged"})
			return
		}
		defer build.Close()
		result, e := realLifecycle().apply(r.Context(), in.JobID, in.ReleaseID, in.Action)
		if e != nil {
			respond(w, 409, map[string]any{"error": e.Error(), "steps": result.Steps, "status": result.Status})
			return
		}
		respond(w, 200, result)
	})
}
func retiredInventory() ([]retiredRuntime, error) {
	out := []retiredRuntime{}
	for _, r := range runtimecatalog.All() {
		_, archive, program := realLifecycle().paths(r)
		if _, e := os.Lstat(program); os.IsNotExist(e) {
			continue
		} else if e != nil {
			return nil, e
		}
		if e := ownedRuntimePath(archive, true); e != nil {
			return nil, e
		}
		if e := ownedRuntimePath(program, true); e != nil {
			return nil, e
		}
		m, e := readRetired(filepath.Join(archive, "metadata.json"), r.ID)
		if e != nil {
			return nil, e
		}
		out = append(out, m)
	}
	return out, nil
}
