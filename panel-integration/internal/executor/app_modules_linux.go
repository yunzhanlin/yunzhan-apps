//go:build linux

package executor

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"local/panel/internal/core"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const moduleMaxBytes int64 = 256 << 20

type moduleFile struct {
	SHA  string `json:"sha256"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}
type moduleBaseline struct {
	SiteID      string                `json:"site_id"`
	CreatedAt   string                `json:"created_at"`
	Files       map[string]moduleFile `json:"files"`
	Excludes    []string              `json:"excludes"`
	Signature   string                `json:"signature"`
	AutoRestore bool                  `json:"auto_restore"`
}
type moduleChange struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

func (s *Service) moduleDir(id string) string {
	return filepath.Join(s.Config.SecurityDir, "modules", id)
}
func moduleWrite(path string, value any) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	if e := ordinary(filepath.Dir(path), true); e != nil {
		return e
	}
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(path, append(b, '\n'), 0600)
}
func moduleRead(path string, value any) error {
	if e := ordinary(path, false); e != nil {
		return e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(b) > 4<<20 {
		return errors.New("模块记录过大")
	}
	return json.Unmarshal(b, value)
}
func (s *Service) moduleInstalled(id string) bool {
	var v map[string]any
	return moduleRead(filepath.Join(s.moduleDir(id), "installed.json"), &v) == nil && v["id"] == id
}

func (s *Service) appModuleStatus(ctx context.Context, id string) core.SoftwareAppStatus {
	out := core.SoftwareAppStatus{ID: id, Detail: "未安装"}
	if !s.moduleInstalled(id) {
		return out
	}
	out.Installed = true
	out.Enabled = true
	out.Version = "1.0"
	out.Healthy = true
	out.Detail = "模块已安装，可配置并执行"
	switch id {
	case "pure-ftpd":
		v, e := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pure-ftpd")
		out.Healthy = e == nil && strings.TrimSpace(v) == "active"
	case "pm2-manager":
		out.Healthy = s.appDependencyReady(id)
	case "nfs-manager":
		out.Healthy = exists(s.systemPath("/sbin/mount.nfs")) || exists(s.systemPath("/usr/sbin/mount.nfs"))
	case "apache-waf":
		out.Healthy = exists(filepath.Join(s.moduleDir(id), "rules.conf"))
	}
	if !out.Healthy {
		out.Detail = "模块已安装，但依赖或服务未就绪"
	}
	return out
}
func (s *Service) appModuleLifecycle(ctx context.Context, id, action string, settings map[string]any, add func(string)) error {
	if _, ok := core.FindAppModule(id); !ok {
		return errors.New("未知模块")
	}
	if action == "uninstall" {
		if !s.moduleInstalled(id) {
			return errors.New("模块未安装")
		}
		if id == "pure-ftpd" {
			if _, e := s.Config.Run(ctx, "/usr/bin/systemctl", "disable", "--now", "panel-pure-ftpd"); e != nil {
				return e
			}
		}
		if id == "nfs-manager" {
			rows, _ := filepath.Glob(filepath.Join(s.moduleDir(id), "mounts", "*.json"))
			if len(rows) > 0 {
				return errors.New("仍有 NFS 挂载，请先卸载挂载点")
			}
		}
		if id == "load-balance" {
			rows, _ := filepath.Glob(filepath.Join(s.moduleDir(id), "balancers", "*.json"))
			if len(rows) > 0 {
				return errors.New("仍有负载均衡入口，请先移除")
			}
		}
		if id == "pm2-manager" {
			rows, _ := filepath.Glob(filepath.Join(s.moduleDir(id), "apps", "*.json"))
			if len(rows) > 0 {
				return errors.New("仍有 PM2 项目，请先删除项目")
			}
		}
		if id == "apache-waf" {
			if e := s.apacheModuleWAF(ctx, false); e != nil {
				return e
			}
		}
		if e := os.Remove(filepath.Join(s.moduleDir(id), "installed.json")); e != nil {
			return e
		}
		add("卸载模块，历史报告和备份保留")
		return nil
	}
	if action != "install" && action != "configure" {
		return errors.New("生命周期动作无效")
	}
	if action == "configure" && !s.moduleInstalled(id) {
		return errors.New("请先安装模块")
	}
	if e := os.MkdirAll(s.moduleDir(id), 0700); e != nil {
		return e
	}
	switch id {
	case "website-analytics", "website-statistics-v2":
		if e := s.enableAnalyticsLogs(ctx); e != nil {
			return e
		}
	case "pure-ftpd":
		if e := s.installPureFTP(ctx); e != nil {
			return e
		}
	case "pm2-manager":
		if e := s.installPM2(ctx); e != nil {
			return e
		}
	case "nfs-manager":
		if !exists(s.systemPath("/sbin/mount.nfs")) && !exists(s.systemPath("/usr/sbin/mount.nfs")) {
			if e := s.appDependencies(ctx, id); e != nil {
				return e
			}
		}
	case "apache-waf":
		if e := s.apacheModuleWAF(ctx, true); e != nil {
			return e
		}
	}
	add("固定功能处理器与依赖检查通过")
	return moduleWrite(filepath.Join(s.moduleDir(id), "installed.json"), map[string]any{"id": id, "version": "1.0", "settings": settings, "installed_at": core.Now()})
}
func (s *Service) appModuleRoutes(m *http.ServeMux) {
	s.appDependencyRoutes(m)
	m.HandleFunc("GET /v1/app-modules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		d, ok := core.FindAppModule(id)
		if !ok {
			respond(w, 404, map[string]string{"error": "未知模块"})
			return
		}
		var report any
		_ = moduleRead(filepath.Join(s.moduleDir(id), "last-report.json"), &report)
		respond(w, 200, map[string]any{"definition": d, "status": s.appModuleStatus(r.Context(), id), "report": report})
	})
	m.HandleFunc("POST /v1/app-modules/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		id, action := r.PathValue("id"), r.PathValue("action")
		if !core.ValidAppModuleAction(id, action) {
			respond(w, 400, map[string]string{"error": "未知操作"})
			return
		}
		if !s.moduleInstalled(id) {
			respond(w, 409, map[string]string{"error": "请先安装应用模块"})
			return
		}
		var in core.AppModuleInput
		if !readJSON(w, r, &in) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		out, e := s.runAppModule(r.Context(), id, action, in)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		if e = moduleWrite(filepath.Join(s.moduleDir(id), "last-report.json"), map[string]any{"time": core.Now(), "action": action, "result": out}); e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
}
func (s *Service) runAppModule(ctx context.Context, id, action string, in core.AppModuleInput) (any, error) {
	switch id {
	case "website-tamper-proof", "enterprise-tamper-proof", "file-monitor":
		return s.moduleIntegrity(ctx, id, action, in)
	case "files-sync":
		return s.moduleSync(ctx, in, action == "preview" || in.DryRun)
	case "php-code-security":
		return s.modulePHPScan(ctx, in.SiteID)
	case "disk-analysis":
		return s.moduleDisk(ctx, in.SiteID)
	case "site-diagnosis":
		return s.moduleDiagnosis(ctx, in.SiteID)
	case "website-analytics", "website-statistics-v2":
		return s.moduleAnalytics(ctx, in.SiteID)
	case "network-threat-detection":
		return s.moduleThreat(ctx, action)
	case "task-manager":
		return s.moduleTasks(ctx, action, in)
	case "load-balance":
		return s.moduleLoadBalance(ctx, action, in)
	case "nfs-manager":
		return s.moduleNFS(ctx, action, in)
	case "pure-ftpd":
		return s.moduleFTP(ctx, action, in)
	case "pm2-manager":
		return s.modulePM2(ctx, action, in)
	case "apache-waf":
		return s.apacheWAFReport(ctx)
	case "mobile-pwa":
		return map[string]any{"manifest": "/manifest.webmanifest", "installable": true, "session_model": "HTTPS + HttpOnly + SameSite + CSRF + TOTP"}, nil
	case "user-manager", "platform-ops", "daily-report":
		return map[string]any{"handler": "panel-api", "ready": true}, nil
	}
	return nil, errors.New("模块没有处理器")
}
func scanModuleFiles(ctx context.Context, root *os.Root, excludes []string, snapshot func(string, []byte) error) (map[string]moduleFile, bool, error) {
	files := map[string]moduleFile{}
	var total int64
	partial := false
	for _, p := range excludes {
		if !core.ValidFilePath(p, false) {
			return nil, false, errors.New("排除路径无效")
		}
	}
	e := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if path == "." {
			return nil
		}
		for _, p := range excludes {
			if path == p || strings.HasPrefix(path, p+"/") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("扫描目录包含符号链接: " + path)
		}
		if d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("扫描目录包含特殊文件")
		}
		if len(files) >= 10000 || info.Size() > 8<<20 || total+info.Size() > moduleMaxBytes {
			partial = true
			return nil
		}
		f, e := regularFile(root, path)
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(f, 8<<20+1))
		f.Close()
		if e != nil {
			return e
		}
		if int64(len(b)) != info.Size() {
			return errors.New("扫描时文件发生变化")
		}
		total += int64(len(b))
		sha := sha256.Sum256(b)
		hash := hex.EncodeToString(sha[:])
		files[path] = moduleFile{hash, info.Size(), uint32(info.Mode().Perm())}
		if snapshot != nil {
			return snapshot(hash, b)
		}
		return nil
	})
	return files, partial, e
}
func (s *Service) moduleBaselineKey() ([]byte, error) {
	path := filepath.Join(s.Config.SecurityDir, "modules", "integrity-key")
	if b, e := os.ReadFile(path); e == nil {
		if len(b) != 32 {
			return nil, errors.New("基线密钥格式无效")
		}
		return b, nil
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	return b, atomicWrite(path, b, 0600)
}
func baselineSignature(b moduleBaseline, key []byte) string {
	b.Signature = ""
	raw, _ := json.Marshal(b)
	h := hmac.New(sha256.New, key)
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Service) moduleIntegrity(ctx context.Context, id, action string, in core.AppModuleInput) (any, error) {
	if action == "restore" && !core.ValidFilePath(in.Path, false) {
		return nil, errors.New("请选择基线中的一个文件")
	}
	ids := in.SiteIDs
	if len(ids) == 0 {
		ids = []string{in.SiteID}
	}
	if len(ids) > 100 {
		return nil, errors.New("最多 100 个站点")
	}
	results := []any{}
	for _, site := range ids {
		f, e := s.openFiles(site)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		dir := filepath.Join(s.moduleDir(id), "baselines", site)
		path := filepath.Join(dir, "baseline.json")
		key, e := s.moduleBaselineKey()
		if e != nil {
			return nil, e
		}
		if action == "baseline" {
			if e = os.MkdirAll(filepath.Join(dir, "blobs"), 0700); e != nil {
				return nil, e
			}
			files, partial, e := scanModuleFiles(ctx, f.public, in.Excludes, func(hash string, b []byte) error { return atomicWrite(filepath.Join(dir, "blobs", hash), b, 0600) })
			if e != nil {
				return nil, e
			}
			if partial {
				return nil, errors.New("扫描超过文件或体积上限，未保存不完整基线")
			}
			base := moduleBaseline{SiteID: site, CreatedAt: core.Now(), Files: files, Excludes: in.Excludes, AutoRestore: in.AutoRestore && id == "enterprise-tamper-proof"}
			base.Signature = baselineSignature(base, key)
			if e = moduleWrite(path, base); e != nil {
				return nil, e
			}
			results = append(results, map[string]any{"site_id": site, "files": len(files), "signature": base.Signature, "auto_restore": base.AutoRestore})
			continue
		}
		var base moduleBaseline
		if e = moduleRead(path, &base); e != nil {
			return nil, errors.New("请先建立文件基线")
		}
		if base.SiteID != site || !hmac.Equal([]byte(base.Signature), []byte(baselineSignature(base, key))) {
			return nil, errors.New("基线签名校验失败")
		}
		current, partial, e := scanModuleFiles(ctx, f.public, base.Excludes, nil)
		if e != nil {
			return nil, e
		}
		if partial {
			return nil, errors.New("扫描超过上限，拒绝恢复")
		}
		changes := []moduleChange{}
		for p, old := range base.Files {
			v, ok := current[p]
			if !ok {
				changes = append(changes, moduleChange{Path: p, Kind: "deleted", Before: old.SHA})
			} else if v != old {
				kind := "modified"
				if v.SHA == old.SHA {
					kind = "permission"
				}
				changes = append(changes, moduleChange{Path: p, Kind: kind, Before: old.SHA, After: v.SHA})
			}
		}
		for p, v := range current {
			if _, ok := base.Files[p]; !ok {
				changes = append(changes, moduleChange{Path: p, Kind: "created", After: v.SHA})
			}
		}
		sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
		restored := []string{}
		if action == "restore" || base.AutoRestore {
			for _, change := range changes {
				if action == "restore" && in.Path != change.Path {
					continue
				}
				old, ok := base.Files[change.Path]
				if !ok {
					continue
				}
				if in.ExpectedSHA != "" && change.After != in.ExpectedSHA {
					return nil, errors.New("文件已再次修改")
				}
				data, e := os.ReadFile(filepath.Join(dir, "blobs", old.SHA))
				if e != nil {
					return nil, e
				}
				digest := sha256.Sum256(data)
				if hex.EncodeToString(digest[:]) != old.SHA {
					return nil, errors.New("备份摘要不匹配")
				}
				if v, ok := current[change.Path]; ok {
					previous, err := readModuleFile(f.public, change.Path)
					if err != nil {
						return nil, err
					}
					if core.Hash(string(previous)) != v.SHA {
						return nil, errors.New("恢复时文件再次改变")
					}
					if e = atomicWrite(filepath.Join(dir, "blobs", v.SHA), previous, 0600); e != nil {
						return nil, e
					}
				}
				if e = moduleWriteSiteFile(f, change.Path, data, os.FileMode(old.Mode)); e != nil {
					return nil, e
				}
				restored = append(restored, change.Path)
			}
		}
		if action == "restore" && !core.ValidFilePath(in.Path, false) {
			return nil, errors.New("请选择基线中的一个文件")
		}
		result := map[string]any{"site_id": site, "changes": changes, "restored": restored, "checked_at": core.Now(), "signature_verified": true}
		if e = moduleWrite(filepath.Join(dir, "last-check.json"), result); e != nil {
			return nil, e
		}
		results = append(results, result)
	}
	return map[string]any{"sites": results}, nil
}
func readModuleFile(root *os.Root, path string) ([]byte, error) {
	f, e := regularFile(root, path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if len(b) > 8<<20 {
		return nil, errors.New("文件超过 8MiB")
	}
	return b, e
}
func moduleWriteSiteFile(f *siteFiles, path string, data []byte, mode os.FileMode) error {
	if !core.ValidFilePath(path, false) {
		return errors.New("文件路径无效")
	}
	parent := ""
	if filepath.Dir(path) != "." {
		for _, part := range strings.Split(filepath.Dir(path), "/") {
			parent = filepath.Join(parent, part)
			e := f.public.Mkdir(parent, 0755)
			created := e == nil
			if e != nil && !errors.Is(e, os.ErrExist) {
				return e
			}
			st, err := f.public.Lstat(parent)
			if err != nil {
				return err
			}
			if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				return errors.New("拒绝链接或非目录父路径")
			}
			dir, err := f.public.OpenFile(parent, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			if created {
				err = dir.Chown(f.uid, f.gid)
			}
			dir.Close()
			if err != nil {
				return err
			}
		}
	}
	// Replace by a private temporary inode: never truncate a user-created hard link.
	if st, e := f.public.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return errors.New("拒绝覆盖链接或特殊文件")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	temporary := filepath.Join(filepath.Dir(path), ".cloudstack-"+core.Token())
	out, e := f.public.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer f.public.Remove(temporary)
	if e = out.Chown(f.uid, f.gid); e == nil {
		_, e = out.Write(data)
	}
	if e == nil {
		e = out.Chmod(mode & 0777)
	}
	if e == nil {
		e = out.Sync()
	}
	closeErr := out.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return f.public.Rename(temporary, path)
}
func (s *Service) moduleSync(ctx context.Context, in core.AppModuleInput, preview bool) (any, error) {
	if in.TargetProjectID != "" {
		if in.TargetSiteID != "" {
			return nil, errors.New("目标网站与应用项目不能同时填写")
		}
		return s.moduleSyncLegacy(ctx, in, preview)
	}
	if in.SiteID == in.TargetSiteID {
		return nil, errors.New("来源和目标不能相同")
	}
	source, e := s.openFiles(in.SiteID)
	if e != nil {
		return nil, e
	}
	defer source.Close()
	target, e := s.openFiles(in.TargetSiteID)
	if e != nil {
		return nil, e
	}
	defer target.Close()
	a, partial, e := scanModuleFiles(ctx, source.public, in.Excludes, nil)
	if e != nil || partial {
		return nil, errors.New("来源扫描不完整")
	}
	b, partial, e := scanModuleFiles(ctx, target.public, in.Excludes, nil)
	if e != nil || partial {
		return nil, errors.New("目标扫描不完整")
	}
	checkpointPath := filepath.Join(s.moduleDir("files-sync"), in.SiteID+"-"+in.TargetSiteID+".json")
	old := map[string]moduleFile{}
	_ = moduleRead(checkpointPath, &old)
	copyPaths := []string{}
	conflicts := []string{}
	for path, v := range a {
		cur, exists := b[path]
		if exists && cur.SHA == v.SHA {
			continue
		}
		prev, tracked := old[path]
		if exists && (!tracked || cur.SHA != prev.SHA) {
			conflicts = append(conflicts, path)
			continue
		}
		copyPaths = append(copyPaths, path)
	}
	sort.Strings(copyPaths)
	sort.Strings(conflicts)
	if !preview {
		for _, p := range copyPaths {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			data, err := readModuleFile(source.public, p)
			if err != nil {
				return nil, err
			}
			if core.Hash(string(data)) != a[p].SHA {
				return nil, errors.New("同步时来源文件改变")
			}
			if e = moduleWriteSiteFile(target, p, data, os.FileMode(a[p].Mode)); e != nil {
				return nil, e
			}
			old[p] = a[p]
			if e = moduleWrite(checkpointPath, old); e != nil {
				return nil, e
			}
		}
	}
	return map[string]any{"preview": preview, "copied": copyPaths, "conflicts": conflicts, "deletes": []string{}, "checkpoint": filepath.Base(checkpointPath)}, nil
}
func (s *Service) moduleDisk(ctx context.Context, id string) (any, error) {
	f, e := s.openFiles(id)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var total int64
	count := 0
	partial := false
	rows := []map[string]any{}
	dirs := map[string]int64{}
	e = fs.WalkDir(f.public.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return nil
		}
		if count >= 100000 {
			partial = true
			return fs.SkipAll
		}
		count++
		total += st.Size()
		dirs[filepath.Dir(p)] += st.Size()
		rows = append(rows, map[string]any{"path": p, "bytes": st.Size()})
		return nil
	})
	if e != nil {
		return nil, e
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["bytes"].(int64) > rows[j]["bytes"].(int64) })
	if len(rows) > 100 {
		rows = rows[:100]
	}
	return map[string]any{"site_id": id, "total_bytes": total, "files": count, "directories": dirs, "largest_files": rows, "partial": partial}, nil
}

var phpModuleRules = []struct{ name, pattern, severity string }{
	{"dynamic-evaluation", `(?i)\b(?:eval|assert)\s*\(`, "high"}, {"encoded-code", `(?i)\b(?:base64_decode|gzinflate|str_rot13)\s*\(`, "warning"}, {"command-execution", `(?i)\b(?:shell_exec|system|passthru|exec|popen|proc_open)\s*\(`, "high"}, {"unsafe-deserialization", `(?i)\bunserialize\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)`, "high"}, {"untrusted-file-write", `(?i)\b(?:file_put_contents|fwrite|move_uploaded_file)\s*\(`, "warning"},
}

func (s *Service) modulePHPScan(ctx context.Context, id string) (any, error) {
	f, e := s.openFiles(id)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	files, partial, e := scanModuleFiles(ctx, f.public, nil, nil)
	if e != nil {
		return nil, e
	}
	findings := []map[string]any{}
	scanned := 0
scan:
	for p := range files {
		if strings.ToLower(filepath.Ext(p)) != ".php" {
			continue
		}
		scanned++
		b, err := readModuleFile(f.public, p)
		if err != nil {
			return nil, err
		}
		for _, rule := range phpModuleRules {
			re := regexp.MustCompile(rule.pattern)
			for _, index := range re.FindAllIndex(b, 20) {
				line := strings.Count(string(b[:index[0]]), "\n") + 1
				findings = append(findings, map[string]any{"path": p, "line": line, "rule": rule.name, "severity": rule.severity, "evidence": string(b[index[0]:index[1]])})
				if len(findings) >= 500 {
					partial = true
					break scan
				}
			}
		}
	}
	return map[string]any{"site_id": id, "scanned_php": scanned, "findings": findings, "partial": partial, "interpretation": "静态风险命中需要结合代码上下文判断"}, nil
}
func (s *Service) moduleDiagnosis(ctx context.Context, id string) (any, error) {
	f, e := s.openFiles(id)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := f.root.ReadFile(".panel-site.json")
	if e != nil {
		return nil, e
	}
	var marker map[string]string
	_ = json.Unmarshal(b, &marker)
	domain := marker["domain"]
	if !core.ValidDomain(domain) {
		return nil, errors.New("站点域名无效")
	}
	checks := map[string]any{}
	dnsctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	addresses, dnserr := net.DefaultResolver.LookupHost(dnsctx, domain)
	cancel()
	checks["dns"] = map[string]any{"addresses": addresses, "ok": dnserr == nil}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19101/", nil)
	req.Host = domain
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err == nil {
		checks["http"] = map[string]any{"status": resp.StatusCode, "ok": resp.StatusCode < 500}
		resp.Body.Close()
	} else {
		checks["http"] = map[string]any{"ok": false, "error": err.Error()}
	}
	output, configErr := s.Config.Run(ctx, s.Config.NginxBin, "-t")
	checks["nginx"] = map[string]any{"ok": configErr == nil, "output": output}
	scan, e := inspectSiteFiles(f)
	if e != nil {
		return nil, e
	}
	checks["files"] = scan
	tlsctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, tlsErr := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12}}).DialContext(tlsctx, "tcp", net.JoinHostPort(domain, "443"))
	tlsReport := map[string]any{"valid": tlsErr == nil}
	if tlsErr != nil {
		tlsReport["error"] = tlsErr.Error()
	}
	if secure, ok := conn.(*tls.Conn); ok {
		state := secure.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			tlsReport["not_after"] = state.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
			tlsReport["issuer"] = state.PeerCertificates[0].Issuer.String()
		}
	}
	if conn != nil {
		conn.Close()
	}
	checks["tls_certificate"] = tlsReport
	return map[string]any{"site_id": id, "domain": domain, "checked_at": core.Now(), "checks": checks}, nil
}

func (s *Service) moduleAnalytics(ctx context.Context, id string) (any, error) {
	if !core.ValidID(id) {
		return nil, errors.New("请选择网站")
	}
	site, e := s.openFiles(id)
	if e != nil {
		return nil, e
	}
	site.Close()
	path := s.systemPath("/var/log/nginx/panel-" + id + ".access.log")
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(e, os.ErrNotExist) {
		return map[string]any{"requests": 0, "site_id": id, "paths": map[string]int{}, "status_codes": map[string]int{}}, nil
	}
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return nil, errors.New("访问日志无效")
	}
	offset := max(int64(0), st.Size()-16<<20)
	_, _ = f.Seek(offset, io.SeekStart)
	scanner := bufio.NewScanner(io.LimitReader(f, 16<<20))
	scanner.Buffer(make([]byte, 4096), 65536)
	if offset > 0 {
		scanner.Scan()
	}
	requests, errorsCount, bots := 0, 0, 0
	var bytes int64
	ips := map[string]bool{}
	paths := map[string]int{}
	codes := map[string]int{}
	hours := map[string]int{}
	referers := map[string]int{}
	var seconds float64
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var row struct {
			Time, Remote, Path, Agent, Referer string
			Status                             int
			Bytes                              int64
			Seconds                            float64
		}
		if json.Unmarshal(scanner.Bytes(), &row) != nil {
			continue
		}
		requests++
		bytes += row.Bytes
		seconds += row.Seconds
		codes[strconv.Itoa(row.Status)]++
		paths[row.Path]++
		if row.Remote != "" {
			ips[row.Remote] = true
		}
		if row.Status >= 400 {
			errorsCount++
		}
		if len(row.Time) >= 13 {
			hours[row.Time[:13]]++
		}
		if regexp.MustCompile(`(?i)bot|crawler|spider|bingpreview`).MatchString(row.Agent) {
			bots++
		}
		if row.Referer != "" {
			referers[row.Referer]++
		}
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	return map[string]any{"site_id": id, "requests": requests, "bytes": bytes, "unique_ips": len(ips), "errors": errorsCount, "bots": bots, "paths": paths, "status_codes": codes, "hours": hours, "referers": referers, "total_seconds": seconds, "partial": offset > 0, "updated_at": core.Now()}, nil
}
func (s *Service) moduleThreat(ctx context.Context, action string) (any, error) {
	listeners, e := s.Config.Run(ctx, "/usr/bin/ss", "-H", "-lntup")
	if e != nil {
		return nil, e
	}
	connections, e := s.Config.Run(ctx, "/usr/bin/ss", "-H", "-nt")
	if e != nil {
		return nil, e
	}
	current := strings.Split(strings.TrimSpace(listeners), "\n")
	path := filepath.Join(s.moduleDir("network-threat-detection"), "network-baseline.json")
	old := []string{}
	_ = moduleRead(path, &old)
	alerts := []map[string]any{}
	seen := map[string]bool{}
	for _, line := range old {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			seen[fields[0]+":"+fields[4]] = true
		}
	}
	for _, line := range current {
		fields := strings.Fields(line)
		if len(fields) >= 5 && !seen[fields[0]+":"+fields[4]] {
			alerts = append(alerts, map[string]any{"kind": "new-listener", "endpoint": fields[4], "public": !strings.Contains(fields[4], "127.0.0.1") && !strings.Contains(fields[4], "[::1]")})
		}
	}
	if action == "baseline" {
		if e = moduleWrite(path, current); e != nil {
			return nil, e
		}
		alerts = []map[string]any{}
	}
	fail2ban, _ := s.Config.Run(ctx, "/usr/bin/fail2ban-client", "status", "sshd")
	return map[string]any{"listeners": current, "connections": strings.Split(strings.TrimSpace(connections), "\n"), "alerts": alerts, "fail2ban": fail2ban, "checked_at": core.Now()}, nil
}
func (s *Service) moduleTasks(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	first, total, e := readProcessSample("/proc")
	if e != nil {
		return nil, e
	}
	if action == "terminate" {
		p, ok := first[in.PID]
		if !ok || in.PID < 2 || in.StartTime == 0 || p.StartTime != in.StartTime {
			return nil, errors.New("进程身份已经改变")
		}
		uidInfo, e := os.Stat(filepath.Join("/proc", strconv.Itoa(in.PID)))
		if e != nil {
			return nil, e
		}
		uid := uidInfo.Sys().(*syscall.Stat_t).Uid
		if uid == 0 {
			return nil, errors.New("不允许终止 root 进程")
		}
		cmdline, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(in.PID), "cgroup"))
		if !strings.Contains(string(cmdline), "panel-node@") && !strings.Contains(string(cmdline), "panel-pm2@") && !strings.Contains(string(cmdline), "panel-php@") {
			return nil, errors.New("仅允许终止云栈受管进程")
		}
		fd, err := unix.PidfdOpen(in.PID, 0)
		if err != nil {
			return nil, err
		}
		defer unix.Close(fd)
		fresh, _, err := readProcessSample("/proc")
		if err != nil || fresh[in.PID].StartTime != in.StartTime {
			return nil, errors.New("进程身份已经改变")
		}
		if e = unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); e != nil {
			return nil, e
		}
		return map[string]any{"signal": "SIGTERM", "pid": in.PID}, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(250 * time.Millisecond):
	}
	second, totalSecond, e := readProcessSample("/proc")
	if e != nil {
		return nil, e
	}
	processes := computeProcesses(first, second, total, totalSecond, 250*time.Millisecond)
	rows := []map[string]any{}
	for _, p := range processes {
		rows = append(rows, map[string]any{"pid": p.PID, "name": p.Name, "cpu_percent": p.CPUPercent, "memory": p.Memory, "state": p.State, "start_time": second[p.PID].StartTime})
	}
	connections, _ := s.Config.Run(ctx, "/usr/bin/ss", "-H", "-ntp")
	return map[string]any{"processes": rows, "connections": connections}, nil
}

// The worker resumes from private persisted policies after executor restarts.
func (s *Service) StartAppModuleWorker() {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			s.mu.Lock()
			for _, id := range []string{"file-monitor", "website-tamper-proof", "enterprise-tamper-proof"} {
				if !s.moduleInstalled(id) {
					continue
				}
				paths, _ := filepath.Glob(filepath.Join(s.moduleDir(id), "baselines", "*", "baseline.json"))
				for _, p := range paths {
					var b moduleBaseline
					if moduleRead(p, &b) == nil {
						result, err := s.moduleIntegrity(ctx, id, "check", core.AppModuleInput{SiteID: b.SiteID})
						report := map[string]any{"time": core.Now(), "action": "scheduled-check", "result": result}
						if err != nil {
							report["error"] = err.Error()
						}
						_ = moduleWrite(filepath.Join(s.moduleDir(id), "last-report.json"), report)
					}
				}
			}
			s.mu.Unlock()
			cancel()
		}
	}()
}
