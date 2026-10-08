//go:build linux

package executor

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"local/panel/internal/appcatalog"
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
	if len(b)+1 > 4<<20 {
		return errors.New("模块记录超过 4 MiB，未覆盖旧记录")
	}
	return atomicWrite(path, append(b, '\n'), 0600)
}
func moduleRead(path string, value any) error {
	if e := ordinary(path, false); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (4<<20)+1))
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
	var manifest map[string]any
	if moduleRead(filepath.Join(s.moduleDir(id), "installed.json"), &manifest) != nil {
		out.Healthy = false
		out.Detail = "安装记录读取失败"
		return out
	}
	out.Version, _ = manifest["version"].(string)
	if out.Version == "" {
		out.Version = "1.0"
	} // pre-versioned modules
	out.Settings, _ = manifest["settings"].(map[string]any)
	out.Healthy = true
	out.Detail = "模块已安装，可配置并执行"
	if id == "load-balance" {
		if _, err := os.Lstat(s.loadBalancePendingPath()); !errors.Is(err, os.ErrNotExist) {
			out.Healthy = false
			out.Detail = "存在待恢复入口事务；未宣称配置已生效"
			return out
		}
		entries, err := s.loadBalanceEntries()
		if err != nil {
			out.Healthy = false
			out.Detail = err.Error()
			return out
		}
		health, err := s.loadBalanceHealthReports(entries, time.Now().UTC())
		if err != nil {
			out.Healthy = false
			out.Detail = err.Error()
			return out
		}
		normal, failed, unknown := 0, 0, 0
		for _, row := range health {
			switch row["state"] {
			case "healthy":
				normal++
			case "unhealthy":
				failed++
			default:
				unknown++
			}
		}
		out.Detail = fmt.Sprintf("%d 个回环 HTTP 入口；持续 HTTP 节点检查：%d 正常 / %d 失败 / %d 未判定或过期；只观测，不自动修改流量", len(entries), normal, failed, unknown)
	}
	switch id {
	case "pure-ftpd":
		v, e := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pure-ftpd")
		out.Healthy = e == nil && strings.TrimSpace(v) == "active"
		if config, configErr := s.ftpConfig(); configErr != nil {
			out.Healthy = false
		} else if data, _, certificateErr := s.ftpCertificate(config); certificateErr != nil {
			out.Healthy = false
		} else if current, readErr := ftpPrivateRead(filepath.Join(s.moduleDir(id), "server.pem"), 49152); readErr != nil || core.Hash(string(current)) != core.Hash(string(data)) {
			out.Healthy = false
		}
		if _, runtimeErr := s.ftpBinary("pure-ftpd"); runtimeErr != nil {
			out.Healthy = false
		}
		if s.ftpRecoveryPending() {
			out.Healthy = false
			out.Detail = "FTP 有待恢复事务，请先恢复并刷新"
		}
		out.Enabled = out.Healthy
	case "pm2-manager":
		out.Healthy = s.appDependencyReady(id)
	case "nfs-manager":
		out.Healthy = s.appDependencyReady(id) && !s.nfsPending()
	case "php-code-security":
		rows, err := s.phpQuarantineRecords()
		if err != nil {
			out.Healthy = false
			out.Detail = "隔离记录身份或完整性异常，请核对隔离箱"
		} else {
			for _, row := range rows {
				if row.State == "prepared" || row.State == "conflict" || row.State == "restoring" {
					out.Healthy = false
					out.Detail = "存在待核对的隔离或恢复事务，请查看隔离箱"
					break
				}
			}
		}
	case "apache-waf":
		out.Healthy = exists(filepath.Join(s.moduleDir(id), "rules.conf"))
		if out.Healthy {
			state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-apache")
			out.Healthy = err == nil && strings.TrimSpace(state) == "active"
		}
		if out.Healthy {
			if err := s.verifyApacheWAFHealth(ctx, out.Version, out.Settings); err != nil {
				out.Healthy = false
				out.Detail = err.Error()
			}
		}
		if cfg, err := core.DecodeApacheWAFConfig(out.Settings); err == nil {
			out.Enabled = cfg.Policy.Mode != "off"
		}
	}
	if !out.Healthy && out.Detail == "模块已安装，可配置并执行" {
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
		if id == "php-code-security" {
			if err := s.phpQuarantineReference(""); err != nil {
				return err
			}
		}
		if id == "nfs-manager" {
			v, err := s.nfsServerConfig()
			if err != nil {
				return err
			}
			if len(v.Exports) > 0 || s.nfsActive(ctx) || s.nfsPending() {
				return errors.New("NFS 仍有服务端导出、运行服务或待恢复事务；先停止并移除导出，文件不会删除")
			}
			rows, _ := filepath.Glob(filepath.Join(s.moduleDir(id), "mounts", "*.json"))
			if len(rows) > 0 {
				return errors.New("仍有 NFS 挂载，请先卸载挂载点")
			}
			if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "disable", "--now", nfsServerUnit); err != nil {
				return err
			}
		}
		if id == "load-balance" {
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				return err
			}
			defer lock.Close()
			if _, err := os.Lstat(s.loadBalancePendingPath()); !errors.Is(err, os.ErrNotExist) {
				return errors.New("仍有负载均衡待恢复事务，拒绝卸载")
			}
			rows, err := s.loadBalanceEntries()
			if err != nil {
				return err
			}
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
			return s.removeApacheWAF(ctx, add)
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
		if !s.appDependencyReady(id) {
			if e := s.appDependencies(ctx, id); e != nil {
				return e
			}
		}
		if e := os.MkdirAll(s.systemPath("/var/lib/panel-executor/nfs-server-recovery"), 0700); e != nil {
			return e
		}
	case "apache-waf":
		return s.applyApacheWAF(ctx, settings, action == "install", false, add)
	}
	add("固定功能处理器与依赖检查通过")
	installedAt := core.Now()
	if action == "configure" {
		var previous map[string]any
		if e := moduleRead(filepath.Join(s.moduleDir(id), "installed.json"), &previous); e != nil {
			return e
		}
		if at, ok := previous["installed_at"].(string); ok {
			installedAt = at
		}
	}
	manifestPath := filepath.Join(s.moduleDir(id), "installed.json")
	previous, e := backupFile(manifestPath)
	if e != nil {
		return e
	}
	if e = moduleWrite(manifestPath, map[string]any{"id": id, "version": core.SoftwareImplementationVersion(id), "settings": settings, "installed_at": installedAt}); e != nil {
		return e
	}
	if id == "pure-ftpd" && action == "install" && !previous.existed {
		_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "enable", "--now", "panel-pure-ftpd.service")
		if e == nil {
			config, configErr := s.ftpConfig()
			if configErr == nil {
				data, _, certErr := s.ftpCertificate(config)
				if certErr == nil {
					e = s.ftpReady(ctx, config, data)
				} else {
					e = certErr
				}
			} else {
				e = configErr
			}
		}
		if e != nil {
			_, _ = s.Config.Run(context.WithoutCancel(ctx), "/usr/bin/systemctl", "disable", "--now", "panel-pure-ftpd.service")
			if restoreErr := restoreFiles([]fileBackup{previous}); restoreErr != nil {
				return errors.New("FTP 首次启动失败，安装记录恢复失败")
			}
			return e
		}
	}
	return nil
}

func (s *Service) updateSoftware(ctx context.Context, id, version string, add func(string)) error {
	if err := core.ValidateSoftwareUpdate(id, version); err != nil {
		return err
	}
	status := s.softwareStatus(ctx, id)
	stoppedFTP := false
	if id == "pure-ftpd" && status.Installed && !status.Healthy && !s.ftpRecoveryPending() {
		state, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pure-ftpd.service")
		if strings.TrimSpace(state) == "inactive" {
			config, e := s.ftpConfig()
			if e != nil {
				return e
			}
			pem, _, e := s.ftpCertificate(config)
			if e != nil {
				return e
			}
			current, e := ftpPrivateRead(filepath.Join(s.moduleDir(id), "server.pem"), 49152)
			if e != nil || core.Hash(string(current)) != core.Hash(string(pem)) {
				return errors.New("停止的 FTP 证书或配置不完整，未更新")
			}
			text, e := ftpPrivateRead(filepath.Join(s.moduleDir(id), "users.passwd"), 1<<20)
			if e != nil {
				return e
			}
			if _, e = ftpPublicUsers(text, s.Config.SitesDir); e != nil {
				return e
			}
			if _, e = ftpPrivateRead(filepath.Join(s.moduleDir(id), "users.pdb"), 4<<20); e != nil {
				return e
			}
			if _, e = s.ftpBinary("pure-ftpd"); e != nil {
				return e
			}
			stoppedFTP = true
		}
	}
	legacyApache := false
	if id == "apache-waf" && version == core.ApacheWAFVersion && status.Installed && (status.Version == "2.1.0" || status.Version == "2.0.0" || status.Version == "1.0") && !status.Healthy {
		if err := s.verifyApacheWAFLegacyUpgrade(ctx, status); err != nil {
			return fmt.Errorf("旧版 Apache 防护完整性未通过，未开始签名迁移：%w", err)
		}
		legacyApache = true
	}
	if !status.Installed || (!status.Healthy && !stoppedFTP && !legacyApache) {
		return errors.New("应用未安装或健康检查未通过，未修改版本记录")
	}
	cmp, valid := appcatalog.CompareVersions(version, status.Version)
	if !valid || cmp < 0 {
		return errors.New("拒绝应用版本降级或未知版本更新")
	}
	if id == "nginx-waf" && cmp > 0 && version == core.WAFVersion {
		manifest, err := s.readSoftwareManifest(id)
		if err != nil {
			return err
		}
		if wafLegacyVersion(manifest.Version) {
			return s.upgradeWAFLegacy(ctx, add)
		}
		return s.applyWAF(ctx, manifest.Settings, false, add)
	}
	if _, ok := core.FindAppModule(id); ok {
		if id == "pure-ftpd" && cmp > 0 {
			if s.validateFTPRuntime() != nil {
				if err := s.appDependencies(ctx, id); err != nil {
					return err
				}
			}
			if err := s.activateFTPRuntime(ctx); err != nil {
				return err
			}
			add("FTP 固定源码、构建补丁、独立程序和许可证校验通过；切换失败将恢复原服务")
		}
		if id == "apache-waf" && cmp > 0 {
			if version != core.ApacheWAFVersion {
				return errors.New("Apache WAF 更新目标与当前受限处理器版本不符，拒绝隐式版本切换")
			}
			return s.applyApacheWAF(ctx, status.Settings, false, true, add)
		}
		var manifest map[string]any
		path := filepath.Join(s.moduleDir(id), "installed.json")
		if err := moduleRead(path, &manifest); err != nil {
			return err
		}
		manifest["version"], manifest["updated_at"] = version, core.Now()
		if err := moduleWrite(path, manifest); err != nil {
			return err
		}
	} else {
		manifest, err := s.readSoftwareManifest(id)
		if err != nil {
			return err
		}
		manifest.Version = version
		if err = s.writeSoftwareManifest(manifest); err != nil {
			return err
		}
	}
	if stoppedFTP {
		add("FTP 受管运行时已核对；保持服务停止及原开机启动设置，未声明正在运行或已完成 TLS 连接验证")
	} else {
		add("当前签名面板已包含新版功能处理器；健康检查通过，保留配置、数据、基线与历史")
	}
	return nil
}
func (s *Service) appModuleRoutes(m *http.ServeMux) {
	s.appDependencyRoutes(m)
	s.apacheWAFWorkspaceRoutes(m)
	s.moduleAlertRoutes(m)
	m.HandleFunc("GET /v1/app-modules/{id}/history", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, ok := core.FindAppModule(id); !ok {
			respond(w, 404, map[string]string{"error": "未知模块"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		filter, err := core.ParseModuleHistoryQuery(r.URL.Query())
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		out, err := s.moduleHistory(id, filter)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/app-modules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		d, ok := core.FindAppModule(id)
		if !ok {
			respond(w, 404, map[string]string{"error": "未知模块"})
			return
		}
		var report any
		_ = moduleRead(filepath.Join(s.moduleDir(id), "last-report.json"), &report)
		respond(w, 200, map[string]any{"definition": d, "guidance": core.ModuleGuidance(id), "status": s.appModuleStatus(r.Context(), id), "report": report})
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
		// A lifecycle job can uninstall this module while the request waits
		// for the executor mutex. Recheck inside the same critical section as
		// the operation so a queued request cannot recreate orphan resources.
		if !s.moduleInstalled(id) {
			respond(w, 409, map[string]string{"error": "应用已卸载，未执行排队操作"})
			return
		}
		out, e := s.runAppModule(r.Context(), id, action, in)
		if action != "history" && action != "policies" && action != "run-plan" {
			if historyErr := s.appendModuleEvent(id, action, "manual", in, out, e); historyErr != nil && e == nil {
				e = fmt.Errorf("业务可能已执行，但历史保存失败，请核对结果：%w", historyErr)
			}
		}
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
	if action == "history" {
		return s.moduleHistory(id, in)
	}
	switch id {
	case "website-tamper-proof", "enterprise-tamper-proof", "file-monitor":
		if action == "policies" || action == "pause" || action == "resume" || action == "watch-mode" {
			return s.moduleIntegrityControl(id, action, in)
		}
		return s.moduleIntegrity(ctx, id, action, in)
	case "files-sync":
		if action != "preview" && action != "sync" {
			return s.moduleSyncPlans(ctx, action, in)
		}
		return s.moduleSync(ctx, in, action == "preview" || in.DryRun)
	case "php-code-security":
		return s.modulePHPQuarantine(ctx, action, in)
	case "disk-analysis":
		return s.moduleDiskAt(ctx, in.SiteID, in.Path)
	case "site-diagnosis":
		return s.moduleDiagnosis(ctx, in.SiteID)
	case "website-analytics", "website-statistics-v2":
		return s.moduleAnalyticsFiltered(ctx, in)
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
		return core.NativeMobileDelivery(), nil
	case "user-manager", "platform-ops", "daily-report":
		return map[string]any{"handler": "panel-api", "ready": true}, nil
	}
	return nil, errors.New("模块没有处理器")
}
func scanModuleFiles(ctx context.Context, root *os.Root, excludes []string, snapshot func(string, []byte) error) (map[string]moduleFile, bool, error) {
	files := map[string]moduleFile{}
	var total int64
	partial := false
	entries, metadataBytes := 0, 0
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
		entries++
		if entries > 100000 {
			partial = true
			return fs.SkipAll
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
		if !core.ValidFilePath(path, false) {
			return errors.New("扫描发现不支持的文件路径，请配置排除规则")
		}
		encoded, _ := json.Marshal(path)
		if metadataBytes+len(encoded)+160 > 3<<20 {
			partial = true
			return nil
		}
		if len(files) >= 10000 || info.Size() > 8<<20 || total+info.Size() > moduleMaxBytes {
			partial = true
			return nil
		}
		f, e := regularFile(root, path)
		if e != nil {
			return e
		}
		before, e := f.Stat()
		if e != nil {
			f.Close()
			return e
		}
		b, e := io.ReadAll(io.LimitReader(f, 8<<20+1))
		after, statErr := f.Stat()
		f.Close()
		if e != nil {
			return e
		}
		current, pathErr := root.Lstat(path)
		if statErr != nil || pathErr != nil || !os.SameFile(info, before) || !os.SameFile(before, current) || !current.Mode().IsRegular() || int64(len(b)) != info.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() || after.Size() != current.Size() || !after.ModTime().Equal(current.ModTime()) || after.Mode() != current.Mode() {
			return errors.New("扫描时文件发生变化")
		}
		total += int64(len(b))
		sha := sha256.Sum256(b)
		hash := hex.EncodeToString(sha[:])
		files[path] = moduleFile{hash, info.Size(), uint32(info.Mode().Perm())}
		metadataBytes += len(encoded) + 160
		if snapshot != nil {
			return snapshot(hash, b)
		}
		return nil
	})
	return files, partial, e
}
func (s *Service) moduleBaselineKey() ([]byte, error) {
	path := filepath.Join(s.Config.SecurityDir, "modules", "integrity-key")
	if b, e := s.existingBaselineKey(); e == nil {
		return b, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return nil, e
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return b, nil
}
func (s *Service) existingBaselineKey() ([]byte, error) {
	path := filepath.Join(s.Config.SecurityDir, "modules", "integrity-key")
	if err := ordinary(path, false); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("基线密钥格式无效")
	}
	return b, nil
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
			if in.Interval != 0 && (in.Interval < 60 || in.Interval > 86400) {
				return nil, errors.New("监控间隔应为 60–86400 秒")
			}
			paths, _ := filepath.Glob(filepath.Join(s.moduleDir(id), "baselines", "*", "baseline.json"))
			if !exists(path) && len(paths) >= 100 {
				return nil, errors.New("单个模块最多 100 个监控策略")
			}
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
			oldControl, e := backupFile(s.integrityControlPath(id, site))
			if e != nil {
				return nil, e
			}
			if e = s.resetIntegrityControl(id, site, in.Interval, in.Realtime); e != nil {
				return nil, e
			}
			if e = moduleWrite(path, base); e != nil {
				if rollbackErr := restoreFiles([]fileBackup{oldControl}); rollbackErr != nil {
					s.blockModuleAutomation(id + "/" + site)
				}
				return nil, e
			}
			delete(s.moduleAutoBlocked, id+"/"+site)
			s.wakeIntegrityWatcher()
			policy, _ := s.readIntegrityPolicy(id, site)
			results = append(results, map[string]any{"site_id": site, "files": len(files), "signature": base.Signature, "auto_restore": base.AutoRestore, "realtime": policy.Realtime, "revision": policy.Revision})
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
				if decoded, err := hex.DecodeString(old.SHA); err != nil || len(decoded) != 32 || old.Size < 0 || old.Size > 8<<20 {
					return nil, errors.New("备份元数据无效")
				}
				blob, e := os.OpenFile(filepath.Join(dir, "blobs", old.SHA), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
				if e != nil {
					return nil, e
				}
				data, e := io.ReadAll(io.LimitReader(blob, (8<<20)+1))
				blob.Close()
				if e != nil || int64(len(data)) != old.Size {
					return nil, errors.New("备份长度不匹配，拒绝恢复")
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
				var expected *moduleFile
				if value, exists := current[change.Path]; exists {
					expected = &value
				}
				if e = moduleWriteSiteFileGuarded(f, change.Path, data, os.FileMode(old.Mode), expected, true); e != nil {
					return nil, e
				}
				restored = append(restored, change.Path)
			}
		}
		if action == "restore" && !core.ValidFilePath(in.Path, false) {
			return nil, errors.New("请选择基线中的一个文件")
		}
		visible := []moduleChange{}
		budget := 256 << 10
		for _, change := range changes {
			raw, _ := json.Marshal(change)
			if len(visible) >= 200 || len(raw) > budget {
				break
			}
			budget -= len(raw)
			visible = append(visible, change)
		}
		restoredRows := boundedModulePaths(restored)
		result := map[string]any{"site_id": site, "changes": visible, "restored": restoredRows, "changes_count": len(changes), "restored_count": len(restored), "report_limited": len(visible) != len(changes) || len(restoredRows) != len(restored), "checked_at": core.Now(), "signature_verified": true}
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
	return moduleWriteSiteFileGuarded(f, path, data, mode, nil, false)
}
func moduleWriteSiteFileGuarded(f *siteFiles, path string, data []byte, mode os.FileMode, expected *moduleFile, enforce bool) error {
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
	if enforce && expected == nil {
		return renameBetween(f.public, temporary, f.public, path, false)
	}
	if enforce {
		current, err := readModuleFile(f.public, path)
		if err != nil {
			return err
		}
		info, err := f.public.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || core.Hash(string(current)) != expected.SHA || int64(len(current)) != expected.Size || uint32(info.Mode().Perm()) != expected.Mode {
			return errors.New("写入前目标文件已改变，未覆盖")
		}
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
	if err := moduleRead(checkpointPath, &old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("同步检查点损坏，拒绝覆盖目标")
	}
	copyPaths := []string{}
	conflicts := []string{}
	for path, v := range a {
		cur, exists := b[path]
		if exists && cur == v {
			continue
		}
		prev, tracked := old[path]
		if exists && (!tracked || cur != prev) {
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
			var expected *moduleFile
			if value, exists := b[p]; exists {
				expected = &value
			}
			if e = moduleWriteSiteFileGuarded(target, p, data, os.FileMode(a[p].Mode), expected, true); e != nil {
				return nil, e
			}
			old[p] = a[p]
			if e = moduleWrite(checkpointPath, old); e != nil {
				return nil, e
			}
		}
	}
	return syncReport(preview, copyPaths, conflicts, filepath.Base(checkpointPath)), nil
}
func (s *Service) moduleDisk(ctx context.Context, id string) (any, error) {
	return s.moduleDiskAt(ctx, id, "")
}
func (s *Service) moduleDiskAt(ctx context.Context, id, selectedPath string) (any, error) {
	if !core.ValidFilePath(selectedPath, true) {
		return nil, errors.New("请选择网站内的普通目录")
	}
	f, e := s.openFiles(id)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	root := f.public
	if selectedPath != "" && selectedPath != "." {
		parent := ""
		for _, part := range strings.Split(selectedPath, "/") {
			parent = filepath.Join(parent, part)
			info, err := f.public.Lstat(parent)
			if err != nil || !info.IsDir() {
				return nil, errors.New("子目录包含链接或不是普通目录")
			}
		}
		root, e = f.public.OpenRoot(selectedPath)
		if e != nil {
			return nil, e
		}
		defer root.Close()
	}
	var total int64
	count := 0
	entries := 0
	partial := false
	rows := []map[string]any{}
	dirs := map[string]int64{}
	extensions := map[string]int64{}
	rootChildren := map[string]int64{}
	keyBudget := 200 << 10
	addSize := func(group map[string]int64, key string, size int64) {
		if _, present := group[key]; !present {
			cost := 6*len(key) + 32
			if len(key) > 512 || len(group) >= 1000 || cost > keyBudget {
				partial = true
				return
			}
			keyBudget -= cost
		}
		group[key] += size
	}
	e = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entries >= 100000 {
			partial = true
			return fs.SkipAll
		}
		entries++
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
		addSize(dirs, filepath.Dir(p), st.Size())
		ext := strings.ToLower(filepath.Ext(p))
		if ext == "" {
			ext = "无扩展名"
		}
		addSize(extensions, ext, st.Size())
		child, _, _ := strings.Cut(p, "/")
		addSize(rootChildren, child, st.Size())
		fullPath := filepath.Join(selectedPath, p)
		row := map[string]any{"path": fullPath, "bytes": st.Size(), "can_drill": core.ValidFilePath(fullPath, false)}
		if len(fullPath) > 512 {
			row["path"] = fullPath[:512] + "…"
			row["can_drill"] = false
			partial = true
		} else {
			row["directory"] = filepath.Dir(fullPath)
		}
		if len(rows) < 100 {
			rows = append(rows, row)
		} else if st.Size() > rows[len(rows)-1]["bytes"].(int64) {
			rows[len(rows)-1] = row
		} else {
			return nil
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i]["bytes"].(int64) > rows[j]["bytes"].(int64) })
		return nil
	})
	if e != nil {
		return nil, e
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["bytes"].(int64) > rows[j]["bytes"].(int64) })
	if len(rows) > 100 {
		rows = rows[:100]
	}
	return map[string]any{"site_id": id, "path": selectedPath, "total_bytes": total, "files": count, "directories": dirs, "children": rootChildren, "extensions": extensions, "largest_files": rows, "partial": partial, "scope": "仅选定网站 public 目录；跳过符号链接，不删除任何文件"}, nil
}

var phpModuleRules = []struct{ name, pattern, severity string }{
	{"dynamic-evaluation", `(?i)\b(?:eval|assert)\s*\(`, "high"}, {"encoded-code", `(?i)\b(?:base64_decode|gzinflate|str_rot13)\s*\(`, "warning"}, {"command-execution", `(?i)\b(?:shell_exec|system|passthru|exec|popen|proc_open)\s*\(`, "high"}, {"unsafe-deserialization", `(?i)\bunserialize\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)`, "high"}, {"untrusted-file-write", `(?i)\b(?:file_put_contents|fwrite|move_uploaded_file)\s*\(`, "warning"},
}

func (s *Service) modulePHPScan(ctx context.Context, id string) (any, error) {
	return s.modulePHPScanFiltered(ctx, core.AppModuleInput{SiteID: id})
}
func (s *Service) modulePHPScanFiltered(ctx context.Context, in core.AppModuleInput) (any, error) {
	id := in.SiteID
	if len(in.Search) > 128 || len(in.Excludes) > 64 || in.Severity != "" && in.Severity != "high" && in.Severity != "warning" {
		return nil, errors.New("扫描筛选无效：风险级别为 high / warning，关键词不超过 128 字节，排除路径最多 64 项")
	}
	f, e := s.openFiles(id)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	files, partial, e := scanModuleFiles(ctx, f.public, in.Excludes, nil)
	if e != nil {
		return nil, e
	}
	findings := []map[string]any{}
	scanned := 0
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	severityCounts, ruleCounts := map[string]int{}, map[string]int{}
	search := strings.ToLower(in.Search)
scan:
	for _, p := range paths {
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".php" && ext != ".phtml" && ext != ".inc" {
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		scanned++
		b, err := readModuleFile(f.public, p)
		if err != nil {
			return nil, err
		}
		for _, rule := range phpModuleRules {
			if in.Severity != "" && in.Severity != rule.severity {
				continue
			}
			if search != "" && !strings.Contains(strings.ToLower(p), search) && !strings.Contains(rule.name, search) {
				continue
			}
			re := regexp.MustCompile(rule.pattern)
			matches := re.FindAllIndex(b, 21)
			if len(matches) > 20 {
				partial = true
				matches = matches[:20]
			}
			for _, index := range matches {
				line := strings.Count(string(b[:index[0]]), "\n") + 1
				evidence := string(b[index[0]:min(index[1], index[0]+512)])
				findings = append(findings, map[string]any{"site_id": id, "path": p, "line": line, "rule": rule.name, "severity": rule.severity, "evidence": evidence, "sha256": phpSHA(b)})
				severityCounts[rule.severity]++
				ruleCounts[rule.name]++
				if len(findings) >= 500 {
					partial = true
					break scan
				}
			}
		}
	}
	return map[string]any{"site_id": id, "scanned_php": scanned, "findings": findings, "findings_count": len(findings), "severity_counts": severityCounts, "rule_counts": ruleCounts, "excludes": in.Excludes, "checked_at": core.Now(), "partial": partial, "interpretation": "只读静态扫描 PHP / PHTML / INC；注释和合法函数也可能命中，需要结合上下文人工判断；未修改或隔离文件"}, nil
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
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err == nil {
		checks["http"] = map[string]any{"status": resp.StatusCode, "ok": resp.StatusCode >= 200 && resp.StatusCode < 400}
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
	passed := 0
	recommendations := []map[string]any{}
	for _, item := range []struct{ key, advice string }{{"dns", "检查域名 A / AAAA、DNS 生效及是否指向预期服务器；本地测试域名可能不具备公网 DNS。"}, {"http", "检查首页、站点绑定、访问权限和应用错误日志；403 / 404 不属于健康首页响应。"}, {"nginx", "运行 Nginx 配置检查，修复语法错误后再重载，不要在校验失败时覆盖线上配置。"}, {"tls_certificate", "检查域名 443、可信证书链、证书有效期和 HTTPS 配置。"}} {
		check, _ := checks[item.key].(map[string]any)
		ok, _ := check["ok"].(bool)
		if item.key == "tls_certificate" {
			ok, _ = check["valid"].(bool)
		}
		if ok {
			passed++
		} else {
			recommendations = append(recommendations, map[string]any{"check": item.key, "advice": item.advice})
		}
	}
	return map[string]any{"site_id": id, "domain": domain, "checked_at": core.Now(), "checks": checks, "passed_checks": passed, "total_checks": 4, "score": passed * 25, "recommendations": recommendations, "scope": "评分仅反映本次四项连通性与配置检查，不代表安全认证或公网可用性承诺"}, nil
}

func (s *Service) moduleAnalytics(ctx context.Context, id string) (any, error) {
	return s.moduleAnalyticsFiltered(ctx, core.AppModuleInput{SiteID: id})
}
func (s *Service) moduleAnalyticsFiltered(ctx context.Context, in core.AppModuleInput) (any, error) {
	id := in.SiteID
	if _, _, err := analyticsWindow(in); err != nil {
		return nil, err
	}
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
		return buildAnalyticsReport(ctx, strings.NewReader(""), id, in, false, time.Now())
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
	if offset > 0 {
		// Discard only the cut first line without reading ahead past its newline.
		one := make([]byte, 1)
		for {
			n, err := f.Read(one)
			if n == 0 || err != nil || one[0] == '\n' {
				break
			}
		}
	}
	return buildAnalyticsReport(ctx, f, id, in, offset > 0, time.Now())
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
	current, listenerLimit := networkLines(listeners)
	connectionRows, connectionLimit := networkLines(connections)
	path := filepath.Join(s.moduleDir("network-threat-detection"), "network-baseline.json")
	old := []string{}
	baselineErr := moduleRead(path, &old)
	if baselineErr != nil && !errors.Is(baselineErr, os.ErrNotExist) && action != "baseline" {
		return nil, errors.New("网络基线读取失败，未把损坏记录当作可信空基线")
	}
	if action == "baseline" {
		if listenerLimit {
			return nil, errors.New("监听快照超限，未保存不完整基线")
		}
		if e = moduleWrite(path, current); e != nil {
			return nil, e
		}
		old, baselineErr = current, nil
	}
	out := buildNetworkThreatReport(current, connectionRows, old, baselineErr == nil)
	fail2ban, fail2banErr := s.Config.Run(ctx, "/usr/bin/fail2ban-client", "status", "sshd")
	out["fail2ban"] = map[string]any{"available": fail2banErr == nil, "status": fail2ban}
	out["checked_at"], out["partial"] = core.Now(), listenerLimit || connectionLimit
	if stat, err := os.Stat(path); err == nil {
		out["baseline_at"] = stat.ModTime().UTC().Format(time.RFC3339)
	}
	return out, nil
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
		uidInfo, statErr := os.Stat(filepath.Join("/proc", strconv.Itoa(p.PID)))
		cgroup, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(p.PID), "cgroup"))
		managed := strings.Contains(string(cgroup), "panel-node@") || strings.Contains(string(cgroup), "panel-pm2@") || strings.Contains(string(cgroup), "panel-php@")
		canTerminate := false
		if statErr == nil {
			if stat, ok := uidInfo.Sys().(*syscall.Stat_t); ok {
				canTerminate = p.PID > 1 && stat.Uid != 0 && managed
			}
		}
		rows = append(rows, map[string]any{"pid": p.PID, "name": p.Name, "cpu_percent": p.CPUPercent, "memory": p.Memory, "read_rate": p.ReadRate, "write_rate": p.WriteRate, "state": p.State, "start_time": second[p.PID].StartTime, "managed": managed, "can_terminate": canTerminate})
	}
	connections, _ := s.Config.Run(ctx, "/usr/bin/ss", "-H", "-ntp")
	return map[string]any{"processes": rows, "connections": connections}, nil
}

// The worker resumes from private persisted policies after executor restarts.
func (s *Service) StartAppModuleWorker() {
	s.mu.Lock()
	if s.moduleWorkerStarted {
		s.mu.Unlock()
		return
	}
	s.moduleWorkerStarted = true
	s.moduleWatchWake = make(chan struct{}, 1)
	s.mu.Unlock()
	go s.runIntegrityWatcher(context.Background())
	go s.runLoadBalanceHealthWorker(context.Background())
	go s.runWAFBodyLogRotationWorker(context.Background())
	go s.runWAFBodyLogRetentionWorker(context.Background())
	go func() {
		s.mu.Lock()
		s.recoverSyncPlans()
		s.mu.Unlock()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for now := range ticker.C {
			s.runDueSyncPlans(now.UTC())
			s.runDueIntegrity(now.UTC())
		}
	}()
}
