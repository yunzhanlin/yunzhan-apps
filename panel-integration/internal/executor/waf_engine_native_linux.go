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
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
)

const wafEngineJobs = "/var/lib/panel-executor/waf-engine-builds"
const wafNativeEngines = appNativeRoot + "/nginx-waf/engines"
const wafNativeBuildCache = "/var/cache/panel-waf-build"

type wafEngineBuildRecord struct {
	Format         int               `json:"format"`
	JobID          string            `json:"job_id"`
	State          string            `json:"state"`
	Error          string            `json:"error,omitempty"`
	Architecture   string            `json:"architecture"`
	Engine         string            `json:"engine_version"`
	Connector      string            `json:"connector_version"`
	CRS            string            `json:"crs_version"`
	NginxVersion   string            `json:"nginx_version"`
	NginxBinary    string            `json:"nginx_binary"`
	NginxSHA       string            `json:"nginx_sha256"`
	Prefix         string            `json:"prefix"`
	ModuleSHA      string            `json:"module_sha256,omitempty"`
	LibrarySHA     string            `json:"library_sha256,omitempty"`
	TreeSHA        string            `json:"tree_sha256,omitempty"`
	SourceSHA      map[string]string `json:"source_sha256"`
	AssetSHA       map[string]string `json:"asset_sha256"`
	StartedAt      string            `json:"started_at"`
	FinishedAt     string            `json:"finished_at,omitempty"`
	Steps          []core.Step       `json:"steps"`
	ABIValidated   bool              `json:"module_abi_validated"`
	ProductionUsed bool              `json:"production_loaded"`
}

var wafNginxVersionPattern = regexp.MustCompile(`^nginx version: nginx/([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)`)

// A dedicated worker calls this with its persistent job ID. It builds a new
// immutable engine but does not change any Nginx config, active module pointer,
// listener, service or website. "ready" means ABI-tested program only; website
// activation must use a separate recoverable configuration transaction.
func RunWAFEngineBuild(id string) (err error) {
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWAFEngineBuildContext(parent, id)
}

func runWAFEngineBuildContext(parent context.Context, id string) (err error) {
	if os.Geteuid() != 0 || !core.ValidID(id) {
		return errors.New("WAF 原生构建必须为专用 root 服务及有效任务标识")
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Hour)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := readWAFEngineControl(wafEngineCancellations, id); err == nil {
		return errors.New("构建任务已被管理员停止，拒绝重用或重启同一标识")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s := nativeWAFService()
	for _, directory := range []string{wafEngineJobs, filepath.Dir(wafNativeEngines), wafNativeEngines, wafNativeBuildCache} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err := ownedRuntimePath(directory, true); err != nil {
			return err
		}
		mode := os.FileMode(0755)
		if directory == wafEngineJobs {
			mode = 0700
		}
		if err := os.Chmod(directory, mode); err != nil {
			return err
		}
	}
	if err := os.Chmod(wafEngineJobs, 0700); err != nil {
		return err
	}
	if entries, err := os.ReadDir(wafEngineJobs); err != nil || len(entries) >= 64 {
		return errors.New("WAF 构建记录已达 64 份或无法读取；需安全归档，拒绝自动删除")
	}
	if entries, err := os.ReadDir(wafNativeEngines); err != nil || len(entries) >= 16 {
		return errors.New("WAF 原生程序目录已达 16 份或无法读取；保留当前程序，不自动覆盖")
	}
	jobPath := filepath.Join(wafEngineJobs, id+".json")
	if _, err := os.Lstat(jobPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("WAF 构建任务已经存在，拒绝重用或覆盖证据")
	}
	prefix := filepath.Join(wafNativeEngines, id)
	record := wafEngineBuildRecord{Format: 1, JobID: id, State: "building", Architecture: runtime.GOARCH, Engine: wafBodyEngineVersion, Connector: wafBodyConnectorVersion, CRS: wafBodyCRSVersion, Prefix: prefix, SourceSHA: map[string]string{}, AssetSHA: wafEngineAssetPins(), StartedAt: core.Now(), Steps: []core.Step{}}
	if err := createWAFBuildRecord(jobPath, record); err != nil {
		return err
	}
	defer func() {
		record.FinishedAt = core.Now()
		if err != nil {
			record.State, record.Error = "failed", err.Error()
		}
		if saveErr := moduleWrite(jobPath, record); saveErr != nil {
			err = errors.Join(err, saveErr)
		}
	}()
	step := func(message string) error {
		record.Steps = append(record.Steps, core.Step{Time: core.Now(), Message: message})
		return moduleWrite(jobPath, record)
	}
	if err := step("核对实际 Nginx 选择、官方版本源码及程序摘要"); err != nil {
		return err
	}
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	version, err := s.moduleCommand(ctx, 10*time.Second, nginx, "-v")
	if err != nil {
		return fmt.Errorf("不能执行实际 Nginx 版本校验: %w", err)
	}
	match := wafNginxVersionPattern.FindStringSubmatch(strings.TrimSpace(version))
	if len(match) != 2 {
		return errors.New("不能确认当前实际 Nginx 程序版本")
	}
	nginxSource, ok := wafNginxBuildSource(match[1])
	if !ok {
		return errors.New("实际 Nginx 版本不在固定模块构建清单中；不会尝试加载不匹配模块")
	}
	nginxSHA, err := wafNativeFileSHA(ctx, nginx, 32<<20)
	if err != nil {
		return err
	}
	record.NginxVersion, record.NginxBinary, record.NginxSHA = match[1], nginx, nginxSHA
	if err := step("等待全局源码构建锁（最多 30 分钟），不并行抢占其他运行时构建"); err != nil {
		return err
	}
	lock, err := os.OpenFile("/var/lib/panel-executor/build.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	lockCtx, lockCancel := context.WithTimeout(ctx, 30*time.Minute)
	err = acquireRuntimeBuildLock(lockCtx, lock)
	lockCancel()
	if err != nil {
		return fmt.Errorf("等待 WAF 构建锁失败，未开始下载或编译: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := wafBuildDiskBudget(wafNativeBuildCache); err != nil {
		return err
	}
	build := filepath.Join(wafNativeBuildCache, id)
	if err := os.Mkdir(build, 0755); err != nil {
		return err
	}
	if err := os.Chmod(build, 0755); err != nil {
		return err
	}
	work, assets := filepath.Join(build, "work"), filepath.Join(build, "assets")
	for _, directory := range []string{work, assets} {
		if err := os.Mkdir(directory, 0755); err != nil {
			return err
		}
		if err := os.Chmod(directory, 0755); err != nil {
			return err
		}
	}
	for name := range wafEngineAssetPins() {
		data, err := verifiedWAFEngineAsset(name)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(assets, name), data, 0644); err != nil {
			return err
		}
	}
	sources := append(wafEngineSources(), nginxSource)
	sourceCache := filepath.Join(wafNativeBuildCache, "sources")
	if err := os.Mkdir(sourceCache, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := ownedRuntimePath(sourceCache, true); err != nil {
		return err
	}
	if err := os.Chmod(sourceCache, 0755); err != nil {
		return err
	}
	workNames := map[string]string{"modsecurity": "modsecurity", "modsecurity-nginx": "connector", "owasp-crs": "crs", "nginx-build": "nginx"}
	for _, source := range sources {
		if err := step("下载、固定摘要校验及完整预检源码：" + source.Name + " " + source.Version); err != nil {
			return err
		}
		archive := filepath.Join(build, source.Name+".tar.gz")
		cached := filepath.Join(sourceCache, source.Name+"-"+source.SHA256+".tar.gz")
		if _, err := os.Lstat(cached); errors.Is(err, os.ErrNotExist) {
			if err := downloadWAFEngineSource(ctx, source, cached); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if digest, err := wafNativeFileSHA(ctx, cached, wafNativeSourceBytes); err != nil || digest != source.SHA256 {
			return errors.New("WAF 官方源码私有缓存摘要异常，拒绝覆盖、解包或编译")
		}
		if err := copyWAFNativeFile(ctx, cached, archive, wafNativeSourceBytes, os.Geteuid()); err != nil {
			return err
		}
		if err := extractWAFEngineSource(ctx, source, archive, filepath.Join(work, workNames[source.Name])); err != nil {
			return err
		}
		record.SourceSHA[source.Name] = source.SHA256
	}
	buildUser, err := user.Lookup("panel-build")
	if err != nil {
		return errors.New("缺少专用非特权 panel-build 用户")
	}
	uid, uidErr := strconv.Atoi(buildUser.Uid)
	gid, gidErr := strconv.Atoi(buildUser.Gid)
	if uidErr != nil || gidErr != nil || uid < 1 || gid < 1 {
		return errors.New("panel-build 必须是非 root 用户")
	}
	// GNU chown -P/-h does not follow any source link. Only this new owned
	// workspace is granted; parent, archives, evidence and assets stay root-owned.
	if _, err := s.moduleCommand(ctx, time.Minute, "/usr/bin/chown", "-R", "-h", "-P", "panel-build:panel-build", work); err != nil {
		return err
	}
	for _, name := range workNames {
		if err := os.Chmod(filepath.Join(work, name), 0755); err != nil {
			return err
		}
	}
	if err := os.Mkdir(prefix, 0755); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			// Once compiler processes have been cancelled/collected, failed
			// program state is sealed too; it is never selectable or reused.
			if sealErr := sealWAFNativeTree(prefix, uid); sealErr != nil {
				err = errors.Join(err, fmt.Errorf("保留失败程序并收回写权限失败: %w", sealErr))
			}
		}
	}()
	if err := os.Chown(prefix, uid, gid); err != nil {
		return err
	}
	plan, err := wafNativeBuildPlan(work, prefix, assets, record.NginxVersion)
	if err != nil {
		return err
	}
	for _, command := range plan {
		if err := step(command.Label); err != nil {
			return err
		}
		if err := runWAFNativeBuildCommand(ctx, command, filepath.Join(build, "build.log"), work); err != nil {
			return err
		}
	}
	if err := sealWAFNativeTree(prefix, uid); err != nil {
		return err
	}
	module := filepath.Join(work, "nginx", "nginx-"+record.NginxVersion, "objs/ngx_http_modsecurity_module.so")
	if err := os.Mkdir(filepath.Join(prefix, "nginx"), 0755); err != nil {
		return err
	}
	if err := copyWAFNativeFile(ctx, module, filepath.Join(prefix, "nginx/ngx_http_modsecurity_module.so"), 32<<20, uid); err != nil {
		return err
	}
	// Re-extract verified original archives privately: never publish rules or
	// Unicode data from the compiler-writable workspace.
	resources := filepath.Join(build, "verified-resources")
	if err := os.Mkdir(resources, 0700); err != nil {
		return err
	}
	for _, source := range wafEngineSources() {
		if source.Name == "modsecurity-nginx" {
			continue
		}
		if err := extractWAFEngineSource(ctx, source, filepath.Join(build, source.Name+".tar.gz"), filepath.Join(resources, source.Name)); err != nil {
			return err
		}
	}
	sourceDir := filepath.Join(prefix, "source")
	if err := os.Mkdir(sourceDir, 0755); err != nil {
		return err
	}
	if err := copyWAFRuleTree(ctx, filepath.Join(resources, "owasp-crs/coreruleset-4.30.0"), filepath.Join(sourceDir, "coreruleset-4.30.0")); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(sourceDir, "modsecurity-v3.0.17"), 0755); err != nil {
		return err
	}
	if err := copyWAFNativeFile(ctx, filepath.Join(resources, "modsecurity/modsecurity-v3.0.17/unicode.mapping"), filepath.Join(sourceDir, "modsecurity-v3.0.17/unicode.mapping"), 2<<20, os.Geteuid()); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(prefix, "licenses-and-changes"), 0755); err != nil {
		return err
	}
	for name := range wafEngineAssetPins() {
		data, err := verifiedWAFEngineAsset(name)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(prefix, "licenses-and-changes", name), data, 0644); err != nil {
			return err
		}
	}
	if err := step("使用同一实际 Nginx 程序进行独立模块 ABI 和完整 CRS 语法校验；不重载线上服务"); err != nil {
		return err
	}
	if err := probeWAFNativeModule(ctx, s, nginx, prefix, build); err != nil {
		return err
	}
	selected, err := s.nginxBinary()
	if err != nil || selected != nginx {
		return errors.New("编译期间 Nginx 选择已变化，拒绝发布或自动启用模块")
	}
	if current, err := wafNativeFileSHA(ctx, nginx, 32<<20); err != nil || current != nginxSHA {
		return errors.New("实际 Nginx 程序摘要发生变化，拒绝发布模块")
	}
	if record.ModuleSHA, err = wafNativeFileSHA(ctx, filepath.Join(prefix, "nginx/ngx_http_modsecurity_module.so"), 32<<20); err != nil {
		return err
	}
	if record.LibrarySHA, err = wafNativeFileSHA(ctx, filepath.Join(prefix, "lib/libmodsecurity.so.3.0.17"), 64<<20); err != nil {
		return err
	}
	if record.TreeSHA, err = runtimeTreeSHA(ctx, prefix, prefix); err != nil {
		return err
	}
	record.State, record.ABIValidated = "ready", true
	return step("独立引擎完整程序摘要与许可已保存；尚未应用到任何网站")
}

func wafNativeFileSHA(ctx context.Context, path string, limit int64) (string, error) {
	if err := ownedRuntimePath(path, false); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > limit {
		return "", errors.New("WAF 程序大小异常")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&contextReader{ctx, f}, limit+1))
	if err != nil || n != st.Size() || n > limit {
		return "", errors.New("WAF 程序摘要读取失败或文件发生变化")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyWAFNativeFile(ctx context.Context, source, destination string, limit int64, sourceUID int) error {
	f, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return errors.New("WAF 程序或规则资源类型、大小异常")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(sourceUID) || stat.Nlink != 1 {
		return errors.New("WAF 程序或规则资源所有者或链接数异常")
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(&contextReader{ctx, f}, limit+1))
	if err != nil || n != st.Size() || n > limit {
		return errors.New("WAF 资源复制期间内容变化或超过限额")
	}
	return out.Sync()
}

func copyWAFRuleTree(ctx context.Context, source, destination string) error {
	var total int64
	count := 0
	return filepath.WalkDir(source, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > 2000 {
			return errors.New("WAF 规则文件数量超限")
		}
		rel, err := filepath.Rel(source, p)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if d.IsDir() {
			return os.Mkdir(target, 0755)
		}
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			return errors.New("WAF 固定规则树不允许链接或特殊文件")
		}
		total += st.Size()
		if total > 16<<20 {
			return errors.New("WAF 规则目录超过 16 MiB")
		}
		return copyWAFNativeFile(ctx, p, target, 2<<20, os.Geteuid())
	})
}

// Seal each parent descriptor before inspecting descendants, so the build
// user cannot replace children during the privilege/permission transition.
// Symbolic links are never followed; absolute/outside links fail closed.
func sealWAFNativeTree(prefix string, buildUID int) error {
	if err := ordinary(prefix, true); err != nil {
		return err
	}
	root, err := os.OpenRoot(prefix)
	if err != nil {
		return err
	}
	defer root.Close()
	count := 0
	var visit func(string) error
	visit = func(name string) error {
		count++
		if count > 10000 {
			return errors.New("WAF 程序目录条目超过 10000")
		}
		st, err := root.Lstat(name)
		if err != nil {
			return err
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != uint32(buildUID) && stat.Uid != uint32(os.Geteuid())) {
			return errors.New("WAF 待发布程序所有者异常")
		}
		if st.Mode()&os.ModeSymlink != 0 {
			link, err := root.Readlink(name)
			if err != nil {
				return err
			}
			target := filepath.Clean(filepath.Join(filepath.Dir(name), link))
			if filepath.IsAbs(link) || !filepath.IsLocal(target) {
				return errors.New("WAF 程序链接越界")
			}
			resolved, err := root.Stat(name)
			if err != nil || (!resolved.IsDir() && !resolved.Mode().IsRegular()) {
				return errors.New("WAF 程序链接悬空、循环、越界或指向特殊文件")
			}
			return root.Lchown(name, os.Geteuid(), os.Getegid())
		}
		if !st.IsDir() && !st.Mode().IsRegular() {
			return errors.New("WAF 程序包含特殊文件")
		}
		if st.Mode().IsRegular() && stat.Nlink != 1 {
			return errors.New("WAF 程序普通文件存在共享硬链接")
		}
		flags := os.O_RDONLY | syscall.O_NOFOLLOW
		if st.IsDir() {
			flags |= syscall.O_DIRECTORY
		}
		f, err := root.OpenFile(name, flags, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := f.Chown(os.Geteuid(), os.Getegid()); err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if st.IsDir() || st.Mode().Perm()&0111 != 0 {
			mode = 0755
		}
		if err := f.Chmod(mode); err != nil {
			return err
		}
		if !st.IsDir() {
			return nil
		}
		entries, err := f.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := visit(filepath.Join(name, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(".")
}

func probeWAFNativeModule(ctx context.Context, s *Service, nginx, prefix, build string) error {
	probe := filepath.Join(build, "abi-probe")
	if err := os.Mkdir(probe, 0700); err != nil {
		return err
	}
	temporary := filepath.Join(probe, "body-tmp")
	if err := os.Mkdir(temporary, 0700); err != nil {
		return err
	}
	rules, err := renderWAFBodyRules(defaultWAFBodyPolicy(), filepath.Join(prefix, "source"), temporary)
	if err != nil {
		return err
	}
	rulesPath := filepath.Join(probe, "rules.conf")
	if err := atomicWrite(rulesPath, []byte(rules), 0600); err != nil {
		return err
	}
	metadata := filepath.Join(probe, "metadata.log")
	if err := atomicWrite(metadata, nil, 0600); err != nil {
		return err
	}
	conf := fmt.Sprintf("load_module %s;\npid %s;\nerror_log stderr warn;\nevents { worker_connections 16; }\nhttp { access_log off; modsecurity_metadata_log %s; modsecurity on; modsecurity_rules_file %s; }\n", filepath.Join(prefix, "nginx/ngx_http_modsecurity_module.so"), filepath.Join(probe, "nginx.pid"), metadata, rulesPath)
	path := filepath.Join(probe, "nginx.conf")
	if err := atomicWrite(path, []byte(conf), 0600); err != nil {
		return err
	}
	_, err = s.moduleCommand(ctx, 30*time.Second, nginx, "-t", "-p", probe+"/", "-c", path)
	return err
}

func wafBuildDiskBudget(cache string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(cache, &stat); err != nil {
		return err
	}
	if stat.Bsize < 1 || stat.Bavail*uint64(stat.Bsize) < 1<<30 {
		return errors.New("WAF 源码构建需至少 1 GiB 可用空间，未开始修改")
	}
	var bytes int64
	var count int
	return filepath.WalkDir(cache, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 300000 {
			return errors.New("WAF 私有构建缓存条目达到上限，需安全归档")
		}
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if st.Mode().IsRegular() {
			bytes += st.Size()
			if bytes > 6<<30 {
				return errors.New("WAF 私有构建缓存超过 6 GiB，保留现有证据并停止新构建")
			}
		}
		return nil
	})
}

func createWAFBuildRecord(path string, record wafEngineBuildRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
