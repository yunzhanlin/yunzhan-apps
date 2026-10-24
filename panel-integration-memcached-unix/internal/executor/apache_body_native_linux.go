//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
)

// Compiled entrypoint only: immutable sources and commands, no site/service
// mutation, no package installation and no caller-selected dependency flags.
func RunApacheBodyBuild(id string) error {
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runApacheBodyBuildContext(parent, id)
}

func runApacheBodyBuildContext(parent context.Context, id string) (err error) {
	if os.Geteuid() != 0 || !core.ValidID(id) {
		return errors.New("Apache 请求体构建需要专用 root 服务及有效任务标识")
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Hour)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyApacheBodyWorkerCapabilities(); err != nil {
		return err
	}
	// Validate the dedicated read-only cgroup and stable-PID support before
	// creating any build evidence, fetching source or granting compiler access.
	scope, err := beginApacheBodyCompilerScope()
	if err != nil {
		return err
	}
	if err := scope.Close(); err != nil {
		return err
	}
	if err := readApacheBodyControl(apacheBodyRequests, id); err != nil {
		return fmt.Errorf("缺少本任务的私有 Apache 构建请求: %w", err)
	}
	if err := apacheBodyNotCanceled(id); err != nil {
		return err
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{{apacheBodyJobs, 0700}, {apacheBodyEngines, 0755}, {apacheBodyCache, 0755}} {
		if err := ensureApacheBodyDirectory(directory.path, directory.mode); err != nil {
			return err
		}
	}
	// Reuse only the fixed global runtime serialization point, with its type,
	// owner, link count and permissions checked before waiting or writing.
	lock, err := os.OpenFile("/var/lib/panel-executor/build.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := apacheBodyPrivateFile(lock, 1<<10); err != nil {
		return err
	}
	lockCtx, lockCancel := context.WithTimeout(ctx, 30*time.Minute)
	err = acquireRuntimeBuildLock(lockCtx, lock)
	lockCancel()
	if err != nil {
		return fmt.Errorf("等待全局构建锁失败，未开始编译: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := apacheBodyNotCanceled(id); err != nil {
		return err
	}
	for _, limit := range []struct {
		path  string
		count int
	}{{apacheBodyJobs, 64}, {apacheBodyEngines, 16}} {
		entries, err := os.ReadDir(limit.path)
		if err != nil || len(entries) >= limit.count {
			return errors.New("Apache 构建记录或独立程序达到保留限额；拒绝自动删除、覆盖或清理")
		}
	}
	jobPath := filepath.Join(apacheBodyJobs, id+".json")
	record := apacheBodyBuildRecord{Format: 1, JobID: id, State: "building", Architecture: runtime.GOARCH, Engine: apacheBodyEngineVersion, YAJL: apacheBodyYAJLVersion, CRS: wafBodyCRSVersion, Prefix: filepath.Join(apacheBodyEngines, id), SourceSHA: map[string]string{}, AssetSHA: apacheBodyReleaseAssetPins(), StartedAt: core.Now(), CompletedBuildSteps: []string{}, Steps: []core.Step{}}
	if err := createApacheBodyRecord(jobPath, record); err != nil {
		return err
	}
	defer func() {
		record.FinishedAt = core.Now()
		if err != nil {
			record.State, record.Error = "failed", err.Error()
			if len(record.Error) > 4096 {
				record.Error = "Apache 构建失败；详细证据保留于私有构建日志"
			}
		}
		if saveErr := saveApacheBodyRecord(jobPath, record); saveErr != nil {
			err = errors.Join(err, saveErr)
		}
	}()
	step := func(message string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := apacheBodyNotCanceled(id); err != nil {
			return err
		}
		if len(record.Steps) >= 48 {
			return errors.New("Apache 构建审计步骤超限")
		}
		record.Steps = append(record.Steps, core.Step{Time: core.Now(), Message: message})
		return saveApacheBodyRecord(jobPath, record)
	}
	s := nativeWAFService()
	if err := step("核对实际 Apache 2.4.68、固定构建依赖和专用非特权账户"); err != nil {
		return err
	}
	r, err := apacheRelease()
	if err != nil {
		return err
	}
	version, err := s.moduleCommand(ctx, 10*time.Second, r.CLI(), "-v")
	if err != nil || !strings.HasPrefix(version, "Server version: Apache/"+r.Version+" ") && !strings.HasPrefix(version, "Server version: Apache/"+r.Version+"\n") {
		return errors.New("实际 Apache 程序版本不匹配；未开始编译")
	}
	if !s.wafBuildPackagesReady(apacheBodyBuildDependencies()) {
		return errors.New("固定 Apache 编译依赖未就绪；未尝试安装调用方软件包")
	}
	for _, p := range []string{r.Prefix(), r.CLI(), filepath.Join(r.Prefix(), "bin/apxs")} {
		if err := ownedRuntimePath(p, p == r.Prefix()); err != nil {
			return err
		}
	}
	if record.ApacheSHA, err = wafNativeFileSHA(ctx, r.CLI(), 64<<20); err != nil {
		return err
	}
	record.ApacheVersion, record.ApacheBinary = r.Version, r.CLI()
	buildUser, err := user.Lookup("panel-build")
	if err != nil {
		return errors.New("缺少专用非特权 panel-build 用户")
	}
	uid, uidErr := strconv.Atoi(buildUser.Uid)
	gid, gidErr := strconv.Atoi(buildUser.Gid)
	if uidErr != nil || gidErr != nil || uid < 1 || gid < 1 {
		return errors.New("panel-build 账户必须为非 root")
	}
	if err := wafBuildDiskBudget(apacheBodyCache); err != nil {
		return err
	}
	build := filepath.Join(apacheBodyCache, id)
	if err := os.Mkdir(build, 0755); err != nil {
		return err
	}
	if err := os.Chmod(build, 0755); err != nil {
		return err
	}
	paths := apacheBodyPaths(id)
	for _, p := range []string{paths.Work, paths.Prefix, paths.Assets, filepath.Join(paths.Prefix, "lib"), filepath.Join(paths.Prefix, "include"), filepath.Join(paths.Prefix, "include/yajl")} {
		if err := os.Mkdir(p, 0755); err != nil {
			return err
		}
		if err := os.Chmod(p, 0755); err != nil {
			return err
		}
	}
	// On every outcome, compiler processes are collected by the command
	// runner before write permission is withdrawn; failed state is preserved.
	defer func() {
		for _, p := range []string{paths.Work, paths.Prefix} {
			if sealErr := sealWAFNativeTree(p, uid); sealErr != nil {
				err = errors.Join(err, sealErr)
			}
		}
	}()
	for name := range apacheBodyReleaseAssetPins() {
		b, err := verifiedApacheBodyReleaseAsset(name)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(paths.Assets, name), b, 0644); err != nil {
			return err
		}
	}
	sourceCache := filepath.Join(apacheBodyCache, "sources")
	if err := ensureApacheBodyDirectory(sourceCache, 0755); err != nil {
		return err
	}
	workNames := map[string]string{"apache-modsecurity": "modsecurity", "apache-yajl": "yajl", "owasp-crs": "crs"}
	for _, source := range apacheBodyReleaseSources() {
		if err := step("固定来源下载、摘要核对和完整预检：" + source.Name + " " + source.Version); err != nil {
			return err
		}
		cached := filepath.Join(sourceCache, source.Name+"-"+source.SHA256+".tar.gz")
		if _, err := os.Lstat(cached); errors.Is(err, os.ErrNotExist) {
			if source.Name == "owasp-crs" {
				err = downloadWAFEngineSource(ctx, source, cached)
			} else {
				err = downloadApacheBodySource(ctx, source, cached)
			}
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if digest, err := wafNativeFileSHA(ctx, cached, wafNativeSourceBytes); err != nil || digest != source.SHA256 {
			return errors.New("Apache 私有原始源码缓存摘要异常，拒绝覆盖或执行")
		}
		archive := filepath.Join(build, source.Name+".tar.gz")
		if err := copyWAFNativeFile(ctx, cached, archive, wafNativeSourceBytes, 0); err != nil {
			return err
		}
		target := filepath.Join(paths.Work, workNames[source.Name])
		if source.Name == "owasp-crs" {
			err = extractWAFEngineSource(ctx, source, archive, target)
		} else {
			err = extractApacheBodySource(ctx, source, archive, target)
		}
		if err != nil {
			return err
		}
		record.SourceSHA[source.Name] = source.SHA256
	}
	for _, name := range []string{"yajl_common.h", "yajl_parse.h", "yajl_gen.h", "yajl_tree.h"} {
		if err := copyWAFNativeFile(ctx, filepath.Join(paths.Work, "yajl/yajl-2.1.0/src/api", name), filepath.Join(paths.Prefix, "include/yajl", name), 64<<10, 0); err != nil {
			return err
		}
	}
	if err := atomicWrite(filepath.Join(paths.Prefix, "include/yajl/yajl_version.h"), []byte(apacheBodyYAJLVersionHeader), 0644); err != nil {
		return err
	}
	for _, p := range []string{paths.Work, paths.Prefix} {
		if err := apacheBodyGrantCompilerTree(p, uid, gid); err != nil {
			return err
		}
	}
	plan, err := apacheBodyNativeBuildPlan(paths)
	if err != nil {
		return err
	}
	for i, command := range plan {
		if err := step(command.Label); err != nil {
			return err
		}
		if err := runApacheBodyNativeBuildCommand(ctx, paths, i, command, filepath.Join(build, "build.log"), paths.Work); err != nil {
			return err
		}
		record.CompletedBuildSteps = append(record.CompletedBuildSteps, command.Label)
	}
	record.CompilerCollected = true
	record.CompilerCollection = apacheBodyCompilerCollectionContract
	for _, p := range []string{paths.Work, paths.Prefix} {
		if err := sealWAFNativeTree(p, uid); err != nil {
			return err
		}
	}
	if err := step("封存已回收编译器的输出，并检查实际 ELF 加固与静态 JSON 依赖"); err != nil {
		return err
	}
	module := filepath.Join(paths.Work, "modsecurity/modsecurity-v2.9.15/apache2/.libs/mod_security2.so")
	if err := probeApacheBodyELF(ctx, module); err != nil {
		return err
	}
	record.HardeningValidated = true
	if err := os.Mkdir(record.Prefix, 0755); err != nil {
		return err
	}
	for _, p := range []string{filepath.Join(record.Prefix, "apache"), filepath.Join(record.Prefix, "source"), filepath.Join(record.Prefix, "licenses-and-changes")} {
		if err := os.Mkdir(p, 0755); err != nil {
			return err
		}
	}
	if err := copyWAFNativeFile(ctx, module, filepath.Join(record.Prefix, "apache/mod_security2.so"), 64<<20, 0); err != nil {
		return err
	}
	// Root-owned re-extraction, not the compiler's rules/unicode output.
	resources := filepath.Join(build, "verified-resources")
	if err := os.Mkdir(resources, 0700); err != nil {
		return err
	}
	for _, source := range apacheBodyReleaseSources() {
		if source.Name == "apache-yajl" {
			continue
		}
		target := filepath.Join(resources, source.Name)
		archive := filepath.Join(build, source.Name+".tar.gz")
		if source.Name == "owasp-crs" {
			err = extractWAFEngineSource(ctx, source, archive, target)
		} else {
			err = extractApacheBodySource(ctx, source, archive, target)
		}
		if err != nil {
			return err
		}
	}
	if err := copyWAFRuleTree(ctx, filepath.Join(resources, "owasp-crs/coreruleset-4.30.0"), filepath.Join(record.Prefix, "source/coreruleset-4.30.0")); err != nil {
		return err
	}
	unicodeDir := filepath.Join(record.Prefix, "source/modsecurity-v2.9.15")
	if err := os.Mkdir(unicodeDir, 0755); err != nil {
		return err
	}
	if err := copyWAFNativeFile(ctx, filepath.Join(resources, "apache-modsecurity/modsecurity-v2.9.15/unicode.mapping"), filepath.Join(unicodeDir, "unicode.mapping"), 2<<20, 0); err != nil {
		return err
	}
	for name := range apacheBodyReleaseAssetPins() {
		b, err := verifiedApacheBodyReleaseAsset(name)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(record.Prefix, "licenses-and-changes", name), b, 0644); err != nil {
			return err
		}
	}
	if err := sealWAFNativeTree(record.Prefix, 0); err != nil {
		return err
	}
	if err := step("使用同一实际 Apache 进行独立模块 ABI 和完整 CRS 语法校验；不重载服务"); err != nil {
		return err
	}
	if err := probeApacheBodyModule(ctx, s, r.Prefix(), record.Prefix, build); err != nil {
		return err
	}
	if current, err := wafNativeFileSHA(ctx, r.CLI(), 64<<20); err != nil || current != record.ApacheSHA {
		return errors.New("编译期间实际 Apache 程序摘要变化，拒绝发布")
	}
	if record.ModuleSHA, err = wafNativeFileSHA(ctx, filepath.Join(record.Prefix, "apache/mod_security2.so"), 64<<20); err != nil {
		return err
	}
	if record.TreeSHA, err = runtimeTreeSHA(ctx, record.Prefix, record.Prefix); err != nil {
		return err
	}
	if err := step("独立程序、原始源码、完整许可与实际 ABI 证据已保存；尚未启用任何网站"); err != nil {
		return err
	}
	record.State, record.ABIValidated, record.FinishedAt = "ready", true, core.Now()
	return apacheBodyRecordContract(record)
}

func apacheBodyBuildDependencies() []string {
	return []string{"build-essential", "pkg-config", "libpcre2-dev", "libxml2-dev", "libapr1-dev", "libaprutil1-dev", "patch"}
}

func apacheBodyNotCanceled(id string) error {
	if err := readApacheBodyControl(apacheBodyCancellations, id); err == nil {
		return errors.New("Apache 构建任务已取消；同一身份不能重启或覆盖")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func ensureApacheBodyDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("Apache 构建目录不是绝对规范路径")
	}
	if path != "/" {
		if err := ensureApacheBodyDirectoryParent(filepath.Dir(path)); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := ownedRuntimePath(path, true); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode().Perm() != mode {
		return errors.New("Apache 私有目录权限异常；不自动修复或接管已有状态")
	}
	return nil
}

func ensureApacheBodyDirectoryParent(path string) error {
	if path != "/" {
		if err := ensureApacheBodyDirectoryParent(filepath.Dir(path)); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) && path != "/" {
		if err := os.Mkdir(path, 0755); err != nil {
			return err
		}
		if err := os.Chmod(path, 0755); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return ownedRuntimePath(path, true)
}

func apacheBodyPrivateFile(f *os.File, limit int64) error {
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > limit {
		return errors.New("Apache 私有记录类型、权限或大小异常")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("Apache 私有记录所有者或硬链接异常")
	}
	return nil
}

func createApacheBodyRecord(path string, record apacheBodyBuildRecord) error {
	b, err := json.Marshal(record)
	if err != nil || len(b) > 64<<10 {
		return errors.New("Apache 构建记录序列化失败或超限")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(b)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func saveApacheBodyRecord(path string, record apacheBodyBuildRecord) error {
	if err := ownedRuntimePath(filepath.Dir(path), true); err != nil {
		return err
	}
	if _, err := readApacheBodyRecordAt(path, record.JobID); err != nil {
		return err
	}
	b, err := json.Marshal(record)
	if err != nil || len(b) > 64<<10 {
		return errors.New("Apache 构建记录序列化失败或超限")
	}
	return atomicWrite(path, append(b, '\n'), 0600)
}

func apacheBodyGrantCompilerTree(path string, uid, gid int) error {
	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return os.Lchown(p, uid, gid)
		}
		mode := os.FileMode(0644)
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if d.IsDir() || st.Mode().Perm()&0111 != 0 {
			mode = 0755
		}
		if err := os.Chmod(p, mode); err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}

func probeApacheBodyELF(parent context.Context, module string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	outputs := []string{}
	for _, kind := range []string{"-d", "-l", "-s"} {
		cmd := exec.CommandContext(ctx, "/usr/bin/readelf", "-W", kind, module)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
		out := &boundedBuffer{max: 1 << 20}
		cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, out, time.Second
		if err := cmd.Run(); err != nil || out.truncated {
			return errors.New("实际 Apache ELF 证据读取失败或超限")
		}
		outputs = append(outputs, out.String())
	}
	if strings.Contains(outputs[0], "libyajl.so") || strings.Contains(outputs[0], "(RPATH)") || strings.Contains(outputs[0], "(RUNPATH)") {
		return errors.New("Apache 模块含动态 JSON 依赖或不允许的运行时库搜索路径")
	}
	return verifyApacheBodyELFHardening(outputs[0], outputs[1], outputs[2])
}

func probeApacheBodyModule(ctx context.Context, s *Service, apache, prefix, build string) error {
	probe := filepath.Join(build, "abi-probe")
	if err := os.Mkdir(probe, 0700); err != nil {
		return err
	}
	tmp := filepath.Join(probe, "body-tmp")
	if err := os.Mkdir(tmp, 0700); err != nil {
		return err
	}
	global, err := renderApacheBodyGlobalRules(filepath.Join(prefix, "source"))
	if err != nil {
		return err
	}
	rules, err := renderApacheBodySiteRules(defaultWAFBodyPolicy(), filepath.Join(prefix, "source"), tmp, strings.Repeat("0", 32))
	if err != nil {
		return err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "ServerRoot %s\nServerName 127.0.0.1\nPidFile %s\nListen 127.0.0.1:19080\nErrorLog %s\nLogLevel error\n", strconv.Quote(apache), strconv.Quote(filepath.Join(probe, "httpd.pid")), strconv.Quote(filepath.Join(probe, "error.log")))
	for _, name := range []string{"mpm_event", "unixd", "authz_core", "log_config", "env", "unique_id"} {
		module := filepath.Join(apache, "modules/mod_"+name+".so")
		if err := ownedRuntimePath(module, false); err != nil {
			return err
		}
		fmt.Fprintf(&out, "LoadModule %s_module %s\n", name, strconv.Quote(module))
	}
	fmt.Fprintf(&out, "LoadModule security2_module %s\nSecRuleEngine Off\n%s<VirtualHost 127.0.0.1:19080>\nServerName private-abi.invalid\n%s</VirtualHost>\n", strconv.Quote(filepath.Join(prefix, "apache/mod_security2.so")), global, rules)
	conf := filepath.Join(probe, "httpd.conf")
	if err := atomicWrite(conf, []byte(out.String()), 0600); err != nil {
		return err
	}
	_, err = s.moduleCommand(ctx, 30*time.Second, filepath.Join(apache, "bin/httpd"), "-t", "-f", conf)
	return err
}
