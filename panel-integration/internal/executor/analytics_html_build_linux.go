//go:build linux

package executor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
)

const analyticsHTMLBuilds = "/var/lib/panel-executor/analytics-html-builds"
const analyticsHTMLBuildCache = "/var/cache/panel-analytics-html-build"
const analyticsHTMLRequests = "/var/lib/panel-executor/analytics-html-requests"
const analyticsHTMLCancellations = "/var/lib/panel-executor/analytics-html-cancellations"

var analyticsHTMLBuildDependencies = []string{"build-essential", "pkg-config", "libpcre2-dev", "libssl-dev", "zlib1g-dev"}

type analyticsHTMLBuildRecord struct {
	analyticsHTMLEngineIdentity
	NginxVersion   string            `json:"nginx_version"`
	SourceSHA      map[string]string `json:"source_sha256"`
	PatchSourceSHA string            `json:"patch_original_source_sha256"`
	StartedAt      string            `json:"started_at"`
	FinishedAt     string            `json:"finished_at,omitempty"`
	Error          string            `json:"error,omitempty"`
	Steps          []core.Step       `json:"steps"`
	ABIValidated   bool              `json:"module_abi_validated"`
}

func readAnalyticsHTMLBuild(id string) (analyticsHTMLBuildRecord, error) {
	var record analyticsHTMLBuildRecord
	if !core.ValidID(id) {
		return record, errors.New("HTML 引擎构建标识无效")
	}
	path := filepath.Join(analyticsHTMLBuilds, id+".json")
	if err := readAnalyticsHTMLPrivateJSON(path, 64<<10, &record); err != nil {
		return record, err
	}
	if record.JobID != id {
		return record, errors.New("HTML 引擎构建记录身份不匹配")
	}
	return record, nil
}

func readAnalyticsHTMLPrivateJSON(path string, limit int64, out any) error {
	if err := ownedRuntimePath(path, false); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit || st.Mode().Perm() != 0600 {
		return errors.New("HTML 引擎记录类型、大小或权限异常")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("HTML 引擎记录具有共享链接")
	}
	d := json.NewDecoder(io.LimitReader(f, limit+1))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("HTML 引擎记录存在额外数据")
	}
	after, statErr := f.Stat()
	current, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(st, current) || st.Size() != after.Size() || !st.ModTime().Equal(after.ModTime()) || st.Mode() != after.Mode() || st.Mode() != current.Mode() {
		return errors.New("HTML 引擎记录读取期间被修改或替换")
	}
	for _, info := range []os.FileInfo{after, current} {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != stat.Uid || owner.Gid != stat.Gid || owner.Nlink != 1 {
			return errors.New("HTML 引擎记录所有者或链接数在读取期间改变")
		}
	}
	return nil
}

func createAnalyticsHTMLPrivateJSON(path string, value any) error {
	if err := ownedRuntimePath(filepath.Dir(path), true); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > 64<<10 {
		return errors.New("HTML 引擎记录编码失败或超限")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
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

func analyticsHTMLBuildContract(record analyticsHTMLBuildRecord) error {
	if record.Format != 1 || !core.ValidID(record.JobID) || record.State != "ready" || record.Error != "" || record.Architecture != runtime.GOARCH || record.Prefix != filepath.Join(analyticsHTMLNativeRoot, record.JobID) || record.ProgramSHA != analyticsHTMLProgramSHA || record.PatchSourceSHA != analyticsNJSHeaderSourceSHA || !record.ABIValidated {
		return errors.New("HTML 引擎尚未完成、架构或固定发布身份不符")
	}
	sources, ok := analyticsHTMLSources(record.NginxVersion)
	if !ok || len(record.SourceSHA) != len(sources) {
		return errors.New("HTML 引擎源码来源不完整")
	}
	for _, source := range sources {
		if record.SourceSHA[source.Name] != source.SHA256 {
			return errors.New("HTML 引擎源码摘要不在本发布清单")
		}
	}
	for _, digest := range []string{record.NginxSHA, record.ModuleSHA, record.TreeSHA} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || strings.ToLower(digest) != digest {
			return errors.New("HTML 引擎完整摘要缺失")
		}
	}
	start, err := time.Parse(time.RFC3339, record.StartedAt)
	if err != nil {
		return errors.New("HTML 引擎开始时间无效")
	}
	finish, err := time.Parse(time.RFC3339, record.FinishedAt)
	if err != nil || finish.Before(start) || len(record.Steps) == 0 || len(record.Steps) > 32 {
		return errors.New("HTML 引擎结束时间或审计步骤无效")
	}
	return nil
}

func (s *Service) verifyAnalyticsHTMLBuild(ctx context.Context, id string) (analyticsHTMLBuildRecord, error) {
	record, err := readAnalyticsHTMLBuild(id)
	if err != nil {
		return record, err
	}
	if err := analyticsHTMLBuildContract(record); err != nil {
		return record, err
	}
	nginx, err := s.nginxBinary()
	if err != nil || nginx != record.NginxBinary {
		return record, errors.New("实际 Nginx 已改变，不能选用旧 HTML 引擎")
	}
	for _, entry := range []struct {
		path, sha string
		limit     int64
	}{
		{nginx, record.NginxSHA, 32 << 20},
		{filepath.Join(record.Prefix, "ngx_http_js_module.so"), record.ModuleSHA, 32 << 20},
		{filepath.Join(record.Prefix, "analytics-html.js"), analyticsHTMLProgramSHA, 1 << 20},
	} {
		if sha, err := analyticsHTMLFileSHA(ctx, entry.path, entry.limit); err != nil || sha != entry.sha {
			return record, errors.New("HTML 引擎或实际 Nginx 摘要变化")
		}
	}
	if sha, err := runtimeTreeSHA(ctx, record.Prefix, record.Prefix); err != nil || sha != record.TreeSHA {
		return record, errors.New("HTML 引擎程序树完整性校验失败")
	}
	return record, nil
}

// Independent build only. It cannot write /etc, reload nginx, alter a site's
// settings or mark itself active. Activation is a separate guarded operation.
func RunAnalyticsHTMLBuild(id string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAnalyticsHTMLBuild(ctx, id)
}

func runAnalyticsHTMLBuild(parent context.Context, id string) (err error) {
	if os.Geteuid() != 0 || !core.ValidID(id) {
		return errors.New("HTML 引擎仅允许专用 root 服务及有效任务标识")
	}
	if err := readWAFEngineControl(analyticsHTMLRequests, id); err != nil {
		return errors.New("HTML 构建缺少本面板持久请求，未开始构建")
	}
	if err := readWAFEngineControl(analyticsHTMLCancellations, id); err == nil {
		return errors.New("HTML 构建已停止，不重用原任务")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Hour)
	defer cancel()
	s := nativeWAFService()
	for _, directory := range []string{analyticsHTMLBuilds, analyticsHTMLBuildCache, filepath.Dir(analyticsHTMLNativeRoot), analyticsHTMLNativeRoot} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err := ownedRuntimePath(directory, true); err != nil {
			return err
		}
		mode := os.FileMode(0755)
		if directory == analyticsHTMLBuilds {
			mode = 0700
		}
		if err := os.Chmod(directory, mode); err != nil {
			return err
		}
	}
	for _, budget := range []struct {
		path string
		max  int
	}{{analyticsHTMLBuilds, 64}, {analyticsHTMLNativeRoot, 16}} {
		if entries, err := os.ReadDir(budget.path); err != nil || len(entries) >= budget.max {
			return errors.New("HTML 引擎记录或程序目录已满，保留证据，不自动删除")
		}
	}
	jobPath := filepath.Join(analyticsHTMLBuilds, id+".json")
	record := analyticsHTMLBuildRecord{analyticsHTMLEngineIdentity: analyticsHTMLEngineIdentity{Format: 1, JobID: id, State: "building", Architecture: runtime.GOARCH, Prefix: filepath.Join(analyticsHTMLNativeRoot, id), ProgramSHA: analyticsHTMLProgramSHA}, SourceSHA: map[string]string{}, PatchSourceSHA: analyticsNJSHeaderSourceSHA, StartedAt: core.Now(), Steps: []core.Step{}}
	if err := createAnalyticsHTMLPrivateJSON(jobPath, record); err != nil {
		return err
	}
	defer func() {
		record.FinishedAt = core.Now()
		if err != nil {
			record.State = "failed"
			record.Error = err.Error()
		}
		err = errors.Join(err, moduleWrite(jobPath, record))
	}()
	step := func(message string) error {
		if len(record.Steps) >= 32 {
			return errors.New("HTML 构建审计步骤达到上限")
		}
		record.Steps = append(record.Steps, core.Step{Time: core.Now(), Message: message})
		return moduleWrite(jobPath, record)
	}
	if err := step("核对实际 Nginx 程序、固定源码和非特权编译依赖"); err != nil {
		return err
	}
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	version, err := s.moduleCommand(ctx, 10*time.Second, nginx, "-v")
	match := wafNginxVersionPattern.FindStringSubmatch(strings.TrimSpace(version))
	if err != nil || len(match) != 2 {
		return errors.New("无法核对实际 Nginx 版本")
	}
	sources, ok := analyticsHTMLSources(match[1])
	if !ok {
		return errors.New("实际 Nginx 缺少精确审核源码，不替换现有程序")
	}
	if !s.wafBuildPackagesReady(analyticsHTMLBuildDependencies) {
		return errors.New("固定编译依赖尚未就绪，未开始下载或编译")
	}
	record.NginxBinary, record.NginxVersion = nginx, match[1]
	if record.NginxSHA, err = analyticsHTMLFileSHA(ctx, nginx, 32<<20); err != nil {
		return err
	}
	if err := step("等待全局构建锁；不会并行挤占其他运行时编译"); err != nil {
		return err
	}
	lock, err := os.OpenFile("/var/lib/panel-executor/build.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	lockCtx, unlock := context.WithTimeout(ctx, 30*time.Minute)
	err = acquireRuntimeBuildLock(lockCtx, lock)
	unlock()
	if err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := wafBuildDiskBudget(analyticsHTMLBuildCache); err != nil {
		return err
	}
	build := filepath.Join(analyticsHTMLBuildCache, id)
	if err := os.Mkdir(build, 0755); err != nil {
		return err
	}
	if err := os.Chmod(build, 0755); err != nil {
		return err
	}
	archives := filepath.Join(build, "archives")
	if err := os.Mkdir(archives, 0755); err != nil {
		return err
	}
	if err := os.Chmod(archives, 0755); err != nil {
		return err
	}
	names := []string{"njs-1.0.1.tar.gz", "quickjs-" + analyticsQuickJSCommit + ".tar.gz", "nginx-" + match[1] + ".tar.gz"}
	for i, source := range sources {
		if err := step("下载并固定摘要校验：" + source.Name); err != nil {
			return err
		}
		if err := downloadAnalyticsHTMLSource(ctx, source, filepath.Join(archives, names[i])); err != nil {
			return err
		}
		record.SourceSHA[source.Name] = source.SHA256
	}
	program := filepath.Join(build, "program")
	if err := buildAnalyticsHTMLModule(ctx, s, archives, filepath.Join(build, "work"), program, match[1], nginx, step); err != nil {
		return err
	}
	if err := step("发布新的只读独立程序及完整许可；不改动网站或 Nginx 服务"); err != nil {
		return err
	}
	if err := publishAnalyticsHTMLProgram(ctx, program, record.Prefix); err != nil {
		return err
	}
	if err := publishAnalyticsHTMLSharedProgram(ctx, record.Prefix); err != nil {
		return err
	}
	selected, err := s.nginxBinary()
	if err != nil || selected != nginx {
		return errors.New("构建期间 Nginx 选择改变，拒绝选用该引擎")
	}
	if sha, err := analyticsHTMLFileSHA(ctx, nginx, 32<<20); err != nil || sha != record.NginxSHA {
		return errors.New("构建期间实际 Nginx 内容改变")
	}
	if record.ModuleSHA, err = analyticsHTMLFileSHA(ctx, filepath.Join(record.Prefix, "ngx_http_js_module.so"), 32<<20); err != nil {
		return err
	}
	if record.TreeSHA, err = runtimeTreeSHA(ctx, record.Prefix, record.Prefix); err != nil {
		return err
	}
	// Never expose "ready" before the finish timestamp used by its strict
	// verifier is durable; a polling worker must not misclassify this window.
	record.FinishedAt = core.Now()
	record.State, record.ABIValidated = "ready", true
	return step("独立 ABI、程序摘要及许可已核对；尚未全局加载或自动接入网站")
}

func publishAnalyticsHTMLProgram(ctx context.Context, source, destination string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	allowed := map[string]int64{"ngx_http_js_module.so": 32 << 20, "analytics-html.js": 1 << 20, "source.json": 64 << 10, "parse5-LICENSE": 32 << 10, "entities-LICENSE": 32 << 10, "njs-LICENSE": 32 << 10, "nginx-LICENSE": 32 << 10, "quickjs-LICENSE": 32 << 10, "yunzhan-njs-validator-patch.txt": 32 << 10}
	if len(entries) != len(allowed) {
		return errors.New("HTML 程序发布清单不完整或包含未知文件")
	}
	for _, entry := range entries {
		if allowed[entry.Name()] == 0 || entry.IsDir() {
			return errors.New("HTML 程序发布包含未知条目")
		}
		if _, err := analyticsHTMLFileSHA(ctx, filepath.Join(source, entry.Name()), allowed[entry.Name()]); err != nil {
			return err
		}
	}
	if err := ownedRuntimePath(filepath.Dir(destination), true); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0755); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0755); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := copyWAFNativeFile(ctx, filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name()), allowed[entry.Name()], os.Geteuid()); err != nil {
			return fmt.Errorf("保留不完整新程序供核查，不覆盖旧程序：%w", err)
		}
		// The dedicated service uses UMask=0077; immutable code/licenses must
		// nevertheless remain readable by the Nginx worker after publication.
		if err := os.Chmod(filepath.Join(destination, entry.Name()), 0644); err != nil {
			return err
		}
	}
	before, err := runtimeTreeSHA(ctx, source, source)
	if err != nil {
		return err
	}
	after, err := runtimeTreeSHA(ctx, destination, destination)
	if err != nil || before != after {
		return errors.New("HTML 程序副本完整字节、权限或所有者不一致")
	}
	d, err := os.Open(destination)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func publishAnalyticsHTMLSharedProgram(ctx context.Context, prefix string) error {
	if err := os.MkdirAll(analyticsHTMLProgramRoot, 0755); err != nil {
		return err
	}
	if err := ownedRuntimePath(analyticsHTMLProgramRoot, true); err != nil {
		return err
	}
	if err := os.Chmod(analyticsHTMLProgramRoot, 0755); err != nil {
		return err
	}
	path := analyticsHTMLProgramPath()
	if _, err := os.Lstat(path); err == nil {
		sha, err := analyticsHTMLFileSHA(ctx, path, 1<<20)
		if err != nil || sha != analyticsHTMLProgramSHA {
			return errors.New("已存在的共享 HTML 程序摘要异常，未覆盖")
		}
		st, err := os.Lstat(path)
		if err != nil || st.Mode().Perm() != 0644 || st.Sys().(*syscall.Stat_t).Nlink != 1 {
			return errors.New("已存在的共享 HTML 程序权限或链接异常，未修复或覆盖")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := copyWAFNativeFile(ctx, filepath.Join(prefix, "analytics-html.js"), path, 1<<20, os.Geteuid()); err != nil {
		return err
	}
	if err := os.Chmod(path, 0644); err != nil {
		return err
	}
	if sha, err := analyticsHTMLFileSHA(ctx, path, 1<<20); err != nil || sha != analyticsHTMLProgramSHA {
		return errors.New("新共享 HTML 程序摘要不匹配；保留证据且不启用")
	}
	d, err := os.Open(analyticsHTMLProgramRoot)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
