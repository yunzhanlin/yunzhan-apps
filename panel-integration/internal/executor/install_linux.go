//go:build linux

package executor

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const installState = "/var/lib/panel-executor/installs"

// Native PHP builds include all reviewed extensions and may run on small
// servers or slower architecture-compatibility hosts. Keep a finite budget
// without silently publishing partial binaries; no client-supplied timeout.
func runtimeInstallTimeout(release runtimecatalog.Release) time.Duration {
	if release.Family == "php" {
		return 4 * time.Hour
	}
	return 110 * time.Minute
}

func acquireRuntimeBuildLock(ctx context.Context, file *os.File) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

type InstallStatus struct {
	ExtensionID string      `json:"extension_id,omitempty"`
	JobID       string      `json:"job_id"`
	ReleaseID   string      `json:"release_id"`
	State       string      `json:"state"`
	Error       string      `json:"error"`
	Steps       []core.Step `json:"steps"`
}
type RuntimeManifest struct {
	Release      runtimecatalog.Release `json:"release"`
	Architecture string                 `json:"architecture"`
	InstalledAt  string                 `json:"installed_at"`
	Extensions   []string               `json:"extensions"`
	Configure    []string               `json:"configure"`
}

func installPath(id string) string { return filepath.Join(installState, id+".json") }
func readInstall(id string) (InstallStatus, error) {
	var st InstallStatus
	if !core.ValidID(id) {
		return st, errors.New("无效任务标识")
	}
	b, e := os.ReadFile(installPath(id))
	if e == nil {
		e = json.Unmarshal(b, &st)
	}
	return st, e
}
func writeInstall(st InstallStatus) error {
	b, e := json.Marshal(st)
	if e != nil {
		return e
	}
	return atomicWrite(installPath(st.JobID), b, 0600)
}
func LoadRuntime(id string) (RuntimeManifest, error) {
	var m RuntimeManifest
	r, ok := runtimecatalog.Find(id)
	if !ok {
		return m, errors.New("版本不在已审核目录中")
	}
	b, e := os.ReadFile(filepath.Join(r.Prefix(), ".panel-runtime.json"))
	if e != nil {
		return m, e
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, e
	}
	if m.Release != r || m.Architecture != runtime.GOARCH {
		return m, errors.New("运行时清单与版本或架构不匹配")
	}
	binaries := []string{r.CLI()}
	if r.Family == "php" {
		binaries = append(binaries, r.FPM())
	}
	if r.Family == "mysql" {
		binaries = append(binaries, r.Prefix()+"/bin/mysqld", r.Prefix()+"/bin/mysqldump")
	}
	if r.Family == "mariadb" {
		binaries = append(binaries, r.Prefix()+"/bin/mariadbd", r.Prefix()+"/bin/mariadb-dump", r.Prefix()+"/scripts/mariadb-install-db")
	}
	if r.Family == "docker" {
		binaries = append(binaries, "/usr/libexec/docker/cli-plugins/docker-compose")
	}
	if r.Family == "redis" {
		binaries = append(binaries, r.Prefix()+"/bin/redis-cli")
	}
	if r.Family == "apache" {
		binaries = append(binaries, r.Prefix()+"/bin/apachectl")
	}
	for _, p := range binaries {
		if e = ordinary(p, false); e != nil {
			return m, e
		}
	}
	return m, nil
}
func startInstall(ctx context.Context, id, release string, retry bool) (InstallStatus, error) {
	return startInstallOperation(ctx, id, release, "", retry)
}
func startInstallOperation(ctx context.Context, id, release, extension string, retry bool) (InstallStatus, error) {
	st := InstallStatus{JobID: id, ReleaseID: release, ExtensionID: extension, State: "queued", Steps: []core.Step{}}
	lock, lockErr := runtimeUseLock()
	if lockErr != nil {
		return st, lockErr
	}
	defer lock.Close()
	if !core.ValidID(id) {
		return st, errors.New("无效任务标识")
	}
	if _, ok := runtimecatalog.Find(release); !ok {
		return st, errors.New("版本尚未支持安装")
	}
	if extension != "" {
		r, ok := runtimecatalog.Find(release)
		if !ok || r.Family != "php" {
			return st, errors.New("无效 PHP 版本")
		}
		if _, ok := runtimecatalog.FindExtension(extension); !ok {
			return st, errors.New("扩展不在固定版本目录中")
		}
		if _, e := LoadRuntime(release); e != nil {
			return st, errors.New("请先安装目标 PHP 版本")
		}
	}
	if e := os.MkdirAll(installState, 0700); e != nil {
		return st, e
	}
	old, e := readInstall(id)
	if e == nil {
		if old.ReleaseID != release || old.ExtensionID != extension {
			return st, errors.New("任务与版本不匹配")
		}
		active, _ := RunCommand(ctx, "/usr/bin/systemctl", "show", "-p", "ActiveState", "--value", "panel-install@"+id+".service")
		if strings.TrimSpace(active) == "activating" || strings.TrimSpace(active) == "active" {
			return old, nil
		}
		if old.State == "succeeded" {
			return old, nil
		}
		if old.State == "failed" && !retry {
			return old, nil
		}
	}
	if e = writeInstall(st); e != nil {
		return st, e
	}
	unit := "panel-install@" + id + ".service"
	if release, ok := runtimecatalog.Find(release); ok && release.Family == "docker" {
		unit = "panel-docker-install@" + id + ".service"
	}
	_, e = RunCommand(ctx, "/usr/bin/systemctl", "start", "--no-block", unit)
	return st, e
}

// InstallJob runs in a dedicated systemd service. Compile commands run as the
// unprivileged build account; only verified staged files are promoted as root.
func InstallJob(id string) (ret error) {
	st, e := readInstall(id)
	if e != nil {
		return e
	}
	r, ok := runtimecatalog.Find(st.ReleaseID)
	if !ok {
		return errors.New("unknown release")
	}
	st.State = "running"
	st.Error = ""
	add := func(msg string) error {
		st.Steps = append(st.Steps, core.Step{Time: core.Now(), Message: msg})
		return writeInstall(st)
	}
	defer func() {
		if ret != nil {
			st.State = "failed"
			st.Error = ret.Error()
			st.Steps = append(st.Steps, core.Step{Time: core.Now(), Message: ret.Error()})
		} else {
			st.State = "succeeded"
		}
		if e := writeInstall(st); e != nil && ret == nil {
			ret = e
		}
	}()
	if e = add("核对固定版本目录，等待源码构建锁"); e != nil {
		return e
	}
	lock, e := os.OpenFile("/var/lib/panel-executor/build.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	lockContext, lockCancel := context.WithTimeout(context.Background(), 30*time.Minute)
	e = acquireRuntimeBuildLock(lockContext, lock)
	lockCancel()
	if e != nil {
		return fmt.Errorf("等待源码构建锁失败（最多 30 分钟）；未开始安装: %w", e)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if st.ExtensionID != "" {
		ext, ok := runtimecatalog.FindExtension(st.ExtensionID)
		if !ok {
			return errors.New("扩展不在固定目录中")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		return installPHPExtension(ctx, r, ext, id, add)
	}
	if r.Family == "docker" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		return installDocker(ctx, r, id, add)
	}
	if _, e = LoadRuntime(r.ID); e == nil {
		return add("该精确版本已安装，核对清单与程序文件通过")
	}
	budget := runtimeInstallTimeout(r)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	defer func() {
		if ret != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			ret = fmt.Errorf("安装超过固定 %d 分钟时限；未发布不完整运行时，构建日志保留: %w", int(budget/time.Minute), ctx.Err())
		}
	}()
	if e = add(fmt.Sprintf("本次安装总时限 %d 分钟；超时即失败，不发布未校验程序", int(budget/time.Minute))); e != nil {
		return e
	}
	if r.Family == "mysql" {
		return installMySQL(ctx, r, id, add)
	}
	if r.Family == "mariadb" {
		return installMariaDB(ctx, r, id, add)
	}
	if r.Family == "redis" {
		return installRedis(ctx, r, id, add)
	}
	if r.Family == "node" {
		return installNode(ctx, r, id, add)
	}
	base := filepath.Join("/var/cache/panel-build", id)
	if e = os.MkdirAll(base, 0700); e != nil {
		return e
	}
	// The top-level directory is root-owned. The build user can only mutate work/.
	if e = os.Chmod(base, 0755); e != nil {
		return e
	}
	archive := filepath.Join(base, "source.tar.gz")
	if e = downloadRuntimeSource(ctx, r, archive); e != nil {
		return e
	}
	if e = add("已从官方站点下载源码，并通过目录中固定的 SHA-256 校验"); e != nil {
		return e
	}
	work := filepath.Join(base, "work")
	// Retry gets a clean, task-specific build tree; no sites or runtime data here.
	if e = os.RemoveAll(work); e != nil {
		return e
	}
	if e = os.Mkdir(work, 0755); e != nil {
		return e
	}
	if e = extractSource(archive, work); e != nil {
		return e
	}
	if _, e = RunCommand(ctx, "/usr/bin/chown", "-R", "panel-build:panel-build", work); e != nil {
		return e
	}
	sourceName := r.Family + "-" + r.Version
	if r.Family == "apache" {
		sourceName = "httpd-" + r.Version
	}
	source := filepath.Join(work, sourceName)
	stage := filepath.Join(work, "stage")
	flags := []string{"--prefix=" + r.Prefix(), "--with-config-file-path=" + r.Prefix() + "/etc", "--with-config-file-scan-dir=" + r.Prefix() + "/etc/conf.d", "--enable-fpm", "--disable-cgi", "--disable-phpdbg", "--without-pear", "--with-openssl", "--with-curl", "--with-zlib", "--enable-mbstring", "--enable-bcmath", "--enable-sockets", "--enable-pcntl", "--enable-exif", "--enable-ftp", "--with-mysqli=mysqlnd", "--with-pdo-mysql=mysqlnd", "--with-zip", "--enable-intl", "--enable-gd", "--with-jpeg", "--with-freetype"}
	if r.Family == "nginx" {
		flags = []string{"--prefix=" + r.Prefix(), "--sbin-path=" + r.CLI(), "--conf-path=/etc/nginx/nginx.conf", "--pid-path=/run/nginx.pid", "--error-log-path=/var/log/nginx/error.log", "--http-log-path=/var/log/nginx/access.log", "--user=www-data", "--group=www-data", "--with-compat", "--with-http_ssl_module", "--with-http_v2_module", "--with-http_stub_status_module", "--with-http_realip_module", "--with-http_gzip_static_module", "--with-threads", "--with-stream", "--with-stream_ssl_module"}
	}
	if r.Family == "apache" {
		flags = []string{"--prefix=" + r.Prefix(), "--enable-so", "--enable-ssl=shared", "--with-ssl", "--enable-http2=shared", "--enable-rewrite=shared", "--enable-remoteip=shared", "--enable-proxy=shared", "--enable-proxy-http=shared", "--enable-proxy-fcgi=shared", "--enable-headers=shared", "--enable-expires=shared", "--enable-deflate=shared", "--enable-status=shared", "--enable-mime=shared", "--enable-dir=shared", "--enable-log-config=shared", "--enable-unixd=shared", "--enable-mpms-shared=all", "--with-mpm=event"}
	}
	logPath := filepath.Join(base, "build.log")
	if e = add("以独立构建用户配置精确版本及固定模块"); e != nil {
		return e
	}
	if e = buildCommand(ctx, source, logPath, source+"/configure", flags...); e != nil {
		return e
	}
	jobs := runtimeBuildJobs()
	if e = add(fmt.Sprintf("开始源码编译（%d 个并行任务）；完整构建日志保存在专用缓存目录", jobs)); e != nil {
		return e
	}
	if e = buildCommand(ctx, source, logPath, "/usr/bin/make", "-j"+strconv.Itoa(jobs)); e != nil {
		return e
	}
	if e = add("编译完成，安装到暂存目录"); e != nil {
		return e
	}
	stageArg := "INSTALL_ROOT=" + stage
	if r.Family == "nginx" || r.Family == "apache" {
		stageArg = "DESTDIR=" + stage
	}
	if e = buildCommand(ctx, source, logPath, "/usr/bin/make", "install", stageArg); e != nil {
		return e
	}
	staged := filepath.Join(stage, r.Prefix())
	if _, e = os.Stat(r.Prefix()); e == nil {
		return errors.New("目标目录已存在但没有匹配的完整清单，请核对后重试")
	}
	parent := filepath.Dir(r.Prefix())
	if e = os.MkdirAll(parent, 0755); e != nil {
		return e
	}
	temp := r.Prefix() + ".pending-" + id
	if e = os.RemoveAll(temp); e != nil {
		return e
	}
	if e = copyBuildTree(staged, temp); e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	if r.Family == "php" {
		if e = os.MkdirAll(filepath.Join(temp, "etc/conf.d"), 0755); e != nil {
			return e
		}
		ini := []byte("expose_php=Off\nmemory_limit=128M\nmax_execution_time=60\ndisplay_errors=Off\nlog_errors=On\ndate.timezone=UTC\ncgi.fix_pathinfo=0\nsession.cookie_httponly=1\n")
		if e = atomicWrite(filepath.Join(temp, "etc/php.ini"), ini, 0644); e != nil {
			return e
		}
	}
	candidate := filepath.Join(temp, strings.TrimPrefix(r.CLI(), r.Prefix()+"/"))
	manifest := RuntimeManifest{Release: r, Architecture: runtime.GOARCH, InstalledAt: core.Now(), Extensions: []string{}, Configure: flags}
	if r.Family == "nginx" {
		version, er := RunCommand(ctx, candidate, "-V")
		if er != nil || !strings.Contains(version, "nginx/"+r.Version) {
			return fmt.Errorf("Nginx 精确版本校验失败: %v", er)
		}
		for _, flag := range flags {
			if strings.HasPrefix(flag, "--with-") {
				if !strings.Contains(version, flag) {
					return fmt.Errorf("Nginx 缺少构建模块 %s", flag)
				}
				manifest.Extensions = append(manifest.Extensions, strings.TrimPrefix(flag, "--with-"))
			}
		}
	} else if r.Family == "apache" {
		version, er := RunCommand(ctx, candidate, "-v")
		if er != nil || !strings.Contains(version, "Apache/"+r.Version) {
			return fmt.Errorf("Apache 精确版本校验失败: %v", er)
		}
		for _, module := range []string{"mod_ssl.so", "mod_http2.so", "mod_rewrite.so", "mod_proxy.so", "mod_proxy_http.so", "mod_proxy_fcgi.so", "mod_headers.so", "mod_expires.so", "mod_deflate.so", "mod_status.so"} {
			if e = ordinary(filepath.Join(temp, "modules", module), false); e != nil {
				return fmt.Errorf("Apache 缺少构建模块 %s: %w", module, e)
			}
			manifest.Extensions = append(manifest.Extensions, strings.TrimSuffix(strings.TrimPrefix(module, "mod_"), ".so"))
		}
	} else {
		version, e := RunCommand(ctx, candidate, "-n", "-r", "echo PHP_VERSION;")
		if e != nil || version != r.Version {
			return fmt.Errorf("CLI 版本核对失败: %s: %v", version, e)
		}
		modules, e := RunCommand(ctx, candidate, "-n", "-m")
		if e != nil {
			return e
		}
		for _, line := range strings.Split(modules, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "[") {
				manifest.Extensions = append(manifest.Extensions, line)
			}
		}
		for _, required := range []string{"mysqli", "pdo_mysql", "mbstring", "curl", "openssl", "zip", "intl", "gd"} {
			if !strings.Contains("\n"+modules, "\n"+required+"\n") {
				return fmt.Errorf("缺少必需扩展 %s", required)
			}
		}
	}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	if e = atomicWrite(filepath.Join(temp, ".panel-runtime.json"), b, 0644); e != nil {
		return e
	}
	if e = os.Rename(temp, r.Prefix()); e != nil {
		return e
	}
	return add("独立目录安装完成；精确版本与固定构建模块核对通过")
}

type sourceHTTPError struct{ Status int }

func (e sourceHTTPError) Error() string { return fmt.Sprintf("源码服务器 HTTP %d", e.Status) }

func downloadRuntimeSource(ctx context.Context, r runtimecatalog.Release, dst string) error {
	err := downloadVerified(ctx, r.URL, r.SHA256, dst)
	var status sourceHTTPError
	if errors.As(err, &status) && (status.Status == 404 || status.Status == 410) {
		if archive := runtimecatalog.SourceArchiveURL(r); archive != "" {
			return downloadVerified(ctx, archive, r.SHA256, dst)
		}
	}
	return err
}

func downloadVerified(ctx context.Context, url, digest, dst string) error {
	client := &http.Client{Timeout: 8 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 || req.URL.Scheme != "https" || (req.URL.Host != "www.php.net" && req.URL.Host != "nginx.org" && req.URL.Host != "downloads.apache.org" && req.URL.Host != "archive.apache.org" && req.URL.Host != "pecl.php.net" && req.URL.Host != "download.redis.io" && req.URL.Host != "nodejs.org" && req.URL.Host != "download.pureftpd.org") {
			return errors.New("源码下载重定向超出允许来源")
		}
		return nil
	}}
	if strings.HasPrefix(url, "https://download.pureftpd.org/") {
		// The upstream mirror can reset HTTP/2 streams during source transfers.
		// HTTPS/1.1 keeps normal certificate and complete digest verification.
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.ForceAttemptHTTP2 = false
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		transport.Protocols = new(http.Protocols)
		transport.Protocols.SetHTTP1(true)
		client.Transport = transport
		defer transport.CloseIdleConnections()
	}
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return e
	}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return sourceHTTPError{Status: resp.StatusCode}
	}
	f, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 64*1024*1024+1))
	if e != nil {
		return e
	}
	if n > 64*1024*1024 {
		return errors.New("源码包超过限制")
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("源码 SHA-256 不匹配，拒绝执行")
	}
	return f.Sync()
}
func extractSource(archive, dest string) error {
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	count := 0
	for {
		h, e := tr.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		count++
		if h.Size < 0 || h.Size > 512*1024*1024-total {
			return errors.New("源码归档超过解压限制")
		}
		total += h.Size
		if count > 100000 || total > 512*1024*1024 || h.Size < 0 {
			return errors.New("源码归档超过解压限制")
		}
		clean := filepath.Clean(h.Name)
		if !filepath.IsLocal(clean) {
			return errors.New("源码归档路径越界")
		}
		target := filepath.Join(dest, clean)
		switch h.Typeflag {
		case tar.TypeXHeader, tar.TypeXGlobalHeader:
			// archive/tar applies PAX records to the following header. They do
			// not create a filesystem object; the resulting name and link are
			// still checked by the normal path boundary below.
			continue
		case tar.TypeDir:
			if e = os.MkdirAll(target, 0755); e != nil {
				return e
			}
		case tar.TypeReg, tar.TypeRegA:
			if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
				return e
			}
			mode := os.FileMode(0644)
			if h.Mode&0111 != 0 {
				mode = 0755
			}
			out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if e != nil {
				return e
			}
			_, e = io.CopyN(out, tr, h.Size)
			ce := out.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		case tar.TypeSymlink:
			link := filepath.Clean(h.Linkname)
			resolved := filepath.Clean(filepath.Join(filepath.Dir(clean), link))
			if filepath.IsAbs(link) || !filepath.IsLocal(resolved) {
				return fmt.Errorf("源码归档链接越界: %s", h.Name)
			}
			if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
				return e
			}
			if e = os.Symlink(h.Linkname, target); e != nil {
				return e
			}
		default:
			return fmt.Errorf("源码归档包含不允许的链接或文件类型: %s", h.Name)
		}
	}
}
func buildCommand(ctx context.Context, dir, logPath, name string, args ...string) error {
	file, e := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer file.Close()
	argv := append([]string{"-u", "panel-build", "--", name}, args...)
	cmd := exec.CommandContext(ctx, "/usr/sbin/runuser", argv...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "CFLAGS=-O2", "HOME=" + filepath.Dir(dir), "MAKEFLAGS="}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 3 * time.Second
	out := &boundedBuffer{max: 24 * 1024}
	stat, _ := file.Stat()
	remaining := int64(64 * 1024 * 1024)
	if stat != nil {
		remaining -= stat.Size()
	}
	cmd.Stdout = io.MultiWriter(&cappedLog{File: file, Remaining: remaining}, out)
	cmd.Stderr = cmd.Stdout
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("%s 执行失败: %w；查看 %s", filepath.Base(name), e, logPath)
	}
	return nil
}
func copyBuildTree(src, dest string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		target := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		if d.Type()&os.ModeSymlink != 0 {
			link, er := os.Readlink(path)
			if er != nil {
				return er
			}
			resolved, er := filepath.EvalSymlinks(path)
			if er != nil {
				return er
			}
			inside, er := filepath.Rel(src, resolved)
			if er != nil || !filepath.IsLocal(inside) {
				return fmt.Errorf("构建链接越界: %s", rel)
			}
			st, er := os.Stat(resolved)
			if er != nil || !st.Mode().IsRegular() {
				return fmt.Errorf("构建链接目标不是普通文件: %s", rel)
			}
			if er = os.MkdirAll(filepath.Dir(target), 0755); er != nil {
				return er
			}
			return os.Symlink(link, target)
		} else if !d.Type().IsRegular() {
			return fmt.Errorf("构建输出含特殊文件: %s", rel)
		}
		st, e := os.Stat(path)
		if e != nil {
			return e
		}
		if st.Size() > 256*1024*1024 {
			return errors.New("构建输出文件超过复制限制")
		}
		mode := os.FileMode(0644)
		if st.Mode()&0111 != 0 {
			mode = 0755
		}
		in, e := os.Open(path)
		if e != nil {
			return e
		}
		defer in.Close()
		out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if e != nil {
			return e
		}
		_, e = io.Copy(out, io.LimitReader(in, 256*1024*1024))
		ce := out.Close()
		if e != nil {
			return e
		}
		return ce
	})
}

type cappedLog struct {
	File      *os.File
	Remaining int64
}

func (w *cappedLog) Write(p []byte) (int, error) {
	n := len(p)
	if w.Remaining <= 0 {
		return n, nil
	}
	part := p
	if int64(len(part)) > w.Remaining {
		part = part[:w.Remaining]
	}
	written, e := w.File.Write(part)
	w.Remaining -= int64(written)
	if e != nil {
		return written, e
	}
	return n, nil
}
