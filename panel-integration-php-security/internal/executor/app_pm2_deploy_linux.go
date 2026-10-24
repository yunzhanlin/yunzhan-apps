//go:build linux

package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

type pm2Deployment struct {
	ID                  string `json:"id"`
	AppID               string `json:"app_id"`
	SiteID              string `json:"site_id"`
	Revision            int64  `json:"revision"`
	State               string `json:"state"`
	CreatedAt           string `json:"created_at"`
	FinishedAt          string `json:"finished_at,omitempty"`
	Error               string `json:"error,omitempty"`
	PackageSHA          string `json:"package_sha256"`
	LockSHA             string `json:"lock_sha256"`
	Package             []byte `json:"package,omitempty"`
	Lock                []byte `json:"lock,omitempty"`
	BackupPath          string `json:"backup_path,omitempty"`
	WasActive           bool   `json:"was_active,omitempty"`
	AllowInstallScripts bool   `json:"allow_install_scripts"`
	OldDevice           uint64 `json:"old_device,omitempty"`
	OldInode            uint64 `json:"old_inode,omitempty"`
	NewDevice           uint64 `json:"new_device,omitempty"`
	NewInode            uint64 `json:"new_inode,omitempty"`
}

func (s *Service) pm2DeploymentPath(id string) string {
	return filepath.Join(s.moduleDir("pm2-manager"), "deployments", id+".json")
}
func publicPM2Deployment(job pm2Deployment) pm2Deployment {
	job.Package = nil
	job.Lock = nil
	job.OldDevice = 0
	job.OldInode = 0
	job.NewDevice = 0
	job.NewInode = 0
	return job
}

func (s *Service) lockPM2Project(id string) (*os.File, error) {
	if !moduleResourceID.MatchString(id) {
		return nil, errors.New("PM2 标识无效")
	}
	dir := filepath.Join(s.moduleDir("pm2-manager"), "locks")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, id+".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("该项目正在部署依赖，请先查看部署结果")
	}
	return f, nil
}

func readPM2Package(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := regularFile(root, name)
	if err != nil {
		return nil, errors.New("需要网站根目录中的 package.json 和 package-lock.json 普通文件")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("依赖清单超过安全大小上限")
	}
	return raw, nil
}

// Only frozen public-registry tarballs are accepted, never git/file links,
// credentials, private registries, project npmrc or executable install hooks.
func validatePM2Packages(manifest, lock []byte) error {
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		Workspaces           json.RawMessage   `json:"workspaces"`
	}
	var locked struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
			Link      bool   `json:"link"`
			InBundle  bool   `json:"inBundle"`
		} `json:"packages"`
	}
	if json.Unmarshal(manifest, &pkg) != nil || json.Unmarshal(lock, &locked) != nil || locked.LockfileVersion < 2 || locked.LockfileVersion > 3 || locked.Packages == nil {
		return errors.New("需要有效的 package.json 及 v2/v3 npm 锁定文件")
	}
	if len(locked.Packages) > 10000 {
		return errors.New("依赖树超过 10000 个包")
	}
	if len(pkg.Workspaces) > 0 && string(pkg.Workspaces) != "null" {
		return errors.New("工作区依赖需要单独构建，不能作为锁定目录部署")
	}
	namePattern := regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
	versionPattern := regexp.MustCompile(`^[0-9v*~^<>=][0-9A-Za-z.+*~^<>=| -]{0,127}$`)
	for _, dependencies := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		for name, version := range dependencies {
			if !namePattern.MatchString(name) || len(name) > 214 || !versionPattern.MatchString(version) {
				return errors.New("清单只能使用 npm 包名和版本范围，拒绝 URL、git、file 与别名源")
			}
		}
	}
	for path, item := range locked.Packages {
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "node_modules/") || strings.Contains(path, "\\") || strings.ContainsAny(path, "\x00\r\n") || filepath.Clean(path) != path || strings.HasPrefix(path, "/") || strings.Contains(path, "/../") || item.Link {
			return errors.New("锁定文件包含本地链接或非法包路径")
		}
		if item.InBundle && item.Resolved == "" {
			continue
		}
		u, err := url.Parse(item.Resolved)
		if err != nil || u.Scheme != "https" || u.Host != "registry.npmjs.org" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, ".tgz") {
			return errors.New("只接受公共 npm HTTPS 注册表内的锁定包，拒绝自定义源与凭据")
		}
		sha, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(item.Integrity, "sha512-"))
		if err != nil || !strings.HasPrefix(item.Integrity, "sha512-") || len(sha) != 64 {
			return errors.New("依赖包缺少 SHA-512 完整性摘要")
		}
	}
	return nil
}

func (s *Service) pm2LastDeployment(id string) (pm2Deployment, error) {
	var job pm2Deployment
	err := moduleRead(filepath.Join(s.moduleDir("pm2-manager"), "deployments", id+"-latest.json"), &job)
	if err == nil && (job.AppID != id || !core.ValidID(job.ID)) {
		err = errors.New("依赖部署记录身份不匹配")
	}
	if err != nil {
		return job, err
	}
	err = moduleRead(s.pm2DeploymentPath(job.ID), &job)
	if err == nil && (job.AppID != id || !core.ValidID(job.ID) || !core.ValidID(job.SiteID)) {
		err = errors.New("依赖部署记录身份不匹配")
	}
	return job, err
}

func (s *Service) pm2DeploymentStatus(ctx context.Context, id string) (any, error) {
	job, err := s.pm2LastDeployment(id)
	if os.IsNotExist(err) {
		return map[string]any{"deployment": nil}, nil
	}
	if err != nil {
		return nil, err
	}
	state, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pm2-deploy@"+job.ID)
	return map[string]any{"deployment": publicPM2Deployment(job), "service_state": strings.TrimSpace(state)}, nil
}

func (s *Service) archivePM2Deployments(appID string) (any, error) {
	latest, err := s.pm2LastDeployment(appID)
	if os.IsNotExist(err) {
		return map[string]any{"archived": 0}, nil
	}
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(s.moduleDir("pm2-manager"), "deployments")
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = root.MkdirAll("archive", 0700); err != nil {
		return nil, err
	}
	parent, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	archive, err := root.Open("archive")
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	count := 0
	for _, path := range paths {
		id := strings.TrimSuffix(filepath.Base(path), ".json")
		if !core.ValidID(id) || id == latest.ID {
			continue
		}
		var job pm2Deployment
		if err = moduleRead(path, &job); err != nil {
			return nil, err
		}
		if job.AppID != appID || job.ID != id || (job.State != "succeeded" && job.State != "failed") {
			continue
		}
		if err = unix.Renameat2(int(parent.Fd()), id+".json", int(archive.Fd()), id+".json", unix.RENAME_NOREPLACE); err != nil {
			return nil, errors.New("归档记录已存在或不可写，未覆盖原记录")
		}
		count++
		if _, err = root.Lstat(id + ".npm.log"); err == nil {
			if err = unix.Renameat2(int(parent.Fd()), id+".npm.log", int(archive.Fd()), id+".npm.log", unix.RENAME_NOREPLACE); err != nil {
				return nil, errors.New("记录已归档，诊断日志仍保留在原目录")
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return map[string]any{"archived": count, "records_retained": true, "dependency_directories_retained": true}, nil
}

func (s *Service) queuePM2Dependencies(ctx context.Context, app pm2App, revision int64, allowScripts ...bool) (any, error) {
	if revision != app.Revision {
		return nil, errors.New("PM2 配置已变化，请重新选择项目")
	}
	if old, err := s.pm2LastDeployment(app.ID); err == nil {
		if old.State == "queued" || old.State == "running" || old.State == "switching" || old.State == "needs_attention" {
			return nil, errors.New("旧部署尚未完成或需要检查，请先查看部署记录；不会覆盖旧记录")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := s.openFiles(app.SiteID)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	manifest, err := readPM2Package(f.public, "package.json", 64<<10)
	if err != nil {
		return nil, err
	}
	lock, err := readPM2Package(f.public, "package-lock.json", 2<<20)
	if err != nil {
		return nil, err
	}
	if err = validatePM2Packages(manifest, lock); err != nil {
		return nil, err
	}
	paths, err := filepath.Glob(filepath.Join(s.moduleDir("pm2-manager"), "deployments", "*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) >= 256 {
		return nil, errors.New("部署历史已达安全上限，保留现有记录；请归档核对后继续")
	}
	job := pm2Deployment{ID: core.ID(), AppID: app.ID, SiteID: app.SiteID, Revision: app.Revision, State: "queued", CreatedAt: core.Now(), PackageSHA: core.Hash(string(manifest)), LockSHA: core.Hash(string(lock)), Package: manifest, Lock: lock}
	job.AllowInstallScripts = len(allowScripts) > 0 && allowScripts[0]
	if err = moduleWrite(s.pm2DeploymentPath(job.ID), job); err != nil {
		return nil, err
	}
	if err = moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "deployments", app.ID+"-latest.json"), publicPM2Deployment(job)); err != nil {
		return nil, err
	}
	if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "start", "--no-block", "panel-pm2-deploy@"+job.ID); err != nil {
		job.State = "failed"
		job.Error = "依赖部署服务未能启动"
		job.FinishedAt = core.Now()
		_ = moduleWrite(s.pm2DeploymentPath(job.ID), job)
		return nil, err
	}
	return map[string]any{"deployment": publicPM2Deployment(job)}, nil
}

func RunPM2Dependencies(id string) (err error) {
	if !core.ValidID(id) {
		return errors.New("部署标识无效")
	}
	s := New(Config{SitesDir: "/srv/panel/sites"})
	var job pm2Deployment
	if err = moduleRead(s.pm2DeploymentPath(id), &job); err != nil {
		return err
	}
	if job.ID != id || !moduleResourceID.MatchString(job.AppID) || !core.ValidID(job.SiteID) || job.State != "queued" {
		return errors.New("部署清单身份或状态无效，拒绝重复执行")
	}
	var lock *os.File
	for attempt := 0; attempt < 25; attempt++ {
		lock, err = s.lockPM2Project(job.AppID)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		job.State = "failed"
		job.Error = "项目已被另一操作锁定，未安装依赖"
		job.FinishedAt = core.Now()
		_ = moduleWrite(s.pm2DeploymentPath(id), job)
		return err
	}
	defer lock.Close()
	defer func() {
		if err != nil && job.State != "needs_attention" {
			job.State = "failed"
			job.Error = err.Error()
		}
		job.FinishedAt = core.Now()
		if writeErr := moduleWrite(s.pm2DeploymentPath(id), job); writeErr != nil && err == nil {
			err = writeErr
		}
	}()
	var app pm2App
	if err = moduleRead(filepath.Join(s.moduleDir("pm2-manager"), "apps", job.AppID+".json"), &app); err != nil {
		return err
	}
	if app.SiteID != job.SiteID || app.Revision != job.Revision || core.Hash(string(job.Package)) != job.PackageSHA || core.Hash(string(job.Lock)) != job.LockSHA {
		return errors.New("部署清单或项目修订号已变化")
	}
	if err = validatePM2Packages(job.Package, job.Lock); err != nil {
		return err
	}
	f, err := s.openFiles(app.SiteID)
	if err != nil {
		return err
	}
	defer f.Close()
	account, err := user.Lookup(siteUser(app.SiteID))
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if uid < 1 || f.uid != uid {
		return errors.New("部署只允许网站独立非 root 用户")
	}
	private, err := f.root.OpenRoot("private")
	if err != nil {
		return err
	}
	defer private.Close()
	rel := "pm2-deploy-" + id
	if err = private.Mkdir(rel, 0700); err != nil {
		return err
	}
	stage, err := private.OpenRoot(rel)
	if err != nil {
		return err
	}
	defer stage.Close()
	if err = stage.WriteFile("package.json", job.Package, 0600); err != nil {
		return err
	}
	if err = stage.WriteFile("package-lock.json", job.Lock, 0600); err != nil {
		return err
	}
	if err = stage.WriteFile(".global-npmrc", nil, 0600); err != nil {
		return err
	}
	for _, path := range []string{".", "package.json", "package-lock.json", ".global-npmrc"} {
		file, e := stage.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		e = file.Chown(uid, gid)
		file.Close()
		if e != nil {
			return e
		}
	}
	job.State = "running"
	if err = moduleWrite(s.pm2DeploymentPath(id), job); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	stagePath := filepath.Join(s.Config.SitesDir, app.SiteID, "private", rel)
	npm := "/usr/bin/npm"
	args := []string{"ci", "--prefix", stagePath, "--cache", stagePath + "/.cache", "--omit=dev", "--ignore-scripts=" + strconv.FormatBool(!job.AllowInstallScripts), "--no-audit", "--no-fund", "--userconfig=/dev/null", "--globalconfig=" + stagePath + "/.global-npmrc", "--registry=https://registry.npmjs.org/", "--fetch-timeout=20000", "--fetch-retries=1"}
	node := pm2NodeBinaryOn(runtimecatalog.HostPlatform())
	if node != "/usr/bin/node" {
		npm = node
		args = append([]string{filepath.Join(appNativeRoot, "pm2/node/lib/node_modules/npm/bin/npm-cli.js")}, args...)
	}
	cmd := exec.CommandContext(ctx, npm, args...)
	cmd.Dir = stagePath
	cmd.Env = []string{"PATH=" + filepath.Dir(node) + ":/usr/bin:/bin", "LANG=C", "HOME=" + stagePath, "NODE_ENV=production"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
	output := &boundedBuffer{max: 32 << 10}
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.WaitDelay = time.Second
	if err = runPM2NPM(ctx, cancel, cmd, stage); err != nil {
		_ = atomicWrite(filepath.Join(s.moduleDir("pm2-manager"), "deployments", id+".npm.log"), output.Bytes(), 0600)
		return errors.New("npm ci 失败或超时，线上依赖未切换；请核对锁定文件和包兼容性")
	}
	if _, statErr := stage.Stat("node_modules"); os.IsNotExist(statErr) {
		if err = stage.Mkdir("node_modules", 0755); err != nil {
			return err
		}
	}
	manifest, e := readPM2Package(f.public, "package.json", 64<<10)
	if e != nil {
		return e
	}
	locked, e := readPM2Package(f.public, "package-lock.json", 2<<20)
	if e != nil {
		return e
	}
	if core.Hash(string(manifest)) != job.PackageSHA || core.Hash(string(locked)) != job.LockSHA {
		return errors.New("安装期间网站依赖清单已变化，未切换线上依赖")
	}
	// Pin the directory descriptors and rename only direct child names. Do not
	// follow user-controlled path components or delete previous dependencies.
	publicFD, e := f.public.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer publicFD.Close()
	stageFD, e := stage.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer stageFD.Close()
	newInfo, e := stage.Lstat("node_modules")
	if e != nil || !newInfo.IsDir() {
		return errors.New("部署输出不是普通依赖目录，未切换")
	}
	oldInfo, e := f.public.Lstat("node_modules")
	oldPresent := e == nil
	if oldPresent && !oldInfo.IsDir() {
		return errors.New("现有依赖目录不是普通目录，拒绝替换")
	}
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	job.State = "switching"
	job.BackupPath = stagePath + "/previous-node_modules"
	newStat := newInfo.Sys().(*syscall.Stat_t)
	job.NewDevice = uint64(newStat.Dev)
	job.NewInode = newStat.Ino
	if oldPresent {
		oldStat := oldInfo.Sys().(*syscall.Stat_t)
		job.OldDevice = uint64(oldStat.Dev)
		job.OldInode = oldStat.Ino
	}
	unit := "panel-pm2@" + app.ID
	state, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", unit)
	active := strings.TrimSpace(state) == "active"
	job.WasActive = active
	if err = moduleWrite(s.pm2DeploymentPath(id), job); err != nil {
		return err
	}
	if active {
		if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "stop", unit); err != nil {
			return err
		}
	}
	oldMoved, newMoved := false, false
	rollback := func(cause error) error {
		recoverCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_, _ = s.Config.Run(recoverCtx, "/usr/bin/systemctl", "stop", unit)
		var renameErr error
		if newMoved {
			renameErr = unix.Renameat2(int(publicFD.Fd()), "node_modules", int(stageFD.Fd()), "failed-node_modules", unix.RENAME_NOREPLACE)
		}
		if renameErr == nil && oldMoved {
			renameErr = unix.Renameat2(int(stageFD.Fd()), "previous-node_modules", int(publicFD.Fd()), "node_modules", unix.RENAME_NOREPLACE)
		}
		var restartErr error
		if active && renameErr == nil {
			_, restartErr = s.Config.Run(recoverCtx, "/usr/bin/systemctl", "start", unit)
			if restartErr == nil {
				restartErr = s.pm2Ready(recoverCtx, unit, app.Port)
			}
		}
		if renameErr != nil || restartErr != nil {
			job.State = "needs_attention"
			job.Error = "依赖切换失败且自动恢复未完成，保留新旧目录与部署记录；请核对后恢复"
			return errors.New(job.Error)
		}
		return cause
	}
	if oldPresent {
		if err = unix.Renameat2(int(publicFD.Fd()), "node_modules", int(stageFD.Fd()), "previous-node_modules", unix.RENAME_NOREPLACE); err != nil {
			return rollback(errors.New("原依赖目录备份失败"))
		}
		oldMoved = true
	}
	if err = unix.Renameat2(int(stageFD.Fd()), "node_modules", int(publicFD.Fd()), "node_modules", unix.RENAME_NOREPLACE); err != nil {
		return rollback(errors.New("新依赖目录切换失败"))
	}
	newMoved = true
	if active {
		if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "start", unit); err == nil {
			err = s.pm2Ready(ctx, unit, app.Port)
		}
		if err != nil {
			return rollback(errors.New("新依赖启动失败，已恢复旧依赖"))
		}
	}
	job.State = "succeeded"
	job.Error = ""
	return nil
}

func checkPM2Stage(root *os.Root) error {
	var size int64
	count := 0
	err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 30000 {
			return errors.New("暂存依赖超过 30000 项")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if _, err := root.Stat(path); err != nil {
				return errors.New("依赖符号链接不能越出暂存目录，不能为断链")
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			size += info.Size()
		}
		if size > 512<<20 {
			return errors.New("暂存依赖超过 512 MiB")
		}
		return nil
	})
	if err != nil {
		return err
	}
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	var space unix.Statfs_t
	if err = unix.Fstatfs(int(f.Fd()), &space); err != nil {
		return err
	}
	if space.Bavail*uint64(space.Bsize) < 1<<30 {
		return errors.New("文件系统可用空间不足 1 GiB，停止部署")
	}
	return nil
}

func runPM2NPM(ctx context.Context, cancel context.CancelFunc, cmd *exec.Cmd, stage *os.Root) error {
	if err := checkPM2Stage(stage); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				return err
			}
			return checkPM2Stage(stage)
		case <-ctx.Done():
			cancel()
			<-done
			return ctx.Err()
		case <-tick.C:
			if err := checkPM2Stage(stage); err != nil {
				cancel()
				<-done
				return err
			}
		}
	}
}

// Recovery is explicit and preserves failed/new directories. Inode identities
// from the pre-switch journal prevent overwriting a replacement made by a user.
func (s *Service) recoverPM2Deployment(ctx context.Context, app pm2App) (any, error) {
	job, err := s.pm2LastDeployment(app.ID)
	if err != nil {
		return nil, err
	}
	state, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pm2-deploy@"+job.ID)
	if strings.TrimSpace(state) == "active" || strings.TrimSpace(state) == "activating" || strings.TrimSpace(state) == "deactivating" {
		return nil, errors.New("部署进程仍在运行，请先取消该部署")
	}
	if job.State == "succeeded" || job.State == "failed" {
		return map[string]any{"deployment": publicPM2Deployment(job)}, nil
	}
	if job.SiteID != app.SiteID || job.Revision != app.Revision {
		return nil, errors.New("恢复记录与项目不匹配，未修改目录")
	}
	if job.State == "switching" || job.State == "needs_attention" {
		f, e := s.openFiles(app.SiteID)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		private, e := f.root.OpenRoot("private")
		if e != nil {
			return nil, e
		}
		defer private.Close()
		stage, e := private.OpenRoot("pm2-deploy-" + job.ID)
		if e != nil {
			return nil, e
		}
		defer stage.Close()
		if e = recoverPM2DependencyDirectories(f.public, stage, job); e != nil {
			return nil, e
		}
		if job.WasActive {
			if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "restart", "panel-pm2@"+app.ID); e == nil {
				e = s.pm2Ready(ctx, "panel-pm2@"+app.ID, app.Port)
			}
			if e != nil {
				return nil, errors.New("旧依赖已恢复，但应用未就绪；保留恢复记录，请核对应用源文件")
			}
		}
	}
	job.State = "failed"
	job.Error = "中断部署已安全恢复；线上依赖未切换或已恢复，暂存目录保留"
	job.FinishedAt = core.Now()
	if err = moduleWrite(s.pm2DeploymentPath(job.ID), job); err != nil {
		return nil, err
	}
	return map[string]any{"deployment": publicPM2Deployment(job)}, nil
}

func pm2DirectoryIdentity(root *os.Root, name string, device, inode uint64) (bool, error) {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, errors.New("依赖恢复路径不是普通目录")
	}
	st := info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != device || st.Ino != inode {
		return false, errors.New("依赖目录已被外部替换，未覆盖用户目录")
	}
	return true, nil
}

func recoverPM2DependencyDirectories(public, stage *os.Root, job pm2Deployment) error {
	p, err := public.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer p.Close()
	d, err := stage.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer d.Close()
	if job.OldInode != 0 {
		if old, err := pm2DirectoryIdentity(public, "node_modules", job.OldDevice, job.OldInode); err == nil && old {
			return nil
		}
	}
	current, err := pm2DirectoryIdentity(public, "node_modules", job.NewDevice, job.NewInode)
	if err != nil {
		return err
	}
	if current {
		if err = unix.Renameat2(int(p.Fd()), "node_modules", int(d.Fd()), "failed-node_modules", unix.RENAME_NOREPLACE); err != nil {
			return errors.New("新依赖保留失败，未覆盖或删除现有目录")
		}
	}
	if job.OldInode != 0 {
		old, err := pm2DirectoryIdentity(stage, "previous-node_modules", job.OldDevice, job.OldInode)
		if err != nil {
			return err
		}
		if !old {
			return errors.New("原依赖备份缺失，请检查保留目录")
		}
		if err = unix.Renameat2(int(d.Fd()), "previous-node_modules", int(p.Fd()), "node_modules", unix.RENAME_NOREPLACE); err != nil {
			return errors.New("原依赖恢复失败，未覆盖用户目录")
		}
	}
	return nil
}
