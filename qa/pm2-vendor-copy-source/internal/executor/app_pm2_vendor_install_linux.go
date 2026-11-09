//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"

	"golang.org/x/sys/unix"
)

type pm2RootVendorBuild struct {
	VerifiedExisting bool                 `json:"verified_existing"`
	IndependentRoot  bool                 `json:"independent_root_copy"`
	Publication      pm2VendorPublication `json:"publication"`
}

func pm2VendorEnsureParent() error {
	parentPath, name := filepath.Dir(appNativeRoot), filepath.Base(appNativeRoot)
	parent, err := pm2VendorOpenProtectedParent(parentPath)
	if err != nil {
		return err
	}
	defer parent.Close()
	st, err := pm2VendorAt(parent, name)
	if errors.Is(err, unix.ENOENT) {
		if err = unix.Mkdirat(int(parent.Fd()), name, 0755); err != nil {
			return err
		}
		created, err := pm2VendorOpenDirectory(parent, name)
		if err != nil {
			return err
		}
		defer created.Close()
		if err = unix.Fchown(int(created.Fd()), 0, 0); err == nil {
			err = unix.Fchmod(int(created.Fd()), 0755)
		}
		if err == nil {
			err = created.Sync()
		}
		if err == nil {
			err = parent.Sync()
		}
		return err
	}
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
		return errors.New("PM2 原运行库父目录身份或权限无法核对；未创建、修复或覆盖")
	}
	return nil
}

// Distribution Node/npm remain the existing interpreter choice. Root-copy
// repair must not silently change a project's Node major ABI. Ubuntu22.04
// retains its already-reviewed private Node24.21.0 selection.
func pm2VendorTrustedSystemProgram(name string) error {
	return pm2VendorTrustedSystemProgramOn("/", name)
}

func pm2VendorTrustedSystemProgramOn(systemRoot, name string) error {
	if name != "/usr/bin/node" && name != "/usr/bin/npm" {
		return errors.New("PM2 系统运行程序不在固定目录中")
	}
	if !filepath.IsAbs(systemRoot) || filepath.Clean(systemRoot) != systemRoot {
		return errors.New("PM2 系统根目录身份无效")
	}
	name = filepath.Join(systemRoot, strings.TrimPrefix(name, "/"))
	link, err := os.Lstat(name)
	if err != nil {
		return err
	}
	stat, ok := link.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("PM2 系统运行程序或链接不是 Root 所有")
	}
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil || !filepath.IsAbs(resolved) {
		return errors.New("PM2 系统运行程序的受管链接无法核对")
	}
	if relative, err := filepath.Rel(systemRoot, resolved); err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
		return errors.New("PM2 系统运行程序链接离开受管根目录")
	}
	parent, err := pm2VendorOpenProtectedParent(filepath.Dir(resolved))
	if err != nil {
		return err
	}
	defer parent.Close()
	value, err := pm2VendorAt(parent, filepath.Base(resolved))
	if err != nil || value.Mode&unix.S_IFMT != unix.S_IFREG || value.Uid != 0 || value.Mode&0022 != 0 || value.Mode&0111 == 0 {
		return errors.New("PM2 系统 Node/npm 程序身份、类型或写权限无法核对")
	}
	return nil
}

var pm2VendorNodeVersion = regexp.MustCompile(`^v([0-9]{1,3})\.[0-9]+\.[0-9]+$`)

func (s *Service) preparePM2RootDistributionNode(ctx context.Context) error {
	packages := []string{"nodejs", "npm"}
	if !s.wafBuildPackagesReady(packages) {
		if _, err := s.moduleCommand(ctx, 2*time.Minute, "/usr/bin/apt-get", "update"); err != nil {
			return err
		}
		args := []string{"install", "-y", "--no-install-recommends", "--no-upgrade"}
		if _, err := s.moduleCommand(ctx, 5*time.Minute, "/usr/bin/apt-get", append(append(append([]string{}, args...), "--download-only"), packages...)...); err != nil {
			return err
		}
		if _, err := s.moduleCommand(ctx, 5*time.Minute, "/usr/bin/apt-get", append(append(append([]string{}, args...), "--no-download"), packages...)...); err != nil {
			return err
		}
	}
	for _, binary := range []string{"/usr/bin/node", "/usr/bin/npm"} {
		if err := pm2VendorTrustedSystemProgram(binary); err != nil {
			return err
		}
	}
	value, err := s.moduleCommand(ctx, 10*time.Second, "/usr/bin/node", "--version")
	match := pm2VendorNodeVersion.FindStringSubmatch(strings.TrimSpace(value))
	if err != nil || len(match) != 2 {
		return errors.New("PM2 实际系统 Node.js 版本无法核对")
	}
	major, err := strconv.Atoi(match[1])
	if err != nil || major < 18 {
		return errors.New("PM2 固定版本需要 Node.js18及以上；未自动替换原有系统 Node 版本")
	}
	return nil
}

// Only the existing fixed dependency unit will call this builder. No caller
// can choose a package name, Node URL, source path, shell or npm arguments.
// Interrupted and previous workspaces stay private; no original runtime or
// npm cache is deleted or repaired in place.
func (s *Service) buildPM2RootVendor(ctx context.Context) (result pm2RootVendorBuild, err error) {
	if os.Geteuid() != 0 || s.Config.SystemRoot != "/" {
		return result, errors.New("PM2 独立运行库构建仅适用于真实 Root 固定依赖服务")
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = s.pm2RootVendorPreparationAllowed(); err != nil {
		return result, err
	}
	if pm2VendorSealedReadyAt(ctx, appNativeRoot) == nil {
		return pm2RootVendorBuild{VerifiedExisting: true, IndependentRoot: true}, nil
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = pm2VendorEnsureParent(); err != nil {
		return result, err
	}
	w, err := newPM2VendorWorkspace(appNativeRoot)
	if err != nil {
		return result, err
	}
	defer w.close()
	defer func() {
		// A failed outcome is a retained original record, including the
		// distinction between no exchange and published-but-unconfirmed.
		recordErr := w.writeRecord("original-build-outcome.json", map[string]any{"ok": err == nil, "result": result, "error": fmt.Sprint(err), "automatic_replay": false, "old_runtime_or_inputs_removed": false}, 0600)
		if err == nil && recordErr != nil {
			err = recordErr
		}
	}()
	var space unix.Statfs_t
	if err = unix.Fstatfs(int(w.parent.Fd()), &space); err != nil {
		return result, err
	}
	if space.Bsize <= 0 || uint64(space.Bavail)*uint64(space.Bsize) < 768<<20 || space.Files > 0 && uint64(space.Ffree) < 2*pm2VendorMaxEntries {
		return result, errors.New("PM2 独立运行库构建的可用空间或 inode 安全余量不足；原运行库保留")
	}
	if err = w.writeRecord("original-build-intent.json", map[string]any{"format": 1, "package_sha256": pm2VendorHash(pm2Package), "lock_sha256": pm2VendorHash(pm2Lock), "upstream": "7.0.4", "private_source": "build", "candidate": "candidate", "maximum_publications": 1, "install_scripts": false, "existing_projects_restarted": false}, 0600); err != nil {
		return result, err
	}
	for _, name := range []string{"build", "home", "tmp"} {
		if err = unix.Mkdirat(int(w.dir.Fd()), name, 0700); err != nil {
			return result, err
		}
		private, openErr := pm2VendorOpenDirectory(w.dir, name)
		if openErr != nil {
			return result, openErr
		}
		err = unix.Fchown(int(private.Fd()), 0, 0)
		if err == nil {
			err = unix.Fchmod(int(private.Fd()), 0700)
		}
		private.Close()
		if err != nil {
			return result, err
		}
	}
	build, err := pm2VendorOpenDirectory(w.dir, "build")
	if err != nil {
		return result, err
	}
	for name, raw := range map[string][]byte{"package.json": pm2Package, "package-lock.json": pm2Lock} {
		if err = pm2VendorWriteNew(build, name, raw, 0644); err != nil {
			build.Close()
			return result, err
		}
	}
	build.Close()
	buildPath := filepath.Join(w.path, "build")
	// npm refuses loading one file twice as both user and global config.
	// Keep a distinct, freshly created empty Root file, never a host npmrc.
	if err = pm2VendorWriteNew(w.dir, "empty-global-npmrc", nil, 0600); err != nil {
		return result, err
	}
	npmBinary := "/usr/bin/npm"
	args := []string{"ci", "--prefix", buildPath, "--cache", filepath.Join(buildPath, ".cache"), "--userconfig=/dev/null", "--globalconfig=" + filepath.Join(w.path, "empty-global-npmrc"), "--registry=https://registry.npmjs.org/", "--fetch-timeout=20000", "--fetch-retries=1", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"}
	if runtimecatalog.HostPlatform() == "ubuntu-22.04" {
		if err = ensurePM2PrivateNode(ctx, buildPath); err != nil {
			return result, err
		}
		npmBinary = filepath.Join(buildPath, "node/bin/node")
		args = append([]string{filepath.Join(buildPath, "node/lib/node_modules/npm/bin/npm-cli.js")}, args...)
	} else if err = s.preparePM2RootDistributionNode(ctx); err != nil {
		return result, err
	}
	environment := []string{"HOME=" + filepath.Join(w.path, "home"), "TMPDIR=" + filepath.Join(w.path, "tmp")}
	if _, err = s.moduleCommandEnvironment(ctx, 4*time.Minute, npmBinary, environment, args...); err != nil {
		return result, err
	}
	entries, err := w.copyIndependent(ctx, "build", "candidate")
	if err != nil {
		return result, err
	}
	sealed, err := w.sealCandidate(ctx, "candidate", entries)
	if err != nil {
		return result, err
	}
	result.Publication, err = w.publishIndependent(ctx, "candidate", sealed)
	if err != nil {
		return result, err
	}
	if err = pm2VendorSealedReadyAt(ctx, appNativeRoot); err != nil {
		return result, err
	}
	result.IndependentRoot = true
	return result, nil
}

func (s *Service) pm2RootVendorReady(ctx context.Context) error {
	if err := pm2VendorSealedReadyAt(ctx, s.systemPath(appNativeRoot)); err != nil {
		return fmt.Errorf("PM2 共享运行库未通过独立 Root 副本核对；请更新应用，未启动或重放项目：%w", err)
	}
	if runtimecatalog.HostPlatform() != "ubuntu-22.04" {
		if err := pm2VendorTrustedSystemProgramOn(s.Config.SystemRoot, "/usr/bin/node"); err != nil {
			return err
		}
	}
	return nil
}

// Both the short preparation endpoint and the fixed Root unit recheck the
// original installation/configuration before constructing any new runtime.
func (s *Service) pm2RootVendorPreparationAllowed() error {
	installed, err := s.moduleInstalledRecord("pm2-manager")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	version, _ := installed["version"].(string)
	known := version == "6" || version == "7.0.4"
	for i := 1; i <= 11; i++ {
		known = known || version == "7.0.4-compat"+strconv.Itoa(i)
	}
	if !known {
		return errors.New("PM2 原安装版本无法核对；未构建或替换运行库")
	}
	records, err := s.pm2ConfigRecords()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Receipt == nil && record.Cancellation == nil {
			return errors.New("PM2 原配置事务尚未核对完成；未构建或替换运行库")
		}
	}
	return nil
}

func (s *Service) preparePM2RootVendorUpdate(ctx context.Context, status core.SoftwareAppStatus, add func(string)) error {
	known := status.Version == "6" || status.Version == "7.0.4"
	for i := 1; i <= 11; i++ {
		known = known || status.Version == "7.0.4-compat"+strconv.Itoa(i)
	}
	if !status.Installed || status.StateUnknown || !known {
		return errors.New("PM2 原安装身份或固定历史版本无法核对；未构建或替换共享运行库")
	}
	before, err := s.moduleInstalledRecord("pm2-manager")
	if err != nil {
		return err
	}
	records, err := s.pm2ConfigRecords()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Receipt == nil && record.Cancellation == nil {
			return errors.New("PM2 原配置事务尚未核对完成，请先恢复或取消原请求；未构建运行库")
		}
	}
	if s.pm2RootVendorReady(ctx) != nil {
		if err = s.appDependencies(ctx, "pm2-manager"); err != nil {
			return err
		}
	}
	if err = s.pm2RootVendorReady(ctx); err != nil {
		return err
	}
	after, err := s.moduleInstalledRecord("pm2-manager")
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("PM2 原安装记录在运行库构建期间变化；保留原版本，未覆盖安装字段")
	}
	add("锁定依赖已构建为独立 Root 新 inode 并绑定私有验收记录；原运行库保留，未重启项目或重放配置。原运行中的项目需逐个明确重启后核对。")
	return nil
}
