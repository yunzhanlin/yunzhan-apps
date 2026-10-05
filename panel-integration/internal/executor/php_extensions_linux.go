//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type PHPABI struct {
	Version        string `json:"version"`
	ZTS            bool   `json:"zts"`
	Debug          bool   `json:"debug"`
	Architecture   string `json:"architecture"`
	ExtensionBuild string `json:"extension_build"`
}
type ExtensionManifest struct {
	PHPRelease  runtimecatalog.Release   `json:"php_release"`
	Extension   runtimecatalog.Extension `json:"extension"`
	ABI         PHPABI                   `json:"abi"`
	ModuleSHA   string                   `json:"module_sha256"`
	InstalledAt string                   `json:"installed_at"`
}

func readPHPABI(ctx context.Context, r runtimecatalog.Release) (PHPABI, error) {
	var abi PHPABI
	if r.Family != "php" {
		return abi, errors.New("扩展只能绑定 PHP")
	}
	if _, e := LoadRuntime(r.ID); e != nil {
		return abi, e
	}
	text, e := RunCommand(ctx, r.CLI(), "-n", "-r", `echo json_encode(['version'=>PHP_VERSION,'zts'=>(bool)PHP_ZTS,'debug'=>(bool)PHP_DEBUG]);`)
	if e != nil {
		return abi, e
	}
	if e = json.Unmarshal([]byte(text), &abi); e != nil {
		return abi, e
	}
	path, e := RunCommand(ctx, filepath.Join(r.Prefix(), "bin/php-config"), "--extension-dir")
	if e != nil {
		return abi, e
	}
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, r.Prefix()+"/lib/php/extensions/") {
		return abi, errors.New("PHP 扩展路径不属于该版本")
	}
	build := filepath.Base(path)
	if !regexp.MustCompile(`^(no-debug|debug)-(non-zts|zts)-[0-9]{8}$`).MatchString(build) {
		return abi, errors.New("未识别的 PHP 扩展 ABI")
	}
	abi.ExtensionBuild = build
	abi.Architecture = runtime.GOARCH
	if abi.Version != r.Version {
		return abi, errors.New("PHP ABI 与精确版本不匹配")
	}
	if strings.HasPrefix(build, "debug-") != abi.Debug || strings.Contains(build, "-non-zts-") == abi.ZTS {
		return abi, errors.New("PHP 构建特性不匹配")
	}
	return abi, nil
}
func extensionModuleSHA(path string) (string, error) {
	if e := ownedRuntimePath(path, false); e != nil {
		return "", e
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 64*1024*1024+1))
	if e != nil {
		return "", e
	}
	if n > 64*1024*1024 {
		return "", errors.New("扩展模块大小超限")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func verifyModuleELF(path, arch string) error {
	f, e := elf.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	wanted := elf.EM_AARCH64
	if arch == "amd64" {
		wanted = elf.EM_X86_64
	} else if arch != "arm64" {
		return errors.New("不支持的模块架构")
	}
	if f.Type != elf.ET_DYN || f.Class != elf.ELFCLASS64 || f.Machine != wanted {
		return errors.New("扩展二进制架构或类型不匹配")
	}
	return nil
}
func verifyModuleLoad(ctx context.Context, r runtimecatalog.Release, ext runtimecatalog.Extension, path string) error {
	if e := verifyModuleELF(path, runtime.GOARCH); e != nil {
		return e
	}
	output, e := RunCommand(ctx, r.CLI(), "-n", "-d", "extension="+path, "-r", "echo phpversion('"+ext.Name+"');")
	if e != nil {
		return e
	}
	if output != ext.Version {
		return errors.New("扩展实际加载版本不匹配")
	}
	return nil
}
func LoadPHPExtension(ctx context.Context, r runtimecatalog.Release, ext runtimecatalog.Extension) (ExtensionManifest, error) {
	var m ExtensionManifest
	for _, dir := range []string{"/opt/panel/php-extensions", filepath.Join("/opt/panel/php-extensions", r.ID), filepath.Dir(ext.Prefix(r)), ext.Prefix(r)} {
		if e := ownedRuntimePath(dir, true); e != nil {
			return m, e
		}
	}
	path := filepath.Join(ext.Prefix(r), ".panel-extension.json")
	if e := ownedRuntimePath(path, false); e != nil {
		return m, e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return m, e
	}
	if len(b) > 65536 {
		return m, errors.New("扩展清单超限")
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, e
	}
	if m.PHPRelease != r || m.Extension != ext {
		return m, errors.New("扩展清单不属于该 PHP 精确版本")
	}
	abi, e := readPHPABI(ctx, r)
	if e != nil {
		return m, e
	}
	if m.ABI != abi {
		return m, errors.New("扩展 ABI 与 PHP 不匹配")
	}
	module := filepath.Join(ext.Prefix(r), ext.Name+".so")
	sum, e := extensionModuleSHA(module)
	if e != nil {
		return m, e
	}
	if m.ModuleSHA != sum {
		return m, errors.New("扩展模块 SHA-256 不匹配")
	}
	if e = verifyModuleELF(module, runtime.GOARCH); e != nil {
		return m, e
	}
	return m, nil
}
func installPHPExtension(ctx context.Context, r runtimecatalog.Release, ext runtimecatalog.Extension, id string, add func(string) error) error {
	abi, e := readPHPABI(ctx, r)
	if e != nil {
		return e
	}
	if _, e = LoadPHPExtension(ctx, r, ext); e == nil {
		return add("扩展已安装，PHP 精确版本、ABI 与模块摘要核对通过")
	}
	if _, e = os.Lstat(ext.Prefix(r)); !os.IsNotExist(e) {
		return errors.New("扩展目标目录已存在但校验未通过，拒绝覆盖")
	}
	base := filepath.Join("/var/cache/panel-build", id)
	if e = os.MkdirAll(base, 0755); e != nil {
		return e
	}
	if e = os.Chmod(base, 0755); e != nil {
		return e
	}
	archive := filepath.Join(base, "extension.tgz")
	if e = downloadVerified(ctx, ext.URL, ext.SHA256, archive); e != nil {
		return e
	}
	if e = add("官方扩展源码 SHA-256 通过，绑定 " + r.ID + " / " + abi.ExtensionBuild); e != nil {
		return e
	}
	work := filepath.Join(base, "work")
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
	source := filepath.Join(work, ext.Name+"-"+ext.Version)
	log := filepath.Join(base, "build.log")
	if e = buildCommand(ctx, source, log, filepath.Join(r.Prefix(), "bin/phpize")); e != nil {
		return e
	}
	if e = buildCommand(ctx, source, log, filepath.Join(source, "configure"), "--with-php-config="+filepath.Join(r.Prefix(), "bin/php-config"), "--enable-"+ext.Name); e != nil {
		return e
	}
	if e = add("以非特权账户为指定 PHP 编译独立扩展"); e != nil {
		return e
	}
	if e = buildCommand(ctx, source, log, "/usr/bin/make", "-j2"); e != nil {
		return e
	}
	parent := filepath.Dir(ext.Prefix(r))
	if e = os.MkdirAll(parent, 0755); e != nil {
		return e
	}
	temp := ext.Prefix(r) + ".pending-" + id
	if e = os.RemoveAll(temp); e != nil {
		return e
	}
	if e = os.Mkdir(temp, 0755); e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	workRoot, e := os.OpenRoot(work)
	if e != nil {
		return e
	}
	defer workRoot.Close()
	src, e := workRoot.Open(filepath.Join(ext.Name+"-"+ext.Version, "modules", ext.Name+".so"))
	if e != nil {
		return e
	}
	defer src.Close()
	info, e := src.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("扩展产物不是普通文件")
	}
	module := filepath.Join(temp, ext.Name+".so")
	dst, e := os.OpenFile(module, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	n, copyErr := io.Copy(dst, io.LimitReader(src, 64*1024*1024+1))
	syncErr := dst.Sync()
	closeErr := dst.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > 64*1024*1024 {
		return errors.New("扩展产物超限")
	}
	if e = verifyModuleLoad(ctx, r, ext, module); e != nil {
		return e
	}
	sum, e := extensionModuleSHA(module)
	if e != nil {
		return e
	}
	m := ExtensionManifest{PHPRelease: r, Extension: ext, ABI: abi, ModuleSHA: sum, InstalledAt: core.Now()}
	if e = writeJSON(filepath.Join(temp, ".panel-extension.json"), m); e != nil {
		return e
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return e
	}
	defer root.Close()
	if e = renameNoReplace(root, filepath.Base(temp), ext.Version); e != nil {
		return e
	}
	if e = syncRuntimeDirs(parent); e != nil {
		return e
	}
	return add("独立扩展安装完成，实际 PHP 加载版本与 ABI 通过；尚未为网站启用")
}
func phpExtensionRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/php/extensions/install", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			JobID       string `json:"job_id"`
			ReleaseID   string `json:"release_id"`
			ExtensionID string `json:"extension_id"`
			Retry       bool   `json:"retry"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		st, e := startInstallOperation(r.Context(), in.JobID, in.ReleaseID, in.ExtensionID, in.Retry)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 202, st)
	})
	m.HandleFunc("GET /v1/php/extensions/{id}", func(w http.ResponseWriter, r *http.Request) {
		release, ok := runtimecatalog.Find(r.PathValue("id"))
		if !ok || release.Family != "php" {
			respond(w, 400, map[string]string{"error": "无效 PHP 版本"})
			return
		}
		lock, e := runtimeUseLock()
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		defer lock.Close()
		out := []map[string]any{}
		for _, ext := range runtimecatalog.Extensions {
			item := map[string]any{"extension": ext, "release_id": release.ID, "status": "not_installed"}
			if _, e := os.Lstat(ext.Prefix(release)); e == nil {
				m, e := LoadPHPExtension(r.Context(), release, ext)
				if e != nil {
					item["status"] = "needs_attention"
					item["error"] = e.Error()
				} else {
					item["status"] = "installed"
					item["manifest"] = m
				}
			} else if !os.IsNotExist(e) {
				respond(w, 409, map[string]string{"error": fmt.Sprint(e)})
				return
			}
			out = append(out, item)
		}
		respond(w, 200, out)
	})
}

func phpExtensionArgs(ctx context.Context, r runtimecatalog.Release, settings *core.PHPSettings) ([]string, error) {
	out := []string{}
	if e := core.ValidatePHPSettings(settings); e != nil {
		return nil, e
	}
	if settings == nil {
		return out, nil
	}
	for _, id := range settings.Extensions {
		ext, ok := runtimecatalog.FindExtension(id)
		if !ok {
			return nil, errors.New("扩展不在固定目录中")
		}
		if _, e := LoadPHPExtension(ctx, r, ext); e != nil {
			return nil, fmt.Errorf("%s / %s 未通过加载前校验: %w", r.ID, id, e)
		}
		out = append(out, "-d", "extension="+filepath.Join(ext.Prefix(r), ext.Name+".so"))
	}
	return out, nil
}

type phpPoolManifest struct {
	SiteID    string            `json:"site_id"`
	ReleaseID string            `json:"release_id"`
	PHP       *core.PHPSettings `json:"php,omitempty"`
}

func savePHPPoolManifest(site core.Site) error {
	path := filepath.Join(phpConfigRoot, core.PHPInstanceID(site), "pool.json")
	want := phpPoolManifest{SiteID: site.ID, ReleaseID: site.PHPVersionID, PHP: site.Settings.PHP}
	data, _ := json.Marshal(want)
	if old, e := os.ReadFile(path); e == nil {
		if e = ownedRuntimePath(path, false); e != nil {
			return e
		}
		var have phpPoolManifest
		if e = json.Unmarshal(old, &have); e != nil {
			return e
		}
		actual, _ := json.Marshal(have)
		if string(actual) != string(data) {
			return errors.New("候选池清单与参数摘要不匹配")
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	return atomicWrite(path, data, 0600)
}
func readPHPPoolSettings(instance string) (*core.PHPSettings, error) {
	if len(instance) < 34 || !core.ValidID(instance[:32]) || instance[32] != '-' {
		return nil, errors.New("invalid PHP instance")
	}
	path := filepath.Join(phpConfigRoot, instance, "pool.json")
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		// Existing pools were created before independent extensions. Only their current
		// matching binding can provide legacy parameters; new extension pools require a manifest.
		b, e = os.ReadFile(filepath.Join(phpConfigRoot, "bindings", instance[:32]+".json"))
		if e != nil {
			return nil, e
		}
		var site core.Site
		if e = json.Unmarshal(b, &site); e != nil {
			return nil, e
		}
		if core.PHPInstanceID(site) != instance || site.ID != instance[:32] {
			return nil, errors.New("缺少可核对的 PHP 池清单")
		}
		if site.Settings.PHP != nil && len(site.Settings.PHP.Extensions) > 0 {
			return nil, errors.New("扩展池清单丢失")
		}
		return site.Settings.PHP, nil
	}
	if e != nil {
		return nil, e
	}
	if e = ownedRuntimePath(path, false); e != nil {
		return nil, e
	}
	return decodePHPPoolManifest(instance, b)
}
func decodePHPPoolManifest(instance string, b []byte) (*core.PHPSettings, error) {
	if len(b) > 65536 {
		return nil, errors.New("PHP 池清单超限")
	}
	var m phpPoolManifest
	if e := json.Unmarshal(b, &m); e != nil {
		return nil, e
	}
	if !core.ValidID(m.SiteID) || core.PHPInstanceID(core.Site{ID: m.SiteID, PHPVersionID: m.ReleaseID, Settings: core.SiteSettings{PHP: m.PHP}}) != instance {
		return nil, errors.New("PHP 池清单与实例标识不匹配")
	}
	if e := core.ValidatePHPSettings(m.PHP); e != nil {
		return nil, e
	}
	return m.PHP, nil
}
