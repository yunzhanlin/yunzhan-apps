//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"syscall"
)

const phpConfigRoot = "/etc/panel/php-sites"

func siteUser(id string) string        { return "ps" + id[:24] }
func poolID(site core.Site) string     { return core.PHPInstanceID(site) }
func poolSocket(site core.Site) string { return "/run/panel-php-" + poolID(site) + "/fpm.sock" }
func poolUnit(site core.Site) string   { return "panel-php@" + poolID(site) + ".service" }
func PrepareSiteUser(id string) error {
	if !core.ValidID(id) {
		return errors.New("invalid site ID")
	}
	name := siteUser(id)
	if u, e := user.Lookup(name); e == nil {
		if u.Name != "panel-managed-"+id {
			return errors.New("existing user is not owned by this site")
		}
		return nil
	}
	_, e := RunCommand(context.Background(), "/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/srv/panel/sites/"+id, "--shell", "/usr/sbin/nologin", "--comment", "panel-managed-"+id, name)
	return e
}
func ServePHP(instance string) error {
	lock, lockErr := runtimeUseLock()
	if lockErr != nil {
		return lockErr
	}
	defer lock.Close()
	if len(instance) < 34 || !core.ValidID(instance[:32]) || instance[32] != '-' {
		return errors.New("invalid PHP instance")
	}
	release, suffix, configured := strings.Cut(instance[33:], "-cfg-")
	if configured && !regexp.MustCompile(`^[a-f0-9]{24}$`).MatchString(suffix) {
		return errors.New("invalid PHP configuration instance")
	}
	r, ok := runtimecatalog.Find(release)
	if !ok || r.Family != "php" {
		return errors.New("unknown PHP release")
	}
	if _, e := LoadRuntime(r.ID); e != nil {
		return e
	}
	cfg := filepath.Join(phpConfigRoot, instance, "fpm.conf")
	if e := ordinary(cfg, false); e != nil {
		return e
	}
	settings, e := readPHPPoolSettings(instance)
	if e != nil {
		return e
	}
	extensionArgs, e := phpExtensionArgs(context.Background(), r, settings)
	if e != nil {
		return e
	}
	args := append([]string{r.FPM()}, extensionArgs...)
	args = append(args, "--nodaemonize", "--fpm-config", cfg)
	return syscall.Exec(r.FPM(), args, []string{"PATH=/usr/bin:/bin", "LANG=C"})
}
func SiteCLI(id string, args []string) error {
	lock, lockErr := runtimeUseLock()
	if lockErr != nil {
		return lockErr
	}
	defer lock.Close()
	if !core.ValidID(id) {
		return errors.New("invalid site ID")
	}
	b, e := os.ReadFile(filepath.Join(phpConfigRoot, "bindings", id+".json"))
	if e != nil {
		return e
	}
	var site core.Site
	if e = json.Unmarshal(b, &site); e != nil {
		return e
	}
	r, ok := runtimecatalog.Find(site.PHPVersionID)
	if !ok || r.Family != "php" {
		return errors.New("site has no PHP binding")
	}
	if _, e := LoadRuntime(r.ID); e != nil {
		return e
	}
	u, e := user.Lookup(siteUser(id))
	if e != nil {
		return e
	}
	uid, e := strconv.ParseUint(u.Uid, 10, 32)
	if e != nil {
		return e
	}
	gid, e := strconv.ParseUint(u.Gid, 10, 32)
	if e != nil {
		return e
	}
	if e := core.ValidatePHPSettings(site.Settings.PHP); e != nil {
		return e
	}
	iniArgs, e := phpExtensionArgs(context.Background(), r, site.Settings.PHP)
	if e != nil {
		return e
	}
	for _, pair := range core.PHPIniValues(site.Settings.PHP) {
		iniArgs = append(iniArgs, "-d", pair[0]+"="+pair[1])
	}
	cmd := exec.Command(r.CLI(), append(iniArgs, args...)...)
	cmd.Dir = "/srv/panel/sites/" + id + "/public"
	cmd.Env = []string{"PATH=" + filepath.Dir(r.CLI()) + ":/usr/bin:/bin", "LANG=C", "HOME=/srv/panel/sites/" + id + "/private"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e := cmd.Start(); e != nil {
		return e
	}
	lock.Close()
	return cmd.Wait()
}
func (s *Service) preparePHP(ctx context.Context, site core.Site, dir string, add func(string)) (func(bool) error, string, error) {
	noop := func(bool) error { return nil }
	if s.Config.SitesDir != "/srv/panel/sites" {
		if site.PHPVersionID == "" {
			return noop, "", nil
		}
		return noop, "", errors.New("PHP adapter requires the dedicated Linux site root")
	}
	bindings := filepath.Join(phpConfigRoot, "bindings")
	if e := os.MkdirAll(bindings, 0700); e != nil {
		return noop, "", e
	}
	var old core.Site
	b, _ := os.ReadFile(filepath.Join(bindings, site.ID+".json"))
	_ = json.Unmarshal(b, &old)
	var currentUnit string
	if site.PHPVersionID != "" {
		r, ok := runtimecatalog.Find(site.PHPVersionID)
		if !ok || r.Family != "php" {
			return noop, "", errors.New("PHP 版本不在已审核目录中")
		}
		if _, e := LoadRuntime(r.ID); e != nil {
			return noop, "", errors.New("PHP 精确版本尚未完整安装")
		}
		extensionArgs, e := phpExtensionArgs(ctx, r, site.Settings.PHP)
		if e != nil {
			return noop, "", e
		}
		if _, e := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "panel-site-user@"+site.ID+".service"); e != nil {
			return noop, "", e
		}
		u, e := user.Lookup(siteUser(site.ID))
		if e != nil {
			return noop, "", e
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		webgroup, e := user.LookupGroup("www-data")
		if e != nil {
			return noop, "", e
		}
		webgid, _ := strconv.Atoi(webgroup.Gid)
		if e = os.Chown(filepath.Join(dir, "public"), uid, webgid); e != nil {
			return noop, "", e
		}
		if e = os.Chmod(filepath.Join(dir, "public"), 0750); e != nil {
			return noop, "", e
		}
		private := filepath.Join(dir, "private")
		if e = os.MkdirAll(private, 0700); e != nil {
			return noop, "", e
		}
		if e = os.Chown(private, uid, gid); e != nil {
			return noop, "", e
		}
		cfgdir := filepath.Join(phpConfigRoot, poolID(site))
		if e = os.MkdirAll(cfgdir, 0755); e != nil {
			return noop, "", e
		}
		config := phpPoolConfiguration(site, dir)
		cfgPath := filepath.Join(cfgdir, "fpm.conf")
		if oldConfig, e := os.ReadFile(cfgPath); e == nil {
			if e = ordinary(cfgPath, false); e != nil {
				return noop, "", e
			}
			if string(oldConfig) != config {
				return noop, "", errors.New("目标 FPM 配置已被外部修改，请核对后重试或选择新的参数")
			}
		} else if os.IsNotExist(e) {
			if e = atomicWrite(cfgPath, []byte(config), 0640); e != nil {
				return noop, "", e
			}
		} else {
			return noop, "", e
		}
		if e = savePHPPoolManifest(site); e != nil {
			return noop, "", e
		}
		if _, e = s.Config.Run(ctx, r.FPM(), append(extensionArgs, "-t", "--fpm-config", filepath.Join(cfgdir, "fpm.conf"))...); e != nil {
			return noop, "", e
		}
		currentUnit = poolUnit(site)
		if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "start", currentUnit); e != nil {
			if poolID(old) != poolID(site) {
				_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "disable", "--now", currentUnit)
			}
			return noop, "", e
		}
		add("独立站点用户与 PHP-FPM 池就绪，目标版本 " + r.Version)
	}
	finish := func(commit bool) error {
		if !commit {
			if currentUnit != "" && poolID(old) != poolID(site) {
				_, e := s.Config.Run(context.Background(), "/usr/bin/systemctl", "disable", "--now", currentUnit)
				return e
			}
			return nil
		}
		if currentUnit != "" {
			if _, e := s.Config.Run(ctx, "/usr/bin/systemctl", "enable", currentUnit); e != nil {
				return e
			}
		}
		site.RuntimeInstanceID = core.PHPInstanceID(site)
		data, _ := json.Marshal(site)
		if e := atomicWrite(filepath.Join(bindings, site.ID+".json"), data, 0600); e != nil {
			return e
		}
		if old.PHPVersionID != "" && poolID(old) != poolID(site) && old.ID == site.ID {
			if _, ok := runtimecatalog.Find(old.PHPVersionID); ok {
				_, e := s.Config.Run(ctx, "/usr/bin/systemctl", "disable", "--now", poolUnit(old))
				if e != nil {
					add("旧 PHP 池清理未完成，可在服务日志中核对: " + e.Error())
				}
			}
		}
		return nil
	}
	return finish, poolSocket(site), nil
}
func phpConfig(site core.Site, dir string) string {
	if site.PHPVersionID == "" {
		return "  location ~* \\.(php|phtml|phar)(/|$) { return 404; }\n"
	}
	socket := poolSocket(site)
	return thinkPHPCompatibilityLocation(site, socket) + fmt.Sprintf("  location ~ \\.php$ {\n%s    try_files $uri =404;\n    fastcgi_hide_header X-Panel-Config;\n    include /etc/nginx/fastcgi_params;\n    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n    fastcgi_pass unix:%s;\n  }\n  location ~* \\.(php|phtml|phar)(/|$) { return 404; }\n", siteAnalyticsHTMLFilters(site), socket)
}
func phpVersion(id string) string { r, _ := runtimecatalog.Find(id); return r.Version }

func phpProbeConfig(site core.Site) string {
	if site.PHPVersionID == "" {
		return ""
	}
	return fmt.Sprintf("  location ~ \"^/panel-check-[a-f0-9]{32}\\\\.php$\" {\n    try_files $uri =404;\n    fastcgi_hide_header X-Panel-Config;\n    include /etc/nginx/fastcgi_params;\n    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n    fastcgi_pass unix:%s;\n  }\n", poolSocket(site))
}

func (s *Service) phpSettingsPreview(site core.Site) (string, string, error) {
	candidate := ""
	if site.PHPVersionID != "" {
		candidate = phpPoolConfiguration(site, filepath.Join(s.Config.SitesDir, site.ID))
	}
	if s.Config.SitesDir != "/srv/panel/sites" {
		return "", candidate, nil
	}
	b, e := os.ReadFile(filepath.Join(phpConfigRoot, "bindings", site.ID+".json"))
	if os.IsNotExist(e) {
		return "", candidate, nil
	}
	if e != nil {
		return "", "", e
	}
	var old core.Site
	if e = json.Unmarshal(b, &old); e != nil || old.ID != site.ID {
		return "", "", errors.New("站点 PHP 绑定清单异常")
	}
	if old.PHPVersionID == "" {
		return "", candidate, nil
	}
	if r, ok := runtimecatalog.Find(old.PHPVersionID); !ok || r.Family != "php" {
		return "", "", errors.New("原 PHP 绑定版本异常")
	}
	cfg := filepath.Join(phpConfigRoot, poolID(old), "fpm.conf")
	if e = ordinary(cfg, false); e != nil {
		return "", "", e
	}
	b, e = os.ReadFile(cfg)
	if e != nil {
		return "", "", e
	}
	if len(b) > 65536 {
		return "", "", errors.New("FPM 配置超限")
	}
	return string(b), candidate, nil
}
