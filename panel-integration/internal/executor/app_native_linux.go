//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
)

var moduleResourceID = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)

const appNativeRoot = "/opt/panel/app-modules"

func (s *Service) moduleCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if s.Config.SystemRoot != "/" {
		return s.Config.Run(ctx, name, args...)
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "DEBIAN_FRONTEND=noninteractive"}
	out := &boundedBuffer{max: 128 << 10}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = time.Second
	if e := cmd.Run(); e != nil {
		return "", fmt.Errorf("%s: %w: %s", filepath.Base(name), e, out.String())
	}
	return out.String(), nil
}
func (s *Service) appDependencies(ctx context.Context, id string) error {
	if s.Config.SystemRoot != "/" {
		_, e := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "panel-app-dependencies@"+id)
		return e
	}
	if _, e := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "--no-block", "panel-app-dependencies@"+id); e != nil {
		return e
	}
	for {
		state, e := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "--property=ActiveState", "--value", "panel-app-dependencies@"+id)
		if e != nil {
			return e
		}
		if strings.TrimSpace(state) == "failed" {
			return errors.New("应用依赖安装失败，请查看固定依赖服务日志")
		}
		if strings.TrimSpace(state) == "inactive" {
			var result struct {
				OK    bool
				Error string
			}
			if e = moduleRead(filepath.Join(s.moduleDir(id), "dependency-result.json"), &result); e != nil {
				return e
			}
			if !result.OK {
				return errors.New(result.Error)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// Runs only in a dedicated root unit with a fixed package list, never a shell command from the API.
func InstallAppDependencies(id string) (err error) {
	if id != "pure-ftpd" && id != "nfs-manager" && id != "pm2-manager" {
		return errors.New("依赖模块无效")
	}
	s := New(Config{})
	if err = moduleWrite(filepath.Join(s.moduleDir(id), "dependency-result.json"), map[string]any{"ok": false, "state": "installing", "time": core.Now()}); err != nil {
		return err
	}
	defer func() {
		_ = moduleWrite(filepath.Join(s.moduleDir(id), "dependency-result.json"), map[string]any{"ok": err == nil, "error": fmt.Sprint(err), "time": core.Now(), "lock_sha256": core.Hash(string(pm2Lock))})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	packages := map[string][]string{"pure-ftpd": {"pure-ftpd"}, "nfs-manager": {"nfs-common"}, "pm2-manager": {"nodejs", "npm"}}[id]
	if id == "pure-ftpd" {
		if _, e := os.Stat("/usr/sbin/pure-ftpd"); e != nil {
			if _, e = s.moduleCommand(ctx, time.Minute, "/usr/bin/systemctl", "mask", "pure-ftpd.service"); e != nil {
				return e
			}
		}
	}
	if _, err = s.moduleCommand(ctx, 2*time.Minute, "/usr/bin/apt-get", "update"); err != nil {
		return err
	}
	if _, err = s.moduleCommand(ctx, 5*time.Minute, "/usr/bin/apt-get", append([]string{"install", "-y", "--no-install-recommends"}, packages...)...); err != nil {
		return err
	}
	if id == "pm2-manager" {
		dir := filepath.Join(appNativeRoot, "pm2")
		if err = os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		if err = atomicWrite(filepath.Join(dir, "package.json"), pm2Package, 0644); err != nil {
			return err
		}
		if err = atomicWrite(filepath.Join(dir, "package-lock.json"), pm2Lock, 0644); err != nil {
			return err
		}
		_, err = s.moduleCommand(ctx, 3*time.Minute, "/usr/bin/npm", "ci", "--prefix", dir, "--cache", filepath.Join(dir, ".cache"), "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund")
		if err == nil {
			err = makePM2Readable(dir)
		}
	}
	return err
}
func (s *Service) installPureFTP(ctx context.Context) error {
	if !exists(s.systemPath("/usr/sbin/pure-ftpd")) {
		if e := s.appDependencies(ctx, "pure-ftpd"); e != nil {
			return e
		}
	}
	dir := s.moduleDir("pure-ftpd")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	db := filepath.Join(dir, "users.pdb")
	if !exists(db) {
		text := filepath.Join(dir, "users.passwd")
		if e := atomicWrite(text, nil, 0600); e != nil {
			return e
		}
		if _, e := s.moduleCommand(ctx, 20*time.Second, "/usr/bin/pure-pw", "mkdb", db, "-f", text); e != nil {
			return e
		}
	}
	cert := filepath.Join(dir, "server.pem")
	if !exists(cert) {
		if _, e := s.moduleCommand(ctx, 20*time.Second, "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365", "-subj", "/CN=localhost", "-keyout", cert, "-out", cert); e != nil {
			return e
		}
		if e := os.Chmod(cert, 0600); e != nil {
			return e
		}
	}
	returnErr := error(nil)
	_, returnErr = s.Config.Run(ctx, "/usr/bin/systemctl", "enable", "--now", "panel-pure-ftpd.service")
	return returnErr
}
func (s *Service) moduleFTP(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	dir := s.moduleDir("pure-ftpd")
	text, db := filepath.Join(dir, "users.passwd"), filepath.Join(dir, "users.pdb")
	if action == "run" {
		out, e := s.moduleCommand(ctx, 20*time.Second, "/usr/bin/pure-pw", "list", "-f", text)
		return map[string]any{"users": out, "bind": "127.0.0.1:2121", "passive_ports": "30000-30049", "tls_required": true, "certificate": filepath.Join(dir, "server.pem")}, e
	}
	if !moduleResourceID.MatchString(in.Username) {
		return nil, errors.New("FTP 用户名需为 3–32 位小写标识")
	}
	backup, e := backupFile(text)
	if e != nil {
		return nil, e
	}
	if action == "create" {
		if len(in.Password) < 16 || len(in.Password) > 72 || strings.ContainsAny(in.Password, "\r\n\x00") {
			return nil, errors.New("密码需为 16–72 字节，不能含换行")
		}
		if e := s.ensureModuleSiteIdentity(ctx, in.SiteID); e != nil {
			return nil, e
		}
		f, e := s.openFiles(in.SiteID)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		if f.uid == 0 {
			return nil, errors.New("拒绝 root 所有的网站")
		}
		home := filepath.Join(s.Config.SitesDir, in.SiteID, "public")
		_, e = runCommandInput(ctx, []byte(in.Password+"\n"+in.Password+"\n"), "/usr/bin/pure-pw", "useradd", in.Username, "-f", text, "-u", strconv.Itoa(f.uid), "-g", strconv.Itoa(f.gid), "-d", home)
		if e != nil {
			return nil, errors.New("FTP 用户创建失败，用户名可能已存在")
		}
	} else if action == "delete" {
		if _, e = s.moduleCommand(ctx, 20*time.Second, "/usr/bin/pure-pw", "userdel", in.Username, "-f", text); e != nil {
			return nil, e
		}
	} else {
		return nil, errors.New("FTP 操作无效")
	}
	if _, e = s.moduleCommand(ctx, 20*time.Second, "/usr/bin/pure-pw", "mkdb", db, "-f", text); e != nil {
		_ = restoreFiles([]fileBackup{backup})
		return nil, e
	}
	return map[string]any{"ok": true, "username": in.Username, "action": action}, nil
}
func (s *Service) installPM2(ctx context.Context) error {
	if !s.appDependencyReady("pm2-manager") {
		return s.appDependencies(ctx, "pm2-manager")
	}
	return nil
}

type pm2App struct {
	ID        string `json:"id"`
	SiteID    string `json:"site_id"`
	Entry     string `json:"entry"`
	Port      int    `json:"port"`
	CreatedAt string `json:"created_at"`
}

func (s *Service) modulePM2(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	dir := filepath.Join(s.moduleDir("pm2-manager"), "apps")
	if action == "run" {
		paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		out := []any{}
		for _, p := range paths {
			var app pm2App
			if e := moduleRead(p, &app); e != nil {
				return nil, e
			}
			state, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pm2@"+app.ID)
			out = append(out, map[string]any{"app": app, "state": strings.TrimSpace(state)})
		}
		return map[string]any{"apps": out, "pm2_version": "7.0.4"}, nil
	}
	if !moduleResourceID.MatchString(in.ResourceID) {
		return nil, errors.New("PM2 标识无效")
	}
	path := filepath.Join(dir, in.ResourceID+".json")
	unit := "panel-pm2@" + in.ResourceID + ".service"
	var app pm2App
	if action == "create" {
		if exists(path) {
			return nil, errors.New("项目已存在")
		}
		if in.Port < 1024 || in.Port > 65535 || !core.ValidFilePath(in.Entry, false) || !strings.HasSuffix(in.Entry, ".js") {
			return nil, errors.New("端口或 JS 入口无效")
		}
		if e := s.ensureModuleSiteIdentity(ctx, in.SiteID); e != nil {
			return nil, e
		}
		f, e := s.openFiles(in.SiteID)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		file, e := regularFile(f.public, in.Entry)
		if e != nil {
			return nil, e
		}
		file.Close()
		if f.uid == 0 {
			return nil, errors.New("PM2 不允许 root 网站")
		}
		listener, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", in.Port))
		if e != nil {
			return nil, errors.New("端口已占用")
		}
		listener.Close()
		paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		if len(paths) >= 32 {
			return nil, errors.New("最多 32 个 PM2 项目")
		}
		for _, p := range paths {
			var other pm2App
			_ = moduleRead(p, &other)
			if other.Port == in.Port {
				return nil, errors.New("端口已分配")
			}
		}
		app = pm2App{in.ResourceID, in.SiteID, in.Entry, in.Port, core.Now()}
		if e = moduleWrite(path, app); e != nil {
			return nil, e
		}
		if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "enable", "--now", unit); e != nil {
			_ = os.Remove(path)
			return nil, e
		}
		return map[string]any{"app": app, "ok": true}, nil
	}
	if e := moduleRead(path, &app); e != nil {
		return nil, errors.New("PM2 项目不存在")
	}
	switch action {
	case "start", "stop", "restart":
		_, e := s.Config.Run(ctx, "/usr/bin/systemctl", action, unit)
		return map[string]any{"id": app.ID, "action": action, "ok": e == nil}, e
	case "logs":
		out, e := s.Config.Run(ctx, "/usr/bin/journalctl", "-u", unit, "-n", "100", "--no-pager", "-o", "cat")
		return map[string]any{"logs": out}, e
	case "delete":
		if _, e := s.Config.Run(ctx, "/usr/bin/systemctl", "disable", "--now", unit); e != nil {
			return nil, e
		}
		return map[string]any{"deleted": app.ID, "site_files_retained": true}, os.Remove(path)
	}
	return nil, errors.New("PM2 操作无效")
}

func (s *Service) ensureModuleSiteIdentity(ctx context.Context, id string) error {
	f, e := s.openFiles(id)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "start", "panel-site-user@"+id+".service"); e != nil {
		return e
	}
	account, e := user.Lookup(siteUser(id))
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if uid < 1 || f.uid != 0 && f.uid != uid {
		return errors.New("网站用户归属不匹配")
	}
	web, e := user.LookupGroup("www-data")
	if e != nil {
		return e
	}
	webgid, _ := strconv.Atoi(web.Gid)
	count := 0
	e = fs.WalkDir(f.public.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		count++
		if count > 10000 {
			return errors.New("网站文件数量超过身份准备上限")
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		file, err := f.public.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer file.Close()
		st, err := file.Stat()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() && !st.IsDir() {
			return errors.New("网站中存在特殊文件")
		}
		stat := st.Sys().(*syscall.Stat_t)
		if st.Mode().IsRegular() && stat.Nlink > 1 {
			return errors.New("拒绝修改多重硬链接文件的归属")
		}
		return file.Chown(uid, webgid)
	})
	if e != nil {
		return e
	}
	if e = f.root.MkdirAll("private", 0700); e != nil {
		return e
	}
	private, e := f.root.OpenFile("private", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer private.Close()
	return private.Chown(uid, gid)
}
func ServePM2(id string) error {
	if !moduleResourceID.MatchString(id) {
		return errors.New("PM2 标识无效")
	}
	s := New(Config{SitesDir: "/srv/panel/sites"})
	var app pm2App
	if e := moduleRead(filepath.Join(s.moduleDir("pm2-manager"), "apps", id+".json"), &app); e != nil {
		return e
	}
	if app.ID != id || !core.ValidID(app.SiteID) || !core.ValidFilePath(app.Entry, false) || app.Port < 1024 || app.Port > 65535 {
		return errors.New("PM2 清单无效")
	}
	f, e := s.openFiles(app.SiteID)
	if e != nil {
		return e
	}
	defer f.Close()
	entry, e := regularFile(f.public, app.Entry)
	if e != nil {
		return e
	}
	entry.Close()
	account, e := user.Lookup(siteUser(app.SiteID))
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if uid < 1 {
		return errors.New("PM2 用户无效")
	}
	home := filepath.Join(s.Config.SitesDir, app.SiteID, "private", "pm2-"+id)
	if e = os.MkdirAll(home, 0700); e != nil {
		return e
	}
	if e = os.Chown(home, uid, gid); e != nil {
		return e
	}
	if e = syscall.Setgroups([]int{gid}); e != nil {
		return e
	}
	if e = syscall.Setgid(gid); e != nil {
		return e
	}
	if e = syscall.Setuid(uid); e != nil {
		return e
	}
	project := filepath.Join(s.Config.SitesDir, app.SiteID, "public")
	if e = os.Chdir(project); e != nil {
		return e
	}
	binary := "/usr/bin/node"
	return syscall.Exec(binary, []string{binary, appNativeRoot + "/pm2/node_modules/pm2/bin/pm2-runtime", "start", app.Entry, "--name", id, "--instances", "1", "--max-memory-restart", "256M"}, []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=" + home, "PM2_HOME=" + home, "NODE_ENV=production", "HOST=127.0.0.1", "PORT=" + strconv.Itoa(app.Port)})
}

type nfsMount struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	ReadOnly bool   `json:"read_only"`
}

func validNFSSource(source string) bool {
	host, path, ok := strings.Cut(source, ":")
	return ok && (core.ValidDomain(host) || net.ParseIP(host) != nil) && strings.HasPrefix(path, "/") && !strings.Contains(path, "..") && !strings.ContainsAny(path, " \t\r\n\x00;") && len(source) < 512
}
func (s *Service) moduleNFS(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	dir := filepath.Join(s.moduleDir("nfs-manager"), "mounts")
	if action == "run" {
		paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		out := []any{}
		for _, p := range paths {
			var m nfsMount
			if e := moduleRead(p, &m); e != nil {
				return nil, e
			}
			mounted, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-nfs@"+m.ID)
			out = append(out, map[string]any{"mount": m, "state": strings.TrimSpace(mounted), "path": "/srv/panel/nfs/" + m.ID})
		}
		return map[string]any{"mounts": out}, nil
	}
	if !moduleResourceID.MatchString(in.ResourceID) {
		return nil, errors.New("挂载标识无效")
	}
	path := filepath.Join(dir, in.ResourceID+".json")
	unit := "panel-nfs@" + in.ResourceID + ".service"
	if action == "mount" {
		if !validNFSSource(in.Source) {
			return nil, errors.New("NFS 来源地址无效")
		}
		if exists(path) {
			return nil, errors.New("挂载已存在")
		}
		if e := moduleWrite(path, nfsMount{in.ResourceID, in.Source, in.ReadOnly}); e != nil {
			return nil, e
		}
		if _, e := s.Config.Run(ctx, "/usr/bin/systemctl", "enable", "--now", unit); e != nil {
			_ = os.Remove(path)
			return nil, e
		}
		return map[string]any{"mounted": in.ResourceID, "path": "/srv/panel/nfs/" + in.ResourceID}, nil
	}
	if action == "unmount" {
		var m nfsMount
		if e := moduleRead(path, &m); e != nil {
			return nil, errors.New("挂载不存在")
		}
		if _, e := s.Config.Run(ctx, "/usr/bin/systemctl", "disable", "--now", unit); e != nil {
			return nil, e
		}
		return map[string]any{"unmounted": m.ID}, os.Remove(path)
	}
	return nil, errors.New("NFS 操作无效")
}
func NFSMountOperation(id string, unmount bool) error {
	if !moduleResourceID.MatchString(id) {
		return errors.New("挂载标识无效")
	}
	s := New(Config{})
	var m nfsMount
	if e := moduleRead(filepath.Join(s.moduleDir("nfs-manager"), "mounts", id+".json"), &m); e != nil {
		return e
	}
	if m.ID != id || !validNFSSource(m.Source) {
		return errors.New("挂载清单无效")
	}
	target := filepath.Join("/srv/panel/nfs", id)
	if e := os.MkdirAll(target, 0700); e != nil {
		return e
	}
	if e := ordinary(target, true); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if unmount {
		_, e := s.moduleCommand(ctx, 25*time.Second, "/usr/bin/umount", target)
		return e
	}
	option := "rw"
	if m.ReadOnly {
		option = "ro"
	}
	_, e := s.moduleCommand(ctx, 25*time.Second, "/usr/bin/mount", "-t", "nfs", "-o", option+",nosuid,nodev,noexec,vers=4.2,timeo=50,retrans=2", m.Source, target)
	return e
}

func (s *Service) moduleLoadBalance(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	if !core.ValidDomain(in.Domain) {
		return nil, errors.New("负载均衡域名无效")
	}
	id := core.Hash(in.Domain)[:20]
	dir := filepath.Join(s.moduleDir("load-balance"), "balancers")
	metadata := filepath.Join(dir, id+".json")
	conf := filepath.Join(s.Config.ConfDir, "load-balance-"+id+".conf")
	if action == "probe" {
		var saved core.AppModuleInput
		if e := moduleRead(metadata, &saved); e != nil {
			return nil, errors.New("入口不存在")
		}
		nodes := []any{}
		for _, n := range saved.Nodes {
			conn, e := net.DialTimeout("tcp", n.Address, 2*time.Second)
			if conn != nil {
				conn.Close()
			}
			nodes = append(nodes, map[string]any{"address": n.Address, "healthy": e == nil})
		}
		return map[string]any{"domain": saved.Domain, "port": saved.Port, "nodes": nodes}, nil
	}
	old, e := backupFile(conf)
	if e != nil {
		return nil, e
	}
	oldMetadata, e := backupFile(metadata)
	if e != nil {
		return nil, e
	}
	if action == "remove" {
		if !exists(metadata) {
			return nil, errors.New("入口不存在")
		}
		if e = os.Remove(conf); e != nil {
			return nil, e
		}
	} else if action == "save" {
		if in.Port < 20000 || in.Port > 60000 || len(in.Nodes) < 2 || len(in.Nodes) > 16 {
			return nil, errors.New("端口应为 20000–60000，节点应为 2–16 个")
		}
		var previous core.AppModuleInput
		_ = moduleRead(metadata, &previous)
		if !old.existed || previous.Port != in.Port {
			listener, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", in.Port))
			if e != nil {
				return nil, errors.New("入口端口已占用")
			}
			listener.Close()
		}
		var content strings.Builder
		fmt.Fprintf(&content, "upstream panel_lb_%s {\n", id)
		if in.Sticky {
			content.WriteString("  ip_hash;\n")
		}
		for _, node := range in.Nodes {
			host, port, e := net.SplitHostPort(node.Address)
			if e != nil || net.ParseIP(host) == nil || port == "" {
				return nil, errors.New("上游必须使用固定 IP:端口")
			}
			p, e := strconv.Atoi(port)
			if e != nil || p < 1 || p > 65535 || node.Weight < 1 || node.Weight > 100 {
				return nil, errors.New("上游端口或权重无效")
			}
			ip := net.ParseIP(host)
			if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				return nil, errors.New("拒绝元数据、组播和未指定地址")
			}
			backup := ""
			if node.Backup {
				if in.Sticky {
					return nil, errors.New("粘滞模式不能使用备用节点")
				}
				backup = " backup"
			}
			fmt.Fprintf(&content, "  server %s weight=%d max_fails=1 fail_timeout=5s%s;\n", node.Address, node.Weight, backup)
		}
		fmt.Fprintf(&content, "}\nserver { listen 127.0.0.1:%d; server_name %s; location / { proxy_pass http://panel_lb_%s; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_connect_timeout 2s; proxy_read_timeout 30s; proxy_next_upstream error timeout http_502 http_503 http_504; } }\n", in.Port, in.Domain, id)
		if e = atomicWrite(conf, []byte(content.String()), 0644); e != nil {
			return nil, e
		}
	} else {
		return nil, errors.New("负载均衡操作无效")
	}
	if action == "remove" {
		e = os.Remove(metadata)
	} else {
		e = moduleWrite(metadata, core.AppModuleInput{Domain: in.Domain, Port: in.Port, Nodes: in.Nodes, Sticky: in.Sticky})
	}
	if e != nil {
		_ = restoreFiles([]fileBackup{old, oldMetadata})
		return nil, e
	}
	if _, e = s.Config.Run(ctx, s.Config.NginxBin, "-t"); e == nil {
		_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx")
	}
	if e != nil {
		_ = restoreFiles([]fileBackup{old, oldMetadata})
		_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "reload", "nginx")
		return nil, e
	}
	if action == "remove" {
		return map[string]any{"removed": in.Domain}, nil
	}
	return map[string]any{"domain": in.Domain, "port": in.Port, "nodes": in.Nodes, "ok": true}, nil
}

const apacheWAFInclude = "IncludeOptional /etc/panel/security-apps/modules/apache-waf/rules.conf\n"

func (s *Service) apacheModuleWAF(ctx context.Context, install bool) error {
	release, e := apacheRelease()
	if e != nil {
		return e
	}
	path := filepath.Join(s.moduleDir("apache-waf"), "rules.conf")
	old, e := backupFile(path)
	if e != nil {
		return e
	}
	config, e := backupFile(s.Config.ApacheSiteConfig)
	if e != nil {
		return e
	}
	if !config.existed {
		return errors.New("请先创建一个 Apache 网站")
	}
	if install {
		rules := `# CloudStack Apache request firewall: fixed auditable request rules, not a full CRS engine.
RewriteEngine On
RewriteOptions InheritDownBefore
RewriteCond %{REQUEST_METHOD} ^(?:TRACE|TRACK)$ [NC,OR]
RewriteCond %{HTTP_USER_AGENT} (sqlmap|nikto|masscan|acunetix|nessus|wpscan) [NC,OR]
RewriteCond %{QUERY_STRING} (union(?:%20|\+)+select|(?:%3c|<)script|/etc/passwd|%2e%2e%2f) [NC,OR]
RewriteCond %{REQUEST_URI} (/etc/passwd|\.\./|%2e%2e%2f) [NC]
RewriteRule ^ - [F,L]
Header always set X-Panel-Apache-WAF active
`
		if e = atomicWrite(path, []byte(rules), 0644); e != nil {
			return e
		}
		updated := regexp.MustCompile(`(?ms)^<VirtualHost[^>]+>.*?</VirtualHost>`).ReplaceAllStringFunc(string(config.data), func(block string) string {
			if strings.Contains(block, apacheWAFInclude) {
				return block
			}
			return strings.Replace(block, "\n", "\n  "+apacheWAFInclude, 1)
		})
		if e = atomicWrite(s.Config.ApacheSiteConfig, []byte(updated), 0644); e != nil {
			return e
		}
	} else {
		if e = os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	if _, e = s.Config.Run(ctx, release.CLI(), "-t", "-f", s.Config.ApacheSiteConfig); e == nil {
		_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "restart", "panel-apache")
	}
	if e != nil {
		_ = restoreFiles([]fileBackup{old, config})
		_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "restart", "panel-apache")
	}
	return e
}
func (s *Service) apacheWAFReport(ctx context.Context) (any, error) {
	r, e := apacheRelease()
	if e != nil {
		return nil, e
	}
	out, e := s.Config.Run(ctx, r.CLI(), "-t", "-f", s.Config.ApacheSiteConfig)
	return map[string]any{"syntax_ok": e == nil, "output": out, "rules": filepath.Join(s.moduleDir("apache-waf"), "rules.conf")}, e
}

func (s *Service) enableAnalyticsLogs(ctx context.Context) error {
	previous, e := backupFile(s.Config.NginxConf)
	if e != nil {
		return e
	}
	source := string(previous.data)
	if strings.Contains(source, `"agent":"$http_user_agent"`) {
		return nil
	}
	pattern := regexp.MustCompile(`(?m)^\s*log_format panel_site escape=json '[^\n]*';`)
	if !pattern.MatchString(source) {
		return errors.New("找不到受管网站日志格式，拒绝改写自定义日志配置")
	}
	line := `  log_format panel_site escape=json '{"time":"$time_iso8601","remote":"$remote_addr","method":"$request_method","path":"$panel_log_path","status":$status,"bytes":$body_bytes_sent,"seconds":$request_time,"agent":"$http_user_agent","referer":"$panel_log_referer"}';`
	source = pattern.ReplaceAllStringFunc(source, func(string) string { return line })
	source = strings.Replace(source, line, line+"\n  map $http_referer $panel_log_referer { ~^(?<panel_referer_base>[^?]*) $panel_referer_base; default ''; }", 1)
	if e = atomicWrite(s.Config.NginxConf, []byte(source), previous.mode); e != nil {
		return e
	}
	if _, e = s.Config.Run(ctx, s.Config.NginxBin, "-t"); e == nil {
		_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx")
	}
	if e != nil {
		_ = restoreFiles([]fileBackup{previous})
		_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "reload", "nginx")
	}
	return e
}

func (s *Service) appDependencyReady(id string) bool {
	switch id {
	case "pure-ftpd":
		return exists(s.systemPath("/usr/sbin/pure-ftpd"))
	case "pm2-manager":
		var result struct {
			OK      bool   `json:"ok"`
			LockSHA string `json:"lock_sha256"`
		}
		st, e := os.Stat(s.systemPath(appNativeRoot))
		lock, lockErr := os.ReadFile(s.systemPath(appNativeRoot + "/pm2/package-lock.json"))
		return e == nil && lockErr == nil && core.Hash(string(lock)) == core.Hash(string(pm2Lock)) && st.Mode().Perm()&0005 == 0005 && moduleRead(filepath.Join(s.moduleDir(id), "dependency-result.json"), &result) == nil && result.OK && result.LockSHA == core.Hash(string(pm2Lock)) && exists(s.systemPath(appNativeRoot+"/pm2/node_modules/pm2/bin/pm2"))
	case "nfs-manager":
		return exists(s.systemPath("/sbin/mount.nfs")) || exists(s.systemPath("/usr/sbin/mount.nfs"))
	}
	return false
}

func makePM2Readable(dir string) error {
	if e := os.Chmod(appNativeRoot, 0755); e != nil {
		return e
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() && d.Name() == ".cache" {
			return fs.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		st, e := d.Info()
		if e != nil {
			return e
		}
		mode := os.FileMode(0644)
		if d.IsDir() || st.Mode().Perm()&0111 != 0 {
			mode = 0755
		}
		return os.Chmod(path, mode)
	})
}
func (s *Service) appDependencyRoutes(m *http.ServeMux) {
	for _, method := range []string{"GET", "POST"} {
		m.HandleFunc(method+" /v1/app-dependencies/{id}", func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if id != "pure-ftpd" && id != "pm2-manager" && id != "nfs-manager" {
				respond(w, 400, map[string]string{"error": "依赖标识无效"})
				return
			}
			unit := "panel-app-dependencies@" + id
			state, _ := s.Config.Run(r.Context(), "/usr/bin/systemctl", "show", "--property=ActiveState", "--value", unit)
			state = strings.TrimSpace(state)
			if state == "activating" || state == "active" {
				respond(w, 200, map[string]string{"state": "running"})
				return
			}
			if s.appDependencyReady(id) {
				respond(w, 200, map[string]string{"state": "ready"})
				return
			}
			if r.Method == "POST" && state != "activating" && state != "active" {
				if _, e := s.Config.Run(r.Context(), "/usr/bin/systemctl", "start", "--no-block", unit); e != nil {
					respond(w, 409, map[string]string{"error": e.Error()})
					return
				}
				state = "activating"
			}
			if state == "failed" {
				respond(w, 200, map[string]string{"state": "failed", "error": "请查看 journalctl -u " + unit})
				return
			}
			respond(w, 200, map[string]string{"state": "running"})
		})
	}
}
