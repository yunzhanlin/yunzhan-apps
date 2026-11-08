//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	sftpJobs      = "/var/lib/panel-executor/sftp-jobs"
	sftpUsers     = "/var/lib/panel-executor/sftp-users"
	sftpRoot      = "/srv/panel/sftp"
	sftpGroup     = "panel-sftp"
	sftpSSHD      = "/etc/ssh/sshd_config.d/90-panel-sftp.conf"
	sftpUserShell = "/usr/sbin/nologin"
)

var sftpUserPattern = regexp.MustCompile(`^psftp-[a-f0-9]{12}$`)

type sftpManifest struct {
	SiteID   string `json:"site_id"`
	Username string `json:"username"`
}

func validateSFTPJob(v core.SFTPJobRequest) error {
	if !core.ValidID(v.JobID) || !core.ValidID(v.SiteID) || !sftpUserPattern.MatchString(v.Username) {
		return errors.New("SFTP 作业身份无效")
	}
	switch v.Action {
	case "create", "password":
		if len(v.Password) < 16 || len(v.Password) > 72 || strings.ContainsAny(v.Password, "\r\n:\x00") {
			return errors.New("SFTP 密码格式无效")
		}
	case "enable", "disable", "delete":
		if v.Password != "" {
			return errors.New("SFTP 作业包含多余密码")
		}
	default:
		return errors.New("SFTP 作业动作无效")
	}
	return nil
}

func sftpManifestPath(username string) string { return filepath.Join(sftpUsers, username+".json") }
func sftpChroot(username string) string       { return filepath.Join(sftpRoot, username) }
func sftpMountpoint(username string) string   { return filepath.Join(sftpChroot(username), "site") }

func readSFTPManifest(username string) (sftpManifest, error) {
	var m sftpManifest
	if !sftpUserPattern.MatchString(username) {
		return m, errors.New("SFTP 用户名无效")
	}
	b, e := os.ReadFile(sftpManifestPath(username))
	if e == nil {
		e = json.Unmarshal(b, &m)
	}
	if e == nil && (m.Username != username || !core.ValidID(m.SiteID)) {
		e = errors.New("SFTP 账户清单不匹配")
	}
	return m, e
}

func sftpCommand(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin = stdin
	out := &boundedBuffer{max: 32 * 1024}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = time.Second
	if e := cmd.Run(); e != nil {
		return out.String(), fmt.Errorf("%s: %w: %s", filepath.Base(name), e, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func sftpPassword(ctx context.Context, username, password string) error {
	_, e := sftpCommand(ctx, strings.NewReader(username+":"+password+"\n"), "/usr/sbin/chpasswd")
	return e
}

func sftpTerminate(username string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = sftpCommand(ctx, nil, "/usr/bin/pkill", "-KILL", "-u", username)
}

func sftpMountUnit(ctx context.Context, username string) (string, error) {
	out, e := sftpCommand(ctx, nil, "/usr/bin/systemd-escape", "--path", "--suffix=mount", sftpMountpoint(username))
	if e != nil {
		return "", e
	}
	unit := strings.TrimSpace(out)
	if unit == "" || strings.ContainsAny(unit, "/\x00\r\n") || !strings.HasSuffix(unit, ".mount") {
		return "", errors.New("无法生成 SFTP 挂载单元名")
	}
	return unit, nil
}

func ensureSFTPSSHD(ctx context.Context) error {
	if _, e := sftpCommand(ctx, nil, "/usr/sbin/groupadd", "--system", "--force", sftpGroup); e != nil {
		return e
	}
	content := `# Managed by 云栈面板. Manual changes are overwritten.
Match Group panel-sftp
    ChrootDirectory /srv/panel/sftp/%u
    ForceCommand internal-sftp -d /site
    DisableForwarding yes
    PasswordAuthentication yes
    PubkeyAuthentication no
`
	if e := os.MkdirAll(filepath.Dir(sftpSSHD), 0755); e != nil {
		return e
	}
	if e := atomicWrite(sftpSSHD, []byte(content), 0644); e != nil {
		return e
	}
	if _, e := sftpCommand(ctx, nil, "/usr/sbin/sshd", "-t"); e != nil {
		return fmt.Errorf("SSH 配置校验失败: %w", e)
	}
	_, e := sftpCommand(ctx, nil, "/usr/bin/systemctl", "reload", "ssh.service")
	return e
}

func verifySFTPSource(siteID string) (string, error) {
	siteDir := filepath.Join("/srv/panel/sites", siteID)
	public := filepath.Join(siteDir, "public")
	if e := ordinary(siteDir, true); e != nil {
		return "", e
	}
	if e := ordinary(public, true); e != nil {
		return "", e
	}
	b, e := os.ReadFile(filepath.Join(siteDir, ".panel-site.json"))
	if e != nil {
		return "", e
	}
	var marker map[string]string
	if json.Unmarshal(b, &marker) != nil || marker["id"] != siteID {
		return "", errors.New("站点目录归属不匹配")
	}
	return public, nil
}

func verifySFTPIdentity(m sftpManifest) error {
	u, e := user.Lookup(m.Username)
	if e != nil {
		return errors.New("SFTP 系统账户不存在")
	}
	g, e := user.LookupGroup(sftpGroup)
	if e != nil || u.Gid != g.Gid || u.HomeDir != "/site" {
		return errors.New("SFTP 系统账户归属异常")
	}
	return nil
}

func createSFTP(ctx context.Context, op core.SFTPJobRequest) (ret error) {
	if _, e := os.Lstat(sftpManifestPath(op.Username)); !errors.Is(e, os.ErrNotExist) {
		return errors.New("SFTP 账户已经存在")
	}
	if _, e := user.Lookup(op.Username); e == nil {
		return errors.New("同名系统账户已经存在")
	}
	source, e := verifySFTPSource(op.SiteID)
	if e != nil {
		return e
	}
	if e = ensureSFTPSSHD(ctx); e != nil {
		return e
	}
	if e = os.MkdirAll(sftpUsers, 0700); e != nil {
		return e
	}
	if e = os.MkdirAll(sftpRoot, 0755); e != nil {
		return e
	}
	if _, e = sftpCommand(ctx, nil, "/usr/sbin/useradd", "--system", "--gid", sftpGroup, "--no-create-home", "--home-dir", "/site", "--shell", sftpUserShell, "--comment", "panel-sftp-"+op.SiteID, op.Username); e != nil {
		return e
	}
	defer func() {
		if ret != nil {
			sftpTerminate(op.Username)
			_, _ = sftpCommand(context.Background(), nil, "/usr/sbin/userdel", op.Username)
		}
	}()
	if e = sftpPassword(ctx, op.Username, op.Password); e != nil {
		return e
	}
	chroot, target := sftpChroot(op.Username), sftpMountpoint(op.Username)
	if e = os.MkdirAll(target, 0755); e != nil {
		return e
	}
	if e = os.Chown(chroot, 0, 0); e != nil {
		return e
	}
	if e = os.Chmod(chroot, 0755); e != nil {
		return e
	}
	if e = os.Chown(target, 0, 0); e != nil {
		return e
	}
	if e = os.Chmod(target, 0755); e != nil {
		return e
	}
	if _, e = sftpCommand(ctx, nil, "/usr/bin/setfacl", "-R", "-m", "u:"+op.Username+":rwX", source); e != nil {
		return e
	}
	if _, e = sftpCommand(ctx, nil, "/usr/bin/setfacl", "-d", "-m", "u:"+op.Username+":rwx", source); e != nil {
		return e
	}
	defer func() {
		if ret != nil {
			_, _ = sftpCommand(context.Background(), nil, "/usr/bin/setfacl", "-R", "-x", "u:"+op.Username, source)
			_, _ = sftpCommand(context.Background(), nil, "/usr/bin/setfacl", "-d", "-x", "u:"+op.Username, source)
		}
	}()
	unit, e := sftpMountUnit(ctx, op.Username)
	if e != nil {
		return e
	}
	unitPath := filepath.Join("/etc/systemd/system", unit)
	unitText := fmt.Sprintf(`[Unit]
Description=Panel SFTP site mount for %s
Before=ssh.service

[Mount]
What=%s
Where=%s
Type=none
Options=bind

[Install]
WantedBy=multi-user.target
`, op.Username, source, target)
	if e = atomicWrite(unitPath, []byte(unitText), 0644); e != nil {
		return e
	}
	defer func() {
		if ret != nil {
			_, _ = sftpCommand(context.Background(), nil, "/usr/bin/systemctl", "disable", "--now", unit)
			_ = os.Remove(unitPath)
			_, _ = sftpCommand(context.Background(), nil, "/usr/bin/systemctl", "daemon-reload")
			_ = os.RemoveAll(chroot)
		}
	}()
	if _, e = sftpCommand(ctx, nil, "/usr/bin/systemctl", "daemon-reload"); e != nil {
		return e
	}
	if _, e = sftpCommand(ctx, nil, "/usr/bin/systemctl", "enable", "--now", unit); e != nil {
		return e
	}
	manifest := sftpManifest{SiteID: op.SiteID, Username: op.Username}
	if e = writeJSON(sftpManifestPath(op.Username), manifest); e != nil {
		return e
	}
	return nil
}

func deleteSFTP(ctx context.Context, op core.SFTPJobRequest) error {
	m, e := readSFTPManifest(op.Username)
	if e != nil {
		return e
	}
	if m.SiteID != op.SiteID {
		return errors.New("SFTP 账户与站点不匹配")
	}
	source, sourceErr := verifySFTPSource(op.SiteID)
	unit, e := sftpMountUnit(ctx, op.Username)
	if e != nil {
		return e
	}
	sftpTerminate(op.Username)
	_, _ = sftpCommand(ctx, nil, "/usr/bin/systemctl", "disable", "--now", unit)
	if e = os.Remove(filepath.Join("/etc/systemd/system", unit)); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	_, _ = sftpCommand(ctx, nil, "/usr/bin/systemctl", "daemon-reload")
	if sourceErr == nil {
		_, _ = sftpCommand(ctx, nil, "/usr/bin/setfacl", "-R", "-x", "u:"+op.Username, source)
		_, _ = sftpCommand(ctx, nil, "/usr/bin/setfacl", "-d", "-x", "u:"+op.Username, source)
	}
	if _, lookupErr := user.Lookup(op.Username); lookupErr == nil {
		if _, e = sftpCommand(ctx, nil, "/usr/sbin/userdel", op.Username); e != nil {
			return e
		}
	}
	if e = os.RemoveAll(sftpChroot(op.Username)); e != nil {
		return e
	}
	return os.Remove(sftpManifestPath(op.Username))
}

func applySFTPJob(ctx context.Context, op core.SFTPJobRequest) error {
	if op.Action == "create" {
		return createSFTP(ctx, op)
	}
	m, e := readSFTPManifest(op.Username)
	if e != nil {
		return e
	}
	if m.SiteID != op.SiteID {
		return errors.New("SFTP 账户与站点不匹配")
	}
	if op.Action == "delete" {
		return deleteSFTP(ctx, op)
	}
	if e = verifySFTPIdentity(m); e != nil {
		return e
	}
	switch op.Action {
	case "password":
		e = sftpPassword(ctx, op.Username, op.Password)
		sftpTerminate(op.Username)
	case "disable":
		_, e = sftpCommand(ctx, nil, "/usr/sbin/usermod", "--lock", op.Username)
		sftpTerminate(op.Username)
	case "enable":
		_, e = sftpCommand(ctx, nil, "/usr/sbin/usermod", "--unlock", op.Username)
	default:
		e = errors.New("SFTP 作业动作无效")
	}
	return e
}

func readSFTPJob(id string) (core.SFTPJobRequest, error) {
	var op core.SFTPJobRequest
	if !core.ValidID(id) {
		return op, errors.New("SFTP 作业标识无效")
	}
	b, e := os.ReadFile(filepath.Join(sftpJobs, id+".request.json"))
	if e == nil {
		e = json.Unmarshal(b, &op)
	}
	if e == nil && (op.JobID != id || validateSFTPJob(op) != nil) {
		e = errors.New("SFTP 作业参数无效")
	}
	return op, e
}

// RunSFTPJob executes one validated root-only operating-system change. The
// secret request is removed before any external command is started.
func RunSFTPJob(id string) (ret error) {
	op, e := readSFTPJob(id)
	if e != nil {
		return e
	}
	requestPath := filepath.Join(sftpJobs, id+".request.json")
	if e = os.Remove(requestPath); e != nil {
		return e
	}
	result := core.SFTPJobResult{State: "failed", Username: op.Username}
	defer func() {
		if ret == nil {
			result.State = "succeeded"
			result.Message = "SFTP 系统账户操作完成"
		} else {
			result.Message = ret.Error()
		}
		if writeErr := writeJSON(filepath.Join(sftpJobs, id+".result.json"), result); ret == nil {
			ret = writeErr
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return applySFTPJob(ctx, op)
}

func writeExclusiveJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, writeErr := f.Write(b)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (s *Service) sftpRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sftp/jobs", func(w http.ResponseWriter, r *http.Request) {
		var op core.SFTPJobRequest
		if !readJSON(w, r, &op) {
			return
		}
		if e := validateSFTPJob(op); e != nil {
			respond(w, 400, map[string]string{"error": e.Error()})
			return
		}
		if e := os.MkdirAll(sftpJobs, 0700); e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		requestPath := filepath.Join(sftpJobs, op.JobID+".request.json")
		if e := writeExclusiveJSON(requestPath, op); e != nil {
			respond(w, 409, map[string]string{"error": "SFTP 作业标识已存在"})
			return
		}
		defer os.Remove(requestPath)
		unit := "panel-sftp-job@" + op.JobID + ".service"
		_, startErr := s.Config.Run(r.Context(), "/usr/bin/systemctl", "start", unit)
		var result core.SFTPJobResult
		b, readErr := os.ReadFile(filepath.Join(sftpJobs, op.JobID+".result.json"))
		if readErr == nil {
			readErr = json.Unmarshal(b, &result)
		}
		if readErr != nil {
			if startErr != nil {
				respond(w, 500, map[string]string{"error": "SFTP 系统作业启动失败"})
			} else {
				respond(w, 500, map[string]string{"error": "SFTP 系统作业未返回结果"})
			}
			return
		}
		if result.Username != op.Username || result.State != "succeeded" {
			respond(w, 409, map[string]string{"error": result.Message})
			return
		}
		respond(w, 200, result)
	})
}
