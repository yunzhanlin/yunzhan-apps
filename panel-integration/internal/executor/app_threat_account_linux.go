//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type threatIDSAccount struct {
	Format int    `json:"format"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

func validateThreatIDSAccount(v threatIDSAccount) error {
	if v.Format != 1 || v.UID == 0 || v.GID == 0 || v.UID >= 1000 || v.GID >= 1000 {
		return errors.New("IDS 专用非 root 系统账户身份无效")
	}
	return nil
}

func (s *Service) threatIDSAccount(ctx context.Context) (threatIDSAccount, error) {
	var v threatIDSAccount
	b, err := ftpPrivateRead(filepath.Join(s.moduleDir("network-threat-detection"), "capture-account.json"), 2048)
	if err != nil {
		return v, err
	}
	if decodeThreatIDSPrivateJSON(b, &v) != nil || validateThreatIDSAccount(v) != nil {
		return v, errors.New("IDS 私有账户记录损坏或不完整；未接管系统账户")
	}
	passwd, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/getent", "passwd", "panel-network-ids")
	if err != nil {
		return v, errors.New("IDS 专用系统账户不可读取")
	}
	fields := strings.Split(strings.TrimSpace(passwd), ":")
	if len(fields) != 7 || fields[0] != "panel-network-ids" || fields[1] != "x" || fields[2] != strconv.FormatUint(uint64(v.UID), 10) || fields[3] != strconv.FormatUint(uint64(v.GID), 10) || fields[4] != "" || fields[5] != "/nonexistent" || fields[6] != "/usr/sbin/nologin" {
		return v, errors.New("IDS 专用账户与私有记录不符")
	}
	group, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/getent", "group", "panel-network-ids")
	if err != nil || strings.TrimSpace(group) != fmt.Sprintf("panel-network-ids:x:%d:", v.GID) {
		return v, errors.New("IDS 专用组身份或成员已改变")
	}
	groups, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/id", "-G", "panel-network-ids")
	actualGroups := strings.Fields(groups)
	if err != nil || len(actualGroups) != 1 || actualGroups[0] != strconv.FormatUint(uint64(v.GID), 10) {
		return v, errors.New("IDS 账户存在额外或未知附加组；未带入低权限单元")
	}
	return v, nil
}

// Only explicit fixed root dependency setup calls this function. A pre-existing
// name without a private ownership record is never silently adopted/deleted.
func (s *Service) prepareThreatIDSAccount(ctx context.Context) error {
	if s.Config.SystemRoot != "/" || os.Geteuid() != 0 {
		return errors.New("IDS 系统账户只能由固定 root 准备服务创建")
	}
	dir := s.moduleDir("network-threat-detection")
	if err := threatIDSTrustedParents(dir, true); err != nil {
		return err
	}
	record := filepath.Join(dir, "capture-account.json")
	if _, err := os.Lstat(record); err == nil {
		_, err = s.threatIDSAccount(ctx)
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, kind := range []string{"passwd", "group"} {
		output, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/getent", kind, "panel-network-ids")
		if err == nil || output != "" {
			return errors.New("现有 IDS 同名账户或组没有受管记录；保留而不接管")
		}
		// moduleCommand wraps the exact getent failure. Only exit 2 proves absence.
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 {
			return errors.New("IDS 同名账户查询故障；未当作不存在")
		}
	}
	if _, err := s.moduleCommand(ctx, 5*time.Second, "/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "panel-network-ids"); err != nil {
		return errors.New("IDS 专用账户准备失败；保留现场，不自动删除账户")
	}
	passwd, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/getent", "passwd", "panel-network-ids")
	if err != nil {
		return err
	}
	fields := strings.Split(strings.TrimSpace(passwd), ":")
	if len(fields) != 7 {
		return errors.New("IDS 新账户身份不能确认；保留现场")
	}
	uid, e1 := strconv.ParseUint(fields[2], 10, 32)
	gid, e2 := strconv.ParseUint(fields[3], 10, 32)
	v := threatIDSAccount{Format: 1, UID: uint32(uid), GID: uint32(gid)}
	if e1 != nil || e2 != nil || validateThreatIDSAccount(v) != nil {
		return errors.New("IDS 新账户不在非 root 系统账户范围；保留现场")
	}
	if err := moduleWrite(record, v); err != nil {
		return err
	}
	_, err = s.threatIDSAccount(ctx)
	return err
}
