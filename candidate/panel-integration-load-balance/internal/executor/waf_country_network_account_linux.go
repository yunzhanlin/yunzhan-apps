//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const countryNetworkUsername = "panel-country-net"
const countryNetworkAccountComment = "panel-waf-country-network"

type countryNetworkIdentity struct {
	Format int    `json:"format"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

func validCountryNetworkIdentity(v countryNetworkIdentity) bool {
	return v.Format == 1 && v.UID > 0 && v.UID < 1000 && v.GID > 0 && v.GID < 1000
}

func countryNetworkNamedIdentity() (countryNetworkIdentity, error) {
	var empty countryNetworkIdentity
	account, err := user.Lookup(countryNetworkUsername)
	if err != nil || account.Username != countryNetworkUsername || account.Name != countryNetworkAccountComment || account.HomeDir != "/nonexistent" {
		return empty, errors.New("国家数据专用账户归属无效")
	}
	uid, uerr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gerr := strconv.ParseUint(account.Gid, 10, 32)
	v := countryNetworkIdentity{1, uint32(uid), uint32(gid)}
	if uerr != nil || gerr != nil || !validCountryNetworkIdentity(v) || strconv.FormatUint(uid, 10) != account.Uid || strconv.FormatUint(gid, 10) != account.Gid {
		return empty, errors.New("国家数据账户不是独立非Root系统账户")
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil || group.Name != countryNetworkUsername {
		return empty, errors.New("国家数据专用组身份不符")
	}
	reverse, err := user.LookupId(account.Uid)
	if err != nil || reverse.Username != countryNetworkUsername {
		return empty, errors.New("国家数据UID存在其他归属")
	}
	return v, nil
}

func (s *Service) countryNetworkAccount(ctx context.Context) (countryNetworkIdentity, error) {
	var empty countryNetworkIdentity
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || s.Config.SystemRoot != "/" {
		return empty, errors.New("国家数据账户只允许固定Root读取")
	}
	path := filepath.Join(s.moduleDir("nginx-waf"), "country-network-account.json")
	raw, err := ftpPrivateRead(path, 2048)
	var record countryNetworkIdentity
	if err != nil || countryCacheDecode(raw, &record) != nil || !validCountryNetworkIdentity(record) {
		return empty, errors.New("国家数据受管账户原始记录不存在或不完整；未接管同名用户")
	}
	actual, err := countryNetworkNamedIdentity()
	if err != nil || actual != record {
		return empty, errors.New("国家数据账户与原始受管记录不符")
	}
	passwd, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/getent", "passwd", countryNetworkUsername)
	want := fmt.Sprintf("%s:x:%d:%d:%s:/nonexistent:/usr/sbin/nologin\n", countryNetworkUsername, record.UID, record.GID, countryNetworkAccountComment)
	if err != nil || passwd != want {
		return empty, errors.New("国家数据专用账户的完整身份改变")
	}
	group, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/getent", "group", countryNetworkUsername)
	if err != nil || group != fmt.Sprintf("%s:x:%d:\n", countryNetworkUsername, record.GID) {
		return empty, errors.New("国家数据专用组存在其他成员或身份改变")
	}
	groups, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/id", "-G", countryNetworkUsername)
	if err != nil || strings.TrimSpace(groups) != strconv.FormatUint(uint64(record.GID), 10) {
		return empty, errors.New("国家数据专用账户带有额外权限组")
	}
	return record, nil
}

// Called only by explicit fixed dependency installation, never an observation
// or a transfer worker. Unknown names/partial preparation are retained, not
// adopted, repaired, deleted or silently retried.
func (s *Service) prepareCountryNetworkAccount(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.Config.SystemRoot != "/" || os.Geteuid() != 0 {
		return errors.New("国家数据账户只能在固定依赖安装中创建")
	}
	dir := s.moduleDir("nginx-waf")
	if err := threatIDSTrustedParents(dir, true); err != nil {
		return err
	}
	record := filepath.Join(dir, "country-network-account.json")
	if _, err := os.Lstat(record); err == nil {
		_, err = s.countryNetworkAccount(ctx)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, kind := range []string{"passwd", "group"} {
		output, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/getent", kind, countryNetworkUsername)
		var exit *exec.ExitError
		if output != "" || !errors.As(err, &exit) || exit.ExitCode() != 2 {
			return errors.New("国家数据同名账户/组已存在或查询未确认缺失；未接管")
		}
	}
	if _, err := s.moduleCommand(ctx, 5*time.Second, "/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--comment", countryNetworkAccountComment, countryNetworkUsername); err != nil {
		return errors.New("国家数据账户创建未确认；保留现场，不自动重放")
	}
	identity, err := countryNetworkNamedIdentity()
	if err != nil {
		return err
	}
	raw, err := countryCacheJSON(identity)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := countryCacheWriteNew(root, "country-network-account.json", raw); err != nil {
		return err
	}
	_, err = s.countryNetworkAccount(ctx)
	return err
}
