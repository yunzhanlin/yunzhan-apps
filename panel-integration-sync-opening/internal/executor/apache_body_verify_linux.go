//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"local/panel/internal/core"
)

func readApacheBodyBuildRecord(id string) (apacheBodyBuildRecord, error) {
	if !core.ValidID(id) {
		return apacheBodyBuildRecord{}, errors.New("Apache 请求体任务标识无效")
	}
	if err := apacheBodyOwnedAncestors(apacheBodyJobs); err != nil {
		return apacheBodyBuildRecord{}, err
	}
	if st, err := os.Lstat(apacheBodyJobs); err != nil || st.Mode().Perm() != 0700 {
		return apacheBodyBuildRecord{}, errors.New("Apache 构建记录目录不是私有目录")
	}
	path := filepath.Join(apacheBodyJobs, id+".json")
	return readApacheBodyRecordAt(path, id)
}

func readApacheBodyRecordAt(path, id string) (apacheBodyBuildRecord, error) {
	var record apacheBodyBuildRecord
	if !core.ValidID(id) {
		return record, errors.New("Apache 请求体任务标识无效")
	}
	if err := ownedRuntimePath(path, false); err != nil {
		return record, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return record, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 || st.Size() == 0 || st.Mode().Perm() != 0600 {
		return record, errors.New("Apache 构建记录类型、权限或大小异常")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return record, errors.New("Apache 构建记录所有者或链接数异常")
	}
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || int64(len(b)) != st.Size() || len(b) > 64<<10 {
		return record, errors.New("Apache 构建记录读取失败、变化或超限")
	}
	if err := apacheBodyDecodeJSON(b, &record); err != nil {
		return record, err
	}
	if record.JobID != id {
		return record, errors.New("Apache 构建记录含额外数据或任务身份不匹配")
	}
	return record, nil
}

// Read-only prerequisite. Rehash actual runtime, module and every release byte;
// an old ready flag cannot authorize changed rules or a different Apache ABI.
func VerifyApacheBodyBuild(id string) error {
	return verifyApacheBodyBuildContext(context.Background(), id)
}

func verifyApacheBodyBuildContext(parent context.Context, id string) error {
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	record, err := readApacheBodyBuildRecord(id)
	if err != nil {
		return err
	}
	if err := apacheBodyRecordContract(record); err != nil {
		return err
	}
	return verifyApacheBodyRetainedBytes(ctx, record)
}

// Only rehashes actual immutable bytes. Callers must first check the current
// activation contract or the closed historical inspection contract. No module
// executes, no program loads, and no record is migrated or rewritten here.
func verifyApacheBodyRetainedBytes(ctx context.Context, record apacheBodyBuildRecord) error {
	r, err := apacheRelease()
	if err != nil || r.CLI() != record.ApacheBinary {
		return errors.New("当前 Apache 程序选择与构建记录不匹配")
	}
	for _, item := range []struct{ path, sha string }{{r.CLI(), record.ApacheSHA}, {filepath.Join(record.Prefix, "apache/mod_security2.so"), record.ModuleSHA}} {
		actual, err := wafNativeFileSHA(ctx, item.path, 64<<20)
		if err != nil || actual != item.sha {
			return errors.New("Apache 实际程序或请求体模块缺失、变化或摘要错误")
		}
	}
	actual, err := runtimeTreeSHA(ctx, record.Prefix, record.Prefix)
	if err != nil || actual != record.TreeSHA {
		return errors.New("Apache 完整请求体程序、规则或许可目录发生变化；拒绝启用")
	}
	return ctx.Err()
}
