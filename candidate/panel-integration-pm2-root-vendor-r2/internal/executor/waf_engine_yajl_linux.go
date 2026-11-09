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
)

// Freeze only these headers while the SHA-verified extracted source is still
// root-owned. No source compiler, shared build UID or pkg-config supplies them.
func collectNginxPrivateYAJLHeaders(ctx context.Context, work, assets string) error {
	for _, name := range []string{"yajl_common.h", "yajl_parse.h", "yajl_gen.h", "yajl_tree.h"} {
		if err := copyWAFNativeFile(ctx, filepath.Join(work, "yajl/yajl-2.1.0/src/api", name), filepath.Join(assets, "private-yajl-"+name), 64<<10, os.Geteuid()); err != nil {
			return err
		}
	}
	return nil
}

func prepareNginxPrivateYAJL(ctx context.Context, assets, prefix string, uid, gid int) error {
	if uid <= 0 || gid <= 0 || !wafEngineConfigPath(assets) || !wafEngineConfigPath(prefix) {
		return errors.New("私有 YAJL 路径或非特权编译身份无效")
	}
	for _, path := range []string{filepath.Join(prefix, "include"), filepath.Join(prefix, "include/yajl"), filepath.Join(prefix, "lib")} {
		if err := os.Mkdir(path, 0755); err != nil {
			return err
		}
		if err := os.Chmod(path, 0755); err != nil {
			return err
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	for _, name := range []string{"yajl_common.h", "yajl_parse.h", "yajl_gen.h", "yajl_tree.h"} {
		if err := copyNginxPrivateYAJLHeader(ctx, filepath.Join(assets, "private-yajl-"+name), filepath.Join(prefix, "include/yajl", name)); err != nil {
			return err
		}
	}
	return atomicWrite(filepath.Join(prefix, "include/yajl/yajl_version.h"), []byte(apacheBodyYAJLVersionHeader), 0644)
}

// Source copies remain root-private under UMask=0077. Publish only these
// bounded public headers with descriptor-based chmod so the capability-free
// compiler can read them; do not widen archives, receipts or arbitrary files.
func copyNginxPrivateYAJLHeader(ctx context.Context, source, destination string) error {
	f, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 64<<10 || st.Mode().Perm()&0022 != 0 {
		return errors.New("私有 YAJL 原始头文件类型、大小或权限异常")
	}
	meta, ok := st.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != 0 || meta.Nlink != 1 || os.Geteuid() != 0 {
		return errors.New("私有 YAJL 原始头文件必须为 root 独占资源")
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(&contextReader{ctx, f}, (64<<10)+1))
	if err != nil || n != st.Size() || n > 64<<10 {
		return errors.New("私有 YAJL 头文件复制失败、变化或超限")
	}
	if err := out.Chmod(0644); err != nil {
		return err
	}
	return out.Sync()
}

func verifyNginxPrivateYAJLLinkage(ctx context.Context, s *Service, prefix string) error {
	if !wafEngineConfigPath(prefix) {
		return errors.New("私有 YAJL 验证路径无效")
	}
	if _, err := wafNativeFileSHA(ctx, filepath.Join(prefix, "lib/libyajl.a"), 32<<20); err != nil {
		return err
	}
	library := filepath.Join(prefix, "lib/libmodsecurity.so.3.0.17")
	if _, err := wafNativeFileSHA(ctx, library, 64<<20); err != nil {
		return err
	}
	output, err := s.moduleCommand(ctx, 10*time.Second, "/usr/bin/readelf", "-d", library)
	if err != nil {
		return err
	}
	return validateNginxPrivateYAJLDynamicTags(output)
}
