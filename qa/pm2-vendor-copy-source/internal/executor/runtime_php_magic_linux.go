//go:build linux

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"syscall"
)

// This executes only BEFORE chown/configure, in the freshly extracted,
// root-controlled work tree. Never read, repair or execute an old failed build.
func prepareRuntimePHPBuildSource(r runtimecatalog.Release, source string) ([]RuntimeBuildTransform, error) {
	spec, needed := runtimeMagicSpecification(r.ID)
	if !needed {
		return nil, nil // Newer upstream releases already use string tables.
	}
	if r.Family != "php" || r.SHA256 != spec.archiveSHA || !filepath.IsAbs(source) || filepath.Clean(source) != source || filepath.Base(source) != "php-"+r.Version {
		return nil, errors.New("fileinfo 构建兼容处理缺少精确上游版本绑定")
	}
	for _, dir := range []string{source, filepath.Join(source, "ext"), filepath.Join(source, "ext/fileinfo")} {
		if err := ownedRuntimePath(dir, true); err != nil {
			return nil, err
		}
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.OpenFile(runtimeMagicPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	before, err := f.Stat()
	if err != nil || !runtimeMagicSourceFile(before) || before.Size() != int64(spec.rawBytes) {
		f.Close()
		return nil, errors.New("fileinfo 原始生成文件身份或大小异常，未接管")
	}
	data, readErr := io.ReadAll(io.LimitReader(f, int64(spec.rawBytes)+1))
	after, statErr := f.Stat()
	named, nameErr := root.Lstat(runtimeMagicPath)
	f.Close()
	if readErr != nil || statErr != nil || nameErr != nil || !runtimeMagicSourceSame(before, after) || !runtimeMagicSourceSame(after, named) || len(data) != spec.rawBytes {
		return nil, errors.New("fileinfo 原始生成文件在读取期间变化")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != spec.inputSHA {
		return nil, errors.New("fileinfo 原始生成文件不匹配固定官方源码，未替换")
	}
	out, payloadSHA, err := runtimeMagicStringSource(data, spec.dataBytes, spec.nonString)
	if err != nil || payloadSHA != spec.dataSHA {
		return nil, errors.New("fileinfo 构建表示未保持原始数据库逐字节等价")
	}
	// Keep the exact upstream file, even if later configuration/build fails.
	// Two no-replace renames publish only this fresh root-owned source leaf.
	retained := runtimeMagicPath + ".upstream-" + spec.inputSHA
	if _, err := root.Lstat(retained); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("fileinfo 已存在保留输出或未知占用，未重放兼容处理")
	}
	tmp := "ext/fileinfo/.data_file.c-build-" + core.ID()
	target, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0644)
	if err != nil {
		return nil, err
	}
	defer root.Remove(tmp)
	_, err = target.Write(out)
	if err == nil {
		err = target.Chmod(0644)
	}
	if err == nil {
		err = target.Sync()
	}
	closeErr := target.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	named, err = root.Lstat(runtimeMagicPath)
	if err != nil || !runtimeMagicSourceSame(before, named) {
		return nil, errors.New("fileinfo 原始文件在替换前变化，保留兼容输出但未执行")
	}
	if err := renameNoReplace(root, runtimeMagicPath, retained); err != nil {
		return nil, err
	}
	if err := renameNoReplace(root, tmp, runtimeMagicPath); err != nil {
		return nil, err
	}
	if err := syncRuntimeDirs(filepath.Join(source, "ext/fileinfo")); err != nil {
		return nil, err
	}
	return []RuntimeBuildTransform{runtimeMagicTransformRecord(spec, out)}, nil
}

func runtimeMagicSourceFile(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode() == 0644 && s.Uid == 0 && s.Gid == 0 && s.Nlink == 1
}

func runtimeMagicSourceSame(a, b os.FileInfo) bool {
	if !runtimeMagicSourceFile(a) || !runtimeMagicSourceFile(b) {
		return false
	}
	x, y := a.Sys().(*syscall.Stat_t), b.Sys().(*syscall.Stat_t)
	return x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid &&
		x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
