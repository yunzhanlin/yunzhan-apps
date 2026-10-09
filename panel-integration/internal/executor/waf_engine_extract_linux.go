//go:build linux

package executor

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const wafSourceExpandedBytes = 512 << 20
const wafSourceArchiveEntries = 100000

type wafArchiveEntry struct {
	name, link string
	kind       byte
	size       int64
	executable bool
	mtime      time.Time
}

func wafArchivePrefix(source wafEngineSource) (string, error) {
	if !reviewedWAFEngineSource(source) {
		return "", errors.New("未审核的 WAF 源码不能解包")
	}
	switch source.Name {
	case "modsecurity":
		return "modsecurity-v" + source.Version, nil
	case "modsecurity-nginx":
		return "ModSecurity-nginx-v" + source.Version, nil
	case "owasp-crs":
		return "coreruleset-" + source.Version, nil
	case "nginx-build":
		return "nginx-" + source.Version, nil
	}
	return "", errors.New("WAF 源码类型无效")
}

func extractWAFEngineSource(ctx context.Context, source wafEngineSource, archive, destination string) error {
	prefix, err := wafArchivePrefix(source)
	if err != nil {
		return err
	}
	return extractPinnedWAFSource(ctx, archive, destination, prefix, source.SHA256)
}

// The destination is an exclusively created private directory and is never
// handed to the build user until extraction completes. Preflight validates
// every entry before the first write. Files/directories precede all symlinks;
// os.Root additionally confines descriptor-relative operations on Linux.
// Failed trees remain private evidence and are not silently deleted/reused.
func extractPinnedWAFSource(ctx context.Context, archive, destination, prefix, want string) error {
	return extractPinnedSourceArchive(ctx, archive, destination, prefix, want, "")
}

// Only a fixed, SHA-verified Git source archive may opt into its exact commit
// comment. Existing WAF extraction remains strict; path/link/size/global
// overrides, duplicate metadata and metadata after an ordinary entry fail.
func extractPinnedSourceArchive(ctx context.Context, archive, destination, prefix, want, gitCommit string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if prefix == "" || path.Base(prefix) != prefix || prefix == "." || prefix == ".." {
		return errors.New("WAF 源码顶层目录无效")
	}
	if err := ownedRuntimePath(archive, false); err != nil {
		return err
	}
	f, err := os.OpenFile(archive, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > wafNativeSourceBytes {
		return errors.New("WAF 源码归档类型或大小异常")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || before.Mode().Perm()&0022 != 0 || stat.Nlink != 1 {
		return errors.New("WAF 源码归档描述符所有者、权限或链接数异常")
	}
	sum := sha256.New()
	if n, err := io.Copy(sum, io.LimitReader(&contextReader{ctx, f}, wafNativeSourceBytes+1)); err != nil || n > wafNativeSourceBytes || hex.EncodeToString(sum.Sum(nil)) != want {
		return errors.New("WAF 源码归档固定哈希不匹配，未开始解包")
	}
	entries, err := scanPinnedSourceArchive(ctx, f, prefix, gitCommit)
	if err != nil {
		return err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return errors.New("WAF 源码归档在预检期间变化")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ownedRuntimePath(filepath.Dir(destination), true); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return fmt.Errorf("WAF 解包目录必须为新建且不可覆盖: %w", err)
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gz, err := gzip.NewReader(&contextReader{ctx, f})
	if err != nil {
		return err
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: 1 << 30}
	tr := tar.NewReader(limited)
	i := 0
	metadataSeen := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			if err := validatePinnedGitMetadata(h, gitCommit, metadataSeen || i != 0); err != nil {
				return err
			}
			metadataSeen = true
			continue
		}
		entry, err := wafSourceEntry(h, prefix)
		if err != nil || i >= len(entries) || entry != entries[i] {
			return errors.New("WAF 源码归档内容与预检不一致")
		}
		i++
		switch entry.kind {
		case tar.TypeDir:
			err = root.MkdirAll(entry.name, 0755)
		case tar.TypeReg:
			if err = root.MkdirAll(path.Dir(entry.name), 0755); err != nil {
				return err
			}
			mode := os.FileMode(0644)
			if entry.executable {
				mode = 0755
			}
			out, e := root.OpenFile(entry.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
			if e != nil {
				return e
			}
			_, err = io.CopyN(out, tr, entry.size)
			closeErr := out.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil {
				// The verified release contains generated configure/Makefile/
				// parser files. Preserve their reviewed timestamp ordering rather
				// than spuriously running a different host generator toolchain.
				// The private root has no symlinks until the final pass below.
				err = root.Chtimes(entry.name, entry.mtime, entry.mtime)
			}
		case tar.TypeSymlink:
			// Defer creation until no more ordinary paths can be written.
		}
		if err != nil {
			return err
		}
	}
	if i != len(entries) || (gitCommit != "" && !metadataSeen) {
		return errors.New("WAF 源码归档在解包期间缩短")
	}
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return fmt.Errorf("WAF 源码 gzip 完整性校验失败: %w", err)
	}
	if limited.N == 0 {
		return errors.New("WAF 源码展开数据超过限额")
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.kind == tar.TypeSymlink {
			if err := root.MkdirAll(path.Dir(entry.name), 0755); err != nil {
				return err
			}
			if err := root.Symlink(entry.link, entry.name); err != nil {
				return err
			}
		}
	}
	return nil
}

func wafSourceEntry(h *tar.Header, prefix string) (wafArchiveEntry, error) {
	mtime := h.ModTime
	if mtime.IsZero() {
		mtime = time.Unix(0, 0)
	}
	entry := wafArchiveEntry{name: strings.TrimSuffix(h.Name, "/"), link: h.Linkname, kind: h.Typeflag, size: h.Size, executable: h.Mode&0111 != 0, mtime: mtime}
	if mtime.Unix() < 0 || mtime.Unix() > 4102444800 {
		return entry, errors.New("WAF 归档时间戳超过审核范围")
	}
	if entry.kind == tar.TypeRegA {
		entry.kind = tar.TypeReg
	}
	if len(entry.name) > 1024 || path.Clean(entry.name) != entry.name || !filepath.IsLocal(entry.name) || strings.ContainsAny(entry.name, "\\") || strings.ContainsFunc(entry.name, unicode.IsControl) || (entry.name != prefix && !strings.HasPrefix(entry.name, prefix+"/")) {
		return entry, errors.New("WAF 归档路径越界或不是固定顶层目录")
	}
	if entry.size < 0 || entry.size > wafSourceExpandedBytes || (entry.kind != tar.TypeReg && entry.size != 0) || (entry.name == prefix && entry.kind != tar.TypeDir) {
		return entry, errors.New("WAF 归档条目大小或顶层类型异常")
	}
	switch entry.kind {
	case tar.TypeDir, tar.TypeReg:
		if entry.link != "" {
			return entry, errors.New("WAF 普通归档条目含链接目标")
		}
	case tar.TypeSymlink:
		resolved := path.Clean(path.Join(path.Dir(entry.name), entry.link))
		if entry.link == "" || len(entry.link) > 1024 || path.IsAbs(entry.link) || strings.ContainsAny(entry.link, "\\") || strings.ContainsFunc(entry.link, unicode.IsControl) || !strings.HasPrefix(resolved, prefix+"/") {
			return entry, errors.New("WAF 归档符号链接越界")
		}
	default:
		return entry, errors.New("WAF 归档含硬链接、设备、FIFO 或不允许的条目")
	}
	return entry, nil
}

func scanWAFSourceArchive(ctx context.Context, f *os.File, prefix string) ([]wafArchiveEntry, error) {
	return scanPinnedSourceArchive(ctx, f, prefix, "")
}

func validatePinnedGitMetadata(h *tar.Header, want string, forbiddenPosition bool) error {
	decoded, err := hex.DecodeString(want)
	if forbiddenPosition || err != nil || len(decoded) != 20 || want != strings.ToLower(want) || h.Typeflag != tar.TypeXGlobalHeader || h.Name != "pax_global_header" || h.Size != 0 || h.Linkname != "" || len(h.PAXRecords) != 1 || h.PAXRecords["comment"] != want {
		return errors.New("源码全局元数据不等于固定 Git 提交注释，拒绝路径、链接、大小或其他覆盖")
	}
	return nil
}

func scanPinnedSourceArchive(ctx context.Context, f *os.File, prefix, gitCommit string) ([]wafArchiveEntry, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(&contextReader{ctx, f})
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	// Includes header/padding/trailing data, not merely declared file sizes.
	limited := &io.LimitedReader{R: gz, N: 1 << 30}
	tr := tar.NewReader(limited)
	entries := []wafArchiveEntry{}
	objects := map[string]byte{}
	var total int64
	metadataSeen := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			if err := validatePinnedGitMetadata(h, gitCommit, metadataSeen || len(entries) != 0); err != nil {
				return nil, err
			}
			metadataSeen = true
			continue
		}
		e, err := wafSourceEntry(h, prefix)
		if err != nil {
			return nil, err
		}
		if _, duplicate := objects[e.name]; duplicate {
			return nil, errors.New("WAF 归档包含重复路径")
		}
		objects[e.name] = e.kind
		total += e.size
		entries = append(entries, e)
		if total > wafSourceExpandedBytes || len(entries) > wafSourceArchiveEntries {
			return nil, errors.New("WAF 归档超过解包限额")
		}
	}
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return nil, fmt.Errorf("WAF 源码 gzip 完整性校验失败: %w", err)
	}
	if limited.N == 0 || len(entries) == 0 || (gitCommit != "" && !metadataSeen) {
		return nil, errors.New("WAF 归档为空或展开数据超过限额")
	}
	for _, e := range entries {
		for parent := path.Dir(e.name); parent != "."; parent = path.Dir(parent) {
			if kind, exists := objects[parent]; exists && kind != tar.TypeDir {
				return nil, errors.New("WAF 归档路径穿过链接或非目录条目")
			}
		}
		if e.kind != tar.TypeSymlink {
			continue
		}
		resolved := path.Clean(path.Join(path.Dir(e.name), e.link))
		if _, exists := objects[resolved]; !exists {
			return nil, errors.New("WAF 归档链接目标未包含在固定源码中")
		}
		for target := resolved; target != "."; target = path.Dir(target) {
			if kind, exists := objects[target]; exists && kind == tar.TypeSymlink {
				return nil, errors.New("WAF 归档拒绝符号链接链和循环")
			}
		}
	}
	return entries, nil
}
