//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type rabbitMQColdCopyResult struct {
	Files       int    `json:"files"`
	Directories int    `json:"directories"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
}

var errRabbitMQCopyDrift = errors.New("RabbitMQ 冷备份期间目录或文件身份发生变化")
var errRabbitMQCopyType = errors.New("RabbitMQ 数据卷含符号链接、挂载、硬链接、特殊文件或扩展属性")

// The caller must hold exclusive Docker mutation authority, prove that the
// source node stopped cleanly, and pin both Docker-owned volume directories
// before opening these descriptors. The destination must be a new empty
// volume and must stay detached until the receipt has been durably recorded.
// On error the original remains intact and the partial volume is retained.
func copyRabbitMQColdVolume(ctx context.Context, source, destination *os.File) (rabbitMQColdCopyResult, error) {
	var empty rabbitMQColdCopyResult
	if os.Geteuid() != 0 || source == nil || destination == nil {
		return empty, errors.New("RabbitMQ 冷拷贝需要 Root 执行器持有原卷和新卷")
	}
	from, fromErr := rabbitMQCopyStat(source)
	to, toErr := rabbitMQCopyStat(destination)
	if fromErr != nil || toErr != nil || from.Dev == to.Dev && from.Ino == to.Ino ||
		from.Mode&unix.S_IFMT != unix.S_IFDIR || to.Mode&unix.S_IFMT != unix.S_IFDIR {
		return empty, errors.New("RabbitMQ 冷拷贝需要两个不同的数据卷目录")
	}
	// Use a new open file description, so caller's directory offset cannot
	// hide preexisting destination files or part of the source inventory.
	dst, err := rabbitMQCopyOpen(destination, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return empty, err
	}
	defer dst.Close()
	if list, err := dst.ReadDir(1); len(list) != 0 || !errors.Is(err, io.EOF) {
		return empty, errors.New("RabbitMQ 新数据卷目录已有内容")
	}
	src, err := rabbitMQCopyOpen(source, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME, 0)
	if err != nil {
		return empty, err
	}
	defer src.Close()
	walk := rabbitMQColdCopy{ctx: ctx, digest: sha256.New()}
	if err := walk.directory(src, dst, ".", from, 0); err != nil {
		return empty, err
	}
	walk.result.SHA256 = fmt.Sprintf("%x", walk.digest.Sum(nil))
	return walk.result, nil
}

type rabbitMQColdCopy struct {
	ctx    context.Context
	digest hash.Hash
	result rabbitMQColdCopyResult
}

func rabbitMQCopyStat(f *os.File) (unix.Stat_t, error) {
	var stat unix.Stat_t
	err := unix.Fstat(int(f.Fd()), &stat)
	return stat, err
}

func rabbitMQCopyOpen(parent *os.File, name string, flags int, mode uint64) (*os.File, error) {
	flags |= unix.O_CLOEXEC | unix.O_NOFOLLOW
	if flags&unix.O_PATH == 0 {
		flags |= unix.O_NONBLOCK
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{
		Flags: uint64(flags), Mode: mode,
		Resolve: siteOneMountResolve,
	})
	if err != nil {
		return nil, fmt.Errorf("RabbitMQ 卷目录项无法安全打开: %w", err)
	}
	return os.NewFile(uintptr(fd), "/proc/self/fd/"+strconv.Itoa(fd)), nil
}

func rabbitMQCopySame(expected, actual unix.Stat_t) bool {
	return expected.Dev == actual.Dev && expected.Ino == actual.Ino && expected.Nlink == actual.Nlink &&
		expected.Mode == actual.Mode && expected.Size == actual.Size && expected.Uid == actual.Uid &&
		expected.Gid == actual.Gid && expected.Mtim == actual.Mtim && expected.Ctim == actual.Ctim
}

func rabbitMQCopyFileRules(file *os.File, expected unix.Stat_t) error {
	actual, err := rabbitMQCopyStat(file)
	if err != nil || !rabbitMQCopySame(expected, actual) {
		return errRabbitMQCopyDrift
	}
	if expected.Mode&07000 != 0 || expected.Mode&0002 != 0 {
		return errRabbitMQCopyType
	}
	n, err := unix.Flistxattr(int(file.Fd()), nil)
	if n != 0 || err != nil && !errors.Is(err, unix.ENOTSUP) {
		return errRabbitMQCopyType
	}
	return nil
}

func rabbitMQCopyMetadata(file *os.File, metadata unix.Stat_t) error {
	fd := int(file.Fd())
	if err := unix.Fchown(fd, int(metadata.Uid), int(metadata.Gid)); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, metadata.Mode&0777); err != nil {
		return err
	}
	times := []unix.Timespec{metadata.Atim, metadata.Mtim}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, file.Name(), times, 0); err != nil {
		return fmt.Errorf("RabbitMQ 冷备份保留时间戳: %w", err)
	}
	return file.Sync()
}

func (c *rabbitMQColdCopy) directory(source, destination *os.File, path string, original unix.Stat_t, depth int) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if depth > 128 || c.result.Files+c.result.Directories >= 1_000_000 {
		return errors.New("RabbitMQ 数据卷目录层级或条目数超过冷备份限制")
	}
	if err := rabbitMQCopyFileRules(source, original); err != nil {
		return err
	}
	n, err := unix.Flistxattr(int(destination.Fd()), nil)
	if n != 0 || err != nil && !errors.Is(err, unix.ENOTSUP) {
		return errRabbitMQCopyType
	}
	entries, err := source.ReadDir(1_000_000 - c.result.Files - c.result.Directories + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) > 1_000_000-c.result.Files-c.result.Directories {
		return errors.New("RabbitMQ 数据卷目录条目数超过冷备份限制")
	}
	// Deterministic depth-first receipts do not depend on a filesystem's
	// directory enumeration order.
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	c.result.Directories++
	fmt.Fprintf(c.digest, "D %q %o %d %d %d %d\n", path, original.Mode&0777, original.Uid, original.Gid, original.Mtim.Sec, original.Mtim.Nsec)
	for _, entry := range entries {
		if err := c.entry(source, destination, path, entry.Name(), depth); err != nil {
			return err
		}
	}
	if err := rabbitMQCopyFileRules(source, original); err != nil {
		return err
	}
	return rabbitMQCopyMetadata(destination, original)
}

func (c *rabbitMQColdCopy) entry(source, destination *os.File, path, name string, depth int) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if c.result.Files+c.result.Directories >= 1_000_000 {
		return errors.New("RabbitMQ 数据卷条目数超过冷备份限制")
	}
	// Inspect an inert descriptor first. The following read opens that
	// exact inode even if its name changes after initial inspection.
	pin, err := rabbitMQCopyOpen(source, name, unix.O_PATH, 0)
	if err != nil {
		return err
	}
	defer pin.Close()
	info, err := rabbitMQCopyStat(pin)
	if err != nil {
		return err
	}
	kind := info.Mode & unix.S_IFMT
	if kind != unix.S_IFDIR && (kind != unix.S_IFREG || info.Nlink != 1 || info.Size < 0) {
		return errRabbitMQCopyType
	}
	openFlags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOATIME
	if kind == unix.S_IFDIR {
		openFlags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(pin.Name(), openFlags, 0)
	if err != nil {
		return err
	}
	src := os.NewFile(uintptr(fd), pin.Name())
	defer src.Close()
	if err := rabbitMQCopyFileRules(src, info); err != nil {
		return err
	}
	child := path + "/" + name
	if kind == unix.S_IFDIR {
		if err := unix.Mkdirat(int(destination.Fd()), name, 0700); err != nil {
			return err
		}
		dst, err := rabbitMQCopyOpen(destination, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		defer dst.Close()
		if err := c.directory(src, dst, child, info, depth+1); err != nil {
			return err
		}
	} else {
		if err := c.copyFile(src, destination, name, child, info); err != nil {
			return err
		}
	}
	var visible unix.Stat_t
	if err := diskUsageEntryStat(source, name, &visible); err != nil || !rabbitMQCopySame(info, visible) {
		return errRabbitMQCopyDrift
	}
	return nil
}

type rabbitMQCopyReader struct {
	context.Context
	io.Reader
}

func (r rabbitMQCopyReader) Read(p []byte) (int, error) {
	if err := r.Context.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func (c *rabbitMQColdCopy) copyFile(source, destination *os.File, name, path string, sourceInfo unix.Stat_t) error {
	if sourceInfo.Size > 1<<40-c.result.Bytes {
		return errors.New("RabbitMQ 数据卷逻辑容量超过 1 TiB")
	}
	dst, err := rabbitMQCopyOpen(destination, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer dst.Close()
	sourceHash := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, sourceHash), rabbitMQCopyReader{c.ctx, io.LimitReader(source, sourceInfo.Size+1)})
	if err != nil {
		return err
	}
	if n != sourceInfo.Size {
		return errRabbitMQCopyDrift
	}
	if err := rabbitMQCopyFileRules(source, sourceInfo); err != nil {
		return err
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	destinationHash := sha256.New()
	read, err := io.Copy(destinationHash, rabbitMQCopyReader{c.ctx, io.LimitReader(dst, n+1)})
	if err != nil {
		return err
	}
	if read != n || !bytes.Equal(sourceHash.Sum(nil), destinationHash.Sum(nil)) {
		return errors.New("RabbitMQ 冷备份副本的完整内容摘要无法核对")
	}
	if err := rabbitMQCopyMetadata(dst, sourceInfo); err != nil {
		return err
	}
	fmt.Fprintf(c.digest, "F %q %o %d %d %d %d %d %x\n", path, sourceInfo.Mode&0777, sourceInfo.Uid,
		sourceInfo.Gid, sourceInfo.Mtim.Sec, sourceInfo.Mtim.Nsec, n, sourceHash.Sum(nil))
	c.result.Files++
	c.result.Bytes += n
	return nil
}
