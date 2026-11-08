//go:build linux

package executor

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const storageSafeBytes = uint64(1<<53 - 1)

type storageIdentity struct{ device, inode uint64 }
type storageScanner struct {
	ctx            context.Context
	device         uint64
	seen           map[storageIdentity]bool
	visited, limit int
	categoryLimit  int
}

// Pin every ancestor. No file content is read, even for links or FIFOs.
func openStorageDirectory(path string) (*os.File, error) {
	if !core.ValidSystemDirectory(path) {
		return nil, errors.New("无效统计目录")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}

func storagePartial(c *core.FileStorageCategory, reason string) {
	c.State = "partial"
	if c.Reason == "" {
		c.Reason = reason
	}
}

func (s *storageScanner) budget(c *core.FileStorageCategory, depth int) bool {
	if s.ctx.Err() != nil {
		storagePartial(c, "timeout")
		return false
	}
	if s.visited >= s.limit || c.Scanned >= s.categoryLimit || depth > 64 {
		storagePartial(c, "limit")
		return false
	}
	s.visited++
	c.Scanned++
	return true
}

func (s *storageScanner) account(c *core.FileStorageCategory, st *unix.Stat_t) bool {
	if st.Dev != s.device {
		c.ForeignMounts++
		return false
	}
	id := storageIdentity{st.Dev, st.Ino}
	if s.seen[id] {
		c.Deduplicated++
		return false
	}
	if st.Blocks < 0 || uint64(st.Blocks) > storageSafeBytes/512 || *c.Bytes > storageSafeBytes-uint64(st.Blocks)*512 {
		c.Skipped++
		storagePartial(c, "overflow")
		return false
	}
	s.seen[id] = true
	*c.Bytes += uint64(st.Blocks) * 512
	return true
}

func (s *storageScanner) walk(c *core.FileStorageCategory, dir *os.File, depth int, counted bool) {
	if !counted && !s.budget(c, depth) {
		return
	}
	var root unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &root) != nil {
		c.Skipped++
		storagePartial(c, "unreadable")
		return
	}
	if !s.account(c, &root) {
		return
	}
	for {
		if s.ctx.Err() != nil {
			storagePartial(c, "timeout")
			return
		}
		items, err := dir.ReadDir(128)
		if err != nil && err != io.EOF {
			c.Skipped++
			storagePartial(c, "unreadable")
			return
		}
		for _, item := range items {
			if !s.budget(c, depth+1) {
				return
			}
			var st unix.Stat_t
			if unix.Fstatat(int(dir.Fd()), item.Name(), &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
				c.Skipped++
				storagePartial(c, "unreadable")
				continue
			}
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				if st.Dev != s.device {
					c.ForeignMounts++
					continue
				}
				fd, e := unix.Openat(int(dir.Fd()), item.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if e != nil {
					c.Skipped++
					storagePartial(c, "unreadable")
					continue
				}
				child := os.NewFile(uintptr(fd), item.Name())
				var actual unix.Stat_t
				if unix.Fstat(fd, &actual) != nil || actual.Dev != st.Dev || actual.Ino != st.Ino {
					c.Skipped++
					storagePartial(c, "changed")
				} else {
					s.walk(c, child, depth+1, true)
				}
				child.Close()
			} else {
				s.account(c, &st)
			}
		}
		if err == io.EOF {
			return
		}
	}
}

func storageCategoryComplete(state string) bool {
	return state == "complete" || state == "absent" || state == "excluded"
}

func collectStorageUsage(ctx context.Context, partition string, categories []core.FileStorageCategory, limit, categoryLimit int) (core.FileStorageUsage, error) {
	started := time.Now().UTC()
	out := core.FileStorageUsage{FilesystemPath: partition, Limit: limit, StartedAt: started.Format(time.RFC3339)}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	disk, err := openStorageDirectory(partition)
	if err != nil {
		return out, errors.New("数据分区不可访问")
	}
	defer disk.Close()
	var root unix.Stat_t
	if err := unix.Fstat(int(disk.Fd()), &root); err != nil {
		return out, err
	}
	s := storageScanner{ctx: ctx, device: root.Dev, seen: make(map[storageIdentity]bool), limit: limit, categoryLimit: categoryLimit}
	out.Complete = true
	var classified uint64
	for _, input := range categories {
		c := core.FileStorageCategory{ID: input.ID, Label: input.Label, Paths: input.Paths, State: "complete"}
		bytes := uint64(0)
		c.Bytes = &bytes
		missing, excluded := 0, 0
		for _, path := range c.Paths {
			if ctx.Err() != nil || s.visited >= limit {
				storagePartial(&c, "timeout_or_limit")
				break
			}
			dir, e := openStorageDirectory(path)
			if errors.Is(e, unix.ENOENT) {
				missing++
				continue
			}
			if e != nil {
				c.Skipped++
				storagePartial(&c, "unreadable")
				continue
			}
			var st unix.Stat_t
			if unix.Fstat(int(dir.Fd()), &st) != nil {
				c.Skipped++
				storagePartial(&c, "unreadable")
			} else if st.Dev != root.Dev {
				c.ForeignMounts++
				excluded++
			} else {
				s.walk(&c, dir, 0, false)
			}
			dir.Close()
		}
		if c.State == "complete" && missing == len(c.Paths) {
			c.State = "absent"
		} else if c.State == "complete" && missing+excluded == len(c.Paths) && excluded > 0 {
			c.State = "excluded"
		}
		if !storageCategoryComplete(c.State) {
			out.Complete = false
			if c.Scanned == 0 {
				c.Bytes = nil
				c.State = "unavailable"
			}
		}
		if c.Bytes != nil {
			if classified > storageSafeBytes-*c.Bytes {
				return out, errors.New("分类占用超出支持范围")
			}
			classified += *c.Bytes
		}
		out.Categories = append(out.Categories, c)
	}
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(int(disk.Fd()), &fs); err != nil || fs.Bsize <= 0 || fs.Bfree > fs.Blocks || fs.Bavail > fs.Bfree || fs.Blocks > storageSafeBytes/uint64(fs.Bsize) {
		return out, errors.New("数据分区容量读数无效")
	}
	out.DiskTotal, out.DiskUsed, out.DiskAvailable = diskUsage(fs)
	out.Reconciled = out.Complete && classified <= out.DiskUsed
	if out.Reconciled {
		remaining := out.DiskUsed - classified
		out.OtherBytes = &remaining
	}
	out.Scanned = s.visited
	out.SampledAt = time.Now().UTC().Format(time.RFC3339)
	out.DurationMS = time.Since(started).Milliseconds()
	return out, nil
}

func (s *Service) fileStorageRoutes(m *http.ServeMux) {
	var gate sync.Mutex
	m.HandleFunc("GET /v1/storage/usage", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			respond(w, 400, map[string]string{"error": "存储统计不接受自定义目录"})
			return
		}
		if !gate.TryLock() {
			respond(w, 503, map[string]string{"error": "存储统计正在进行，请稍后重试"})
			return
		}
		defer gate.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		out, err := collectStorageUsage(ctx, "/srv/panel", []core.FileStorageCategory{
			{ID: "websites", Label: "网站文件", Paths: []string{s.Config.SitesDir}},
			{ID: "databases", Label: "数据库", Paths: []string{"/srv/panel/mysql", "/srv/panel/mariadb"}},
			{ID: "logs", Label: "日志文件", Paths: []string{"/var/log"}},
		}, 100000, 40000)
		if err != nil {
			respond(w, 503, map[string]string{"error": "存储统计暂不可用"})
			return
		}
		respond(w, 200, out)
	})
}
