//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const diskUsageEntriesMax = 100000
const diskUsageDepthMax = 128
const diskUsageReadBatch = 64

type diskUsageInode struct{ device, inode uint64 }
type diskUsageScan struct {
	ctx                                                                context.Context
	device                                                             uint64
	entries, files, hardlinks, sparse, links, special, foreign, cycles int
	logical, uniqueLogical, allocated                                  int64
	entryLimited, depthLimited, classificationLimited                  bool
	keyBudget                                                          int
	seen, visited                                                      map[diskUsageInode]struct{}
	dirs, extensions, children                                         map[string]int64
	rows                                                               []map[string]any
}

// Each component is opened relative to a held directory FD. Never follow a
// symlink, including a directory replaced between stat and open. File contents,
// devices and FIFO are never opened. No shell or deletion operation is used.
func diskUsageOpenDir(parent *os.File, name string, expected *unix.Stat_t) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, errors.New("目录描述符仅接受一个普通路径分量")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || expected != nil && (st.Dev != expected.Dev || st.Ino != expected.Ino) {
		f.Close()
		return nil, errors.New("目录身份在扫描时改变；未沿替换路径读取")
	}
	return f, nil
}

func (w *diskUsageScan) addSize(group map[string]int64, key string, size int64) {
	if _, exists := group[key]; !exists {
		cost := 6*len(key) + 32
		if len(key) > 512 || !utf8.ValidString(key) || len(group) >= 1000 || cost > w.keyBudget {
			w.classificationLimited = true
			return
		}
		w.keyBudget -= cost
	}
	group[key] += size // Each group is a subset of the overflow-checked total.
}
func diskUsageRowBefore(a, b map[string]any) bool {
	if a["bytes"].(int64) != b["bytes"].(int64) {
		return a["bytes"].(int64) > b["bytes"].(int64)
	}
	return a["path"].(string) < b["path"].(string)
}
func (w *diskUsageScan) file(path, selected string, st unix.Stat_t) error {
	// Linux st_blocks is measured in 512-byte units, not st_blksize.
	// https://man7.org/linux/man-pages/man3/stat.3type.html
	if st.Size < 0 || st.Blocks < 0 || st.Blocks > math.MaxInt64/512 || st.Size > math.MaxInt64-w.logical {
		return errors.New("文件大小或分配块超出可核对范围；未显示溢出后的占用")
	}
	w.files++
	w.logical += st.Size
	allocated := st.Blocks * 512
	identity := diskUsageInode{uint64(st.Dev), st.Ino}
	if _, exists := w.seen[identity]; exists {
		w.hardlinks++
	} else {
		if allocated > math.MaxInt64-w.allocated || st.Size > math.MaxInt64-w.uniqueLogical {
			return errors.New("去重占用超出可核对范围")
		}
		w.seen[identity] = struct{}{}
		w.uniqueLogical += st.Size
		w.allocated += allocated
		if allocated < st.Size {
			w.sparse++
		}
	}
	w.addSize(w.dirs, filepath.Dir(path), st.Size)
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		ext = "无扩展名"
	}
	w.addSize(w.extensions, ext, st.Size)
	child, _, _ := strings.Cut(path, "/")
	w.addSize(w.children, child, st.Size)
	full := filepath.Join(selected, path)
	row := map[string]any{"path": full, "bytes": st.Size, "allocated_file_bytes": allocated, "link_count": uint64(st.Nlink), "allocation_below_logical": allocated < st.Size, "can_drill": core.ValidFilePath(full, false)}
	if len(full) > 512 || !utf8.ValidString(full) {
		display := strings.ToValidUTF8(full, "�")
		if len(display) > 512 {
			display = display[:512]
			for !utf8.ValidString(display) {
				display = display[:len(display)-1]
			}
			display += "…"
		}
		row["path"] = display
		row["can_drill"] = false
		w.classificationLimited = true
	} else {
		row["directory"] = filepath.Dir(full)
	}
	if len(w.rows) < 100 {
		w.rows = append(w.rows, row)
	} else if diskUsageRowBefore(row, w.rows[len(w.rows)-1]) {
		w.rows[len(w.rows)-1] = row
	} else {
		return nil
	}
	sort.Slice(w.rows, func(i, j int) bool { return diskUsageRowBefore(w.rows[i], w.rows[j]) })
	return nil
}
func (w *diskUsageScan) walk(dir *os.File, path, selected string, depth int) error {
	for {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		if w.entryLimited {
			return nil
		}
		batch, readErr := dir.ReadDir(diskUsageReadBatch)
		for _, entry := range batch {
			if err := w.ctx.Err(); err != nil {
				return err
			}
			if w.entries >= diskUsageEntriesMax {
				w.entryLimited = true
				return nil
			}
			w.entries++
			var st unix.Stat_t
			if err := unix.Fstatat(int(dir.Fd()), entry.Name(), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				w.links++
				continue
			}
			if uint64(st.Dev) != w.device {
				w.foreign++
				continue
			}
			p := filepath.Join(path, entry.Name())
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFREG:
				if err := w.file(p, selected, st); err != nil {
					return err
				}
			case unix.S_IFDIR:
				if depth >= diskUsageDepthMax {
					w.depthLimited = true
					continue
				}
				identity := diskUsageInode{uint64(st.Dev), st.Ino}
				if _, exists := w.visited[identity]; exists {
					w.cycles++
					continue
				}
				w.visited[identity] = struct{}{}
				child, err := diskUsageOpenDir(dir, entry.Name(), &st)
				if err != nil {
					return err
				}
				err = w.walk(child, p, selected, depth+1)
				closeErr := child.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return closeErr
				}
			default:
				w.special++
			}
			if w.entryLimited {
				return nil
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (s *Service) diskUsageReport(ctx context.Context, id, selected string) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !core.ValidFilePath(selected, true) {
		return nil, errors.New("请选择网站内的普通目录")
	}
	f, err := s.openFiles(id)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Root.OpenFile may resolve an in-root final symlink despite caller flags.
	// Capture the already-authorized site itself, then let the kernel enforce
	// O_NOFOLLOW for the literal public component and every selected child.
	site, err := f.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer site.Close()
	dir, err := diskUsageOpenDir(site, "public", nil)
	if err != nil {
		return nil, err
	}
	defer func() { dir.Close() }()
	if selected != "" && selected != "." {
		for _, part := range strings.Split(selected, "/") {
			next, e := diskUsageOpenDir(dir, part, nil)
			if e != nil {
				return nil, e
			}
			dir.Close()
			dir = next
		}
	}
	var rootStat unix.Stat_t
	if err = unix.Fstat(int(dir.Fd()), &rootStat); err != nil {
		return nil, err
	}
	w := diskUsageScan{ctx: ctx, device: uint64(rootStat.Dev), entries: 1, keyBudget: 200 << 10, seen: map[diskUsageInode]struct{}{}, visited: map[diskUsageInode]struct{}{{uint64(rootStat.Dev), rootStat.Ino}: {}}, dirs: map[string]int64{}, extensions: map[string]int64{}, children: map[string]int64{}, rows: []map[string]any{}}
	if err = w.walk(dir, "", selected, 0); err != nil {
		return nil, err
	}
	complete := !w.entryLimited && !w.depthLimited && w.foreign == 0 && w.cycles == 0
	out := map[string]any{"site_id": id, "path": selected, "total_bytes": w.logical, "unique_logical_bytes": w.uniqueLogical, "allocated_bytes": w.allocated, "files": w.files, "unique_files": len(w.seen), "hardlink_entries": w.hardlinks, "sparse_candidates": w.sparse, "ignored_links": w.links, "ignored_special": w.special, "foreign_filesystems_skipped": w.foreign, "directory_cycles_skipped": w.cycles, "entries_scanned": w.entries, "entry_limited": w.entryLimited, "depth_limited": w.depthLimited, "classification_limited": w.classificationLimited, "scan_complete": complete, "partial": !complete || w.classificationLimited, "read_batch_size": diskUsageReadBatch, "directories": w.dirs, "extensions": w.extensions, "children": w.children, "largest_files": w.rows, "allocation_basis": "st_blocks_512_inode_deduplicated", "snapshot_consistent": false, "scope": "只读扫描所选网站 public 内同一文件系统；不跟随链接、不读文件内容、不删除。逻辑大小按路径相加，分配块只对本次范围内 inode 去重，不包含目录元数据；不等于写时复制共享块、快照或压缩后的独占物理空间。目录/扩展名分布按逻辑大小，不是分配块归属。活动目录不是原子快照。"}
	diskUsageFilesystem(dir, out)
	return out, nil
}
func diskUsageFilesystem(dir *os.File, out map[string]any) {
	var st syscall.Statfs_t
	out["filesystem_available"] = false
	out["filesystem_inodes_available"] = false
	if syscall.Fstatfs(int(dir.Fd()), &st) != nil || st.Bsize <= 0 || st.Blocks == 0 || st.Blocks > math.MaxUint64/uint64(st.Bsize) || st.Bfree > st.Blocks || st.Bavail > st.Bfree {
		out["filesystem_error"] = "所在文件系统容量不能核对；未显示为零"
		return
	}
	total, used, available := diskUsage(st)
	out["filesystem_available"] = true
	out["filesystem_capacity_bytes"] = total
	out["filesystem_used_bytes"] = used
	out["filesystem_available_bytes"] = available
	out["filesystem_reserved_bytes"] = (st.Bfree - st.Bavail) * uint64(st.Bsize)
	if st.Files > 0 && st.Ffree <= st.Files {
		out["filesystem_inodes_available"] = true
		out["filesystem_total_inodes"] = st.Files
		out["filesystem_free_inodes"] = st.Ffree
		out["filesystem_used_inodes"] = st.Files - st.Ffree
	}
}
