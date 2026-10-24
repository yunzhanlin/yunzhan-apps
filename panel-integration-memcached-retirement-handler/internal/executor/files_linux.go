//go:build linux

package executor

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	bzip2writer "github.com/dsnet/compress/bzip2"
	"github.com/ulikunitz/xz"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"local/panel/internal/core"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const filePrivate = ".panel-files"

var fileLocks sync.Map

func fileMutex(id string) *sync.Mutex {
	v, _ := fileLocks.LoadOrStore(id, &sync.Mutex{})
	return v.(*sync.Mutex)
}

type siteFiles struct {
	root, public *os.Root
	uid, gid     int
}

func (s *Service) openFiles(id string) (*siteFiles, error) {
	if !core.ValidID(id) {
		return nil, errors.New("无效站点标识")
	}
	base, e := os.OpenRoot(s.Config.SitesDir)
	if e != nil {
		return nil, e
	}
	defer base.Close()
	root, e := base.OpenRoot(id)
	if e != nil {
		return nil, e
	}
	fail := func(err error) (*siteFiles, error) { root.Close(); return nil, err }
	data, e := root.ReadFile(".panel-site.json")
	if e != nil {
		return fail(e)
	}
	var marker map[string]string
	if json.Unmarshal(data, &marker) != nil || marker["id"] != id {
		return fail(errors.New("站点目录归属不匹配"))
	}
	public, e := root.OpenRoot("public")
	if e != nil {
		return fail(e)
	}
	f, e := public.Open(".")
	if e != nil {
		public.Close()
		return fail(e)
	}
	st, e := f.Stat()
	f.Close()
	if e != nil {
		public.Close()
		return fail(e)
	}
	stat := st.Sys().(*syscall.Stat_t)
	return &siteFiles{root: root, public: public, uid: int(stat.Uid), gid: int(stat.Gid)}, nil
}
func (f *siteFiles) Close() { f.public.Close(); f.root.Close() }
func regularFile(root *os.Root, path string) (*os.File, error) {
	file, e := openRootPathNoLinks(root, path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	st, e := file.Stat()
	if e != nil || !st.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("只允许操作普通文件，链接与特殊文件不可读取")
	}
	return file, nil
}
func fileKind(mode os.FileMode) string {
	if mode.IsDir() {
		return "directory"
	}
	if mode.IsRegular() {
		return "file"
	}
	if mode&os.ModeSymlink != 0 {
		return "link"
	}
	return "special"
}

// fileMetadataMode includes the Unix special permission bits for read-only
// listings. os.FileMode represents these flags outside Perm(); this string is
// not a chmod input or the sanitized mode used by editor/revision writes.
func fileMetadataMode(mode os.FileMode) string {
	bits := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		bits |= 04000
	}
	if mode&os.ModeSetgid != 0 {
		bits |= 02000
	}
	if mode&os.ModeSticky != 0 {
		bits |= 01000
	}
	return fmt.Sprintf("%04o", bits)
}

func fileMetadataOwner(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(stat.Uid), 10)
	}
	return ""
}

// DirectorySize is deliberately on demand: listing a large site must remain
// cheap. WalkDir does not follow links and os.Root confines all reads to public.
func (f *siteFiles) DirectorySize(ctx context.Context, path string) (map[string]any, error) {
	if !core.ValidFilePath(path, false) {
		return nil, errors.New("无效目录路径")
	}
	dir, e := openRootPathNoLinks(f.public, path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	st, e := dir.Stat()
	_ = dir.Close()
	if e != nil || !st.IsDir() {
		return nil, errors.New("请选择目录")
	}
	var bytes, files, directories, skipped int64
	var visited int
	e = fs.WalkDir(f.public.FS(), path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		visited++
		if visited > 100000 || strings.Count(current, "/") > 64 {
			return errors.New("目录项目或层级过多，无法在本次请求中计算")
		}
		if current != path && !core.ValidFilePath(current, false) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			directories++
			return nil
		}
		if !entry.Type().IsRegular() {
			skipped++
			return nil
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if info.Size() < 0 || info.Size() > int64(^uint64(0)>>1)-bytes {
			return errors.New("目录大小超出可计算范围")
		}
		bytes += info.Size()
		files++
		return nil
	})
	if e != nil {
		return nil, e
	}
	return map[string]any{"path": path, "bytes": bytes, "files": files, "directories": directories, "skipped": skipped}, nil
}
func (f *siteFiles) List(path, search string) (map[string]any, error) {
	if !core.ValidFilePath(path, true) || len(search) > 128 {
		return nil, errors.New("无效目录或搜索条件")
	}
	if path == "" {
		path = "."
	}
	pins, e := f.readPins()
	if e != nil {
		return nil, e
	}
	dir, e := openRootPathNoLinks(f.public, path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	info, e := dir.Stat()
	if e != nil || !info.IsDir() {
		return nil, errors.New("请选择目录")
	}
	entries, summary, scanned, e := readFileDirectory(dir, path, true)
	if e != nil {
		return nil, e
	}
	out := []core.FileEntry{}
	for _, entry := range entries {
		if !strings.Contains(strings.ToLower(entry.Name), strings.ToLower(search)) {
			continue
		}
		entry.Pinned = pins[entry.Path]
		out = append(out, entry)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Pinned != out[j].Pinned {
			return out[i].Pinned
		}
		if (out[i].Kind == "directory") != (out[j].Kind == "directory") {
			return out[i].Kind == "directory"
		}
		return out[i].Name < out[j].Name
	})
	return map[string]any{"path": path, "directory": core.FileEntry{Name: filepath.Base(path), Path: path, Kind: "directory", Size: info.Size(), Mode: fileMetadataMode(info.Mode()), Owner: fileMetadataOwner(info), ModifiedAt: info.ModTime().UTC().Format(time.RFC3339)}, "entries": out, "summary": summary, "truncated": summary.Truncated, "scanned": scanned}, nil
}

// SearchTree searches filenames below one managed directory. It never follows
// links, and the limits keep a single UI search from monopolizing the executor.
func (f *siteFiles) SearchTree(ctx context.Context, path, search string) (map[string]any, error) {
	search = strings.TrimSpace(search)
	if !core.ValidFilePath(path, true) || search == "" || len(search) > 128 {
		return nil, errors.New("无效目录或搜索条件")
	}
	if path == "" {
		path = "."
	}
	dir, e := openRootPathNoLinks(f.public, path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	info, e := dir.Stat()
	if e != nil || !info.IsDir() {
		_ = dir.Close()
		return nil, errors.New("请选择目录")
	}
	_, summary, _, e := readFileDirectory(dir, path, true)
	_ = dir.Close()
	if e != nil {
		return nil, e
	}
	pins, e := f.readPins()
	if e != nil {
		return nil, e
	}
	needle := strings.ToLower(search)
	out := make([]core.FileEntry, 0)
	visited := 0
	e = fs.WalkDir(f.public.FS(), path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		visited++
		if visited > 100000 || strings.Count(current, "/") > 64 {
			return errors.New("子目录搜索项目或层级过多，请缩小范围")
		}
		if current == path {
			return nil
		}
		if !core.ValidFilePath(current, false) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.Contains(strings.ToLower(entry.Name()), needle) {
			return nil
		}
		if len(out) >= 10000 {
			return errors.New("子目录搜索结果过多，请缩小范围")
		}
		st, e := entry.Info()
		if e != nil {
			return e
		}
		owner := ""
		if stat, ok := st.Sys().(*syscall.Stat_t); ok {
			owner = strconv.FormatUint(uint64(stat.Uid), 10)
		}
		out = append(out, core.FileEntry{Name: entry.Name(), Path: current, Kind: fileKind(st.Mode()), Pinned: pins[current], Size: st.Size(), Mode: fileMetadataMode(st.Mode()), Owner: owner, ModifiedAt: st.ModTime().UTC().Format(time.RFC3339)})
		return nil
	})
	if e != nil {
		return nil, e
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pinned != out[j].Pinned {
			return out[i].Pinned
		}
		if out[i].Kind == "directory" && out[j].Kind != "directory" {
			return true
		}
		if out[j].Kind == "directory" && out[i].Kind != "directory" {
			return false
		}
		return out[i].Path < out[j].Path
	})
	return map[string]any{"path": path, "directory": core.FileEntry{Name: filepath.Base(path), Path: path, Kind: "directory", Size: info.Size(), Mode: fileMetadataMode(info.Mode()), Owner: fileMetadataOwner(info), ModifiedAt: info.ModTime().UTC().Format(time.RFC3339)}, "entries": out, "summary": summary, "truncated": false, "scanned": visited}, nil
}
func (f *siteFiles) Text(path string) (core.FileText, error) {
	out := core.FileText{Path: path}
	if !core.ValidFilePath(path, false) {
		return out, errors.New("无效文件路径")
	}
	file, e := regularFile(f.public, path)
	if e != nil {
		return out, e
	}
	defer file.Close()
	st, e := file.Stat()
	if e != nil {
		return out, e
	}
	if st.Size() > core.MaxTextFile {
		return out, errors.New("文本编辑上限 32 KiB，更大文件请下载编辑后上传")
	}
	b, e := io.ReadAll(io.LimitReader(file, core.MaxTextFile+1))
	if e != nil {
		return out, e
	}
	if len(b) > core.MaxTextFile || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return out, errors.New("文件不是可编辑的 UTF-8 文本")
	}
	h := sha256.Sum256(b)
	out.Content = string(b)
	out.SHA256 = hex.EncodeToString(h[:])
	out.Mode = fmt.Sprintf("%04o", st.Mode().Perm())
	return out, nil
}
func (f *siteFiles) privateDir(name string) error { return f.root.MkdirAll(filePrivate+"/"+name, 0700) }
func (f *siteFiles) temp() (*os.File, string, error) {
	if e := f.privateDir("tmp"); e != nil {
		return nil, "", e
	}
	name := filePrivate + "/tmp/" + core.ID()
	out, e := openRootPathNoLinks(f.root, name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	return out, name, e
}

// Open parent directory descriptors under os.Root, then ask the kernel for an
// atomic no-replace rename. A concurrent target creation never gets overwritten.
func renameNoReplace(root *os.Root, src, dst string) error {
	return renameBetween(root, src, root, dst, false)
}
func renameBetween(source *os.Root, src string, target *os.Root, dst string, replace bool) error {
	a, e := openRootPathNoLinks(source, filepath.Dir(src), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer a.Close()
	b, e := openRootPathNoLinks(target, filepath.Dir(dst), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer b.Close()
	if replace {
		return unix.Renameat(int(a.Fd()), filepath.Base(src), int(b.Fd()), filepath.Base(dst))
	}
	return unix.Renameat2(int(a.Fd()), filepath.Base(src), int(b.Fd()), filepath.Base(dst), unix.RENAME_NOREPLACE)
}
func (f *siteFiles) writeMeta(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	out, temp, e := f.temp()
	if e != nil {
		return e
	}
	defer f.root.Remove(temp)
	_, e = out.Write(b)
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return f.root.Rename(temp, path)
}
func (f *siteFiles) readPins() (map[string]bool, error) {
	pins := make(map[string]bool)
	b, e := f.root.ReadFile(filePrivate + "/pins.json")
	if errors.Is(e, fs.ErrNotExist) {
		return pins, nil
	}
	if e != nil {
		return nil, e
	}
	if len(b) > 128*1024 {
		return nil, errors.New("置顶记录超过限制")
	}
	var saved []string
	if e = json.Unmarshal(b, &saved); e != nil || len(saved) > 1000 {
		return nil, errors.New("置顶记录损坏")
	}
	for _, path := range saved {
		if !core.ValidFilePath(path, false) {
			return nil, errors.New("置顶记录包含无效路径")
		}
		pins[path] = true
	}
	return pins, nil
}
func (f *siteFiles) setPin(path string, enabled bool) (any, error) {
	file, e := openRootPathNoLinks(f.public, path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	st, e := file.Stat()
	file.Close()
	if e != nil || (!st.IsDir() && !st.Mode().IsRegular()) {
		return nil, errors.New("只能置顶普通文件或目录")
	}
	pins, e := f.readPins()
	if e != nil {
		return nil, e
	}
	if enabled {
		pins[path] = true
	} else {
		delete(pins, path)
	}
	if len(pins) > 1000 {
		return nil, errors.New("最多置顶 1000 项")
	}
	if e = f.savePins(pins); e != nil {
		return nil, e
	}
	return map[string]any{"path": path, "pinned": enabled}, nil
}
func (f *siteFiles) savePins(pins map[string]bool) error {
	paths := make([]string, 0, len(pins))
	for value := range pins {
		paths = append(paths, value)
	}
	sort.Strings(paths)
	if e := f.privateDir(""); e != nil {
		return e
	}
	return f.writeMeta(filePrivate+"/pins.json", paths)
}
func (f *siteFiles) movePins(oldPath, newPath string) error {
	pins, e := f.readPins()
	if e != nil {
		return e
	}
	changed := false
	for path := range pins {
		if path == oldPath || strings.HasPrefix(path, oldPath+"/") {
			delete(pins, path)
			if newPath != "" {
				pins[newPath+strings.TrimPrefix(path, oldPath)] = true
			}
			changed = true
		}
	}
	if changed {
		return f.savePins(pins)
	}
	return nil
}
func (f *siteFiles) prepareShare(path, id string) (any, error) {
	if !core.ValidID(id) {
		return nil, errors.New("无效分享标识")
	}
	source, e := regularFile(f.public, path)
	if e != nil {
		return nil, e
	}
	defer source.Close()
	st, e := source.Stat()
	if e != nil || st.Size() < 0 || st.Size() > core.MaxFileUpload {
		return nil, errors.New("只允许分享不超过 512 MiB 的普通文件")
	}
	if e = f.privateDir("shares"); e != nil {
		return nil, e
	}
	dir := filePrivate + "/shares/" + id
	if e = f.root.Mkdir(dir, 0700); e != nil {
		return nil, e
	}
	ready := false
	defer func() {
		if !ready {
			_ = f.root.RemoveAll(dir)
		}
	}()
	out, e := openRootPathNoLinks(f.root, dir+"/payload", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	h := sha256.New()
	n, e := io.CopyN(io.MultiWriter(out, h), source, st.Size())
	if e == nil {
		e = out.Sync()
	}
	if ce := out.Close(); e == nil {
		e = ce
	}
	if e != nil || n != st.Size() {
		return nil, errors.New("创建分享快照失败或原文件已变化")
	}
	ready = true
	return map[string]any{"name": filepath.Base(path), "bytes": n, "sha256": hex.EncodeToString(h.Sum(nil))}, nil
}
func (f *siteFiles) purgeShare(id string) (any, error) {
	if !core.ValidID(id) {
		return nil, errors.New("无效分享标识")
	}
	return map[string]bool{"ok": true}, f.root.RemoveAll(filePrivate + "/shares/" + id)
}
func (f *siteFiles) retain(path, reason, kind string, content []byte) (core.TrashEntry, error) {
	item := core.TrashEntry{ID: core.ID(), Path: path, Kind: kind, Reason: reason, DeletedAt: core.Now()}
	st, err := f.public.Lstat(path)
	if err != nil {
		return item, err
	}
	item.Mode = fmt.Sprintf("%04o", st.Mode().Perm())
	if e := f.privateDir("trash"); e != nil {
		return item, e
	}
	capacity, e := f.root.Open(filePrivate + "/trash")
	if e != nil {
		return item, e
	}
	existing, e := capacity.ReadDir(2000)
	capacity.Close()
	if e != nil && e != io.EOF {
		return item, e
	}
	if len(existing) >= 2000 {
		return item, errors.New("回收站已达到 2000 条上限，请先清理不再需要的副本")
	}
	dir := filePrivate + "/trash/" + item.ID
	if e := f.root.MkdirAll(dir, 0700); e != nil {
		return item, e
	}
	retained := false
	defer func() {
		if !retained {
			_ = f.root.RemoveAll(dir)
		}
	}()
	if e := f.writeMeta(dir+"/meta.json", item); e != nil {
		return item, e
	}
	if reason == "edit" {
		out, e := openRootPathNoLinks(f.root, dir+"/payload", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return item, e
		}
		_, e = out.Write(content)
		if e == nil {
			e = out.Sync()
		}
		ce := out.Close()
		if e != nil {
			return item, e
		}
		retained = ce == nil
		return item, ce
	}
	e = renameBetween(f.public, path, f.root, dir+"/payload", false)
	retained = e == nil
	return item, e
}
func (f *siteFiles) Trash() ([]core.TrashEntry, error) {
	if e := f.privateDir("trash"); e != nil {
		return nil, e
	}
	dir, e := f.root.Open(filePrivate + "/trash")
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	entries, e := dir.ReadDir(2001)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(entries) > 2000 {
		return nil, errors.New("回收记录超过 2000 条，请先清理确认不再需要的副本")
	}
	out := []core.TrashEntry{}
	for _, entry := range entries {
		if !core.ValidID(entry.Name()) || !entry.IsDir() {
			continue
		}
		item, e := f.trashItem(entry.Name())
		if e == nil {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeletedAt > out[j].DeletedAt })
	return out, nil
}
func (f *siteFiles) trashItem(id string) (core.TrashEntry, error) {
	var item core.TrashEntry
	if !core.ValidID(id) {
		return item, errors.New("无效回收标识")
	}
	b, e := f.root.ReadFile(filePrivate + "/trash/" + id + "/meta.json")
	if e == nil {
		e = json.Unmarshal(b, &item)
	}
	if e == nil && (item.ID != id || !core.ValidFilePath(item.Path, false)) {
		e = errors.New("回收元数据异常")
	}
	if e == nil {
		_, e = f.root.Lstat(filePrivate + "/trash/" + id + "/payload")
	}
	return item, e
}
func (f *siteFiles) Upload(path, digest string, input io.Reader, size int64) (map[string]any, error) {
	return f.upload(path, digest, input, size, 0644)
}
func (f *siteFiles) upload(path, digest string, input io.Reader, size int64, mode os.FileMode) (map[string]any, error) {
	if !core.ValidFilePath(path, false) || size < 0 || size > core.MaxFileUpload {
		return nil, errors.New("无效文件路径或上传超过 512 MiB")
	}
	if digest != "" {
		if b, e := hex.DecodeString(digest); e != nil || len(b) != 32 {
			return nil, errors.New("无效 SHA-256")
		}
	}
	out, temp, e := f.temp()
	if e != nil {
		return nil, e
	}
	defer f.root.Remove(temp)
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(out, h), io.LimitReader(input, core.MaxFileUpload+1))
	if e == nil && n != size {
		e = errors.New("上传长度不匹配或超过限制")
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if e == nil && digest != "" && actual != digest {
		e = errors.New("上传 SHA-256 不匹配")
	}
	if e == nil {
		e = out.Chown(f.uid, f.gid)
	}
	if e == nil {
		e = out.Chmod(mode & 0777)
	}
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e != nil {
		return nil, e
	}
	if ce != nil {
		return nil, ce
	}
	if e = renameBetween(f.root, temp, f.public, path, false); e != nil {
		return nil, fmt.Errorf("上传未覆盖任何现有文件: %w", e)
	}
	return map[string]any{"path": path, "bytes": n, "sha256": actual}, nil
}
func (f *siteFiles) Action(in core.FileAction) (any, error) {
	if in.Action != "restore" && in.Action != "purge" && in.Action != "share_purge" && !core.ValidFilePath(in.Path, false) {
		return nil, errors.New("无效文件路径")
	}
	switch in.Action {
	case "create":
		if len(in.Content) > core.MaxTextFile || !utf8.ValidString(in.Content) || strings.ContainsRune(in.Content, 0) {
			return nil, errors.New("文本必须为不超过 32 KiB 的 UTF-8 内容")
		}
		return f.Upload(in.Path, "", strings.NewReader(in.Content), int64(len(in.Content)))
	case "save":
		if len(in.Content) > core.MaxTextFile || !utf8.ValidString(in.Content) || strings.ContainsRune(in.Content, 0) {
			return nil, errors.New("文本必须为不超过 32 KiB 的 UTF-8 内容")
		}
		old, e := f.Text(in.Path)
		if e != nil {
			return nil, e
		}
		if in.ExpectedSHA256 == "" || old.SHA256 != in.ExpectedSHA256 {
			return nil, errors.New("文件已发生变化，请重新读取再保存")
		}
		backup, e := f.retain(in.Path, "edit", "file", []byte(old.Content))
		if e != nil {
			return nil, e
		}
		out, temp, e := f.temp()
		if e != nil {
			return nil, e
		}
		defer f.root.Remove(temp)
		_, e = out.WriteString(in.Content)
		if e == nil {
			e = out.Chown(f.uid, f.gid)
		}
		mode, _ := strconv.ParseUint(old.Mode, 8, 32)
		if e == nil {
			e = out.Chmod(os.FileMode(mode))
		}
		if e == nil {
			e = out.Sync()
		}
		ce := out.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
		// Recheck after writing the temporary file, so stale editor buffers fail closed.
		current, e := f.Text(in.Path)
		if e != nil {
			return nil, e
		}
		if current.SHA256 != in.ExpectedSHA256 || current.Mode != old.Mode {
			return nil, errors.New("保存期间文件变化，已保留编辑前副本")
		}
		if e = renameBetween(f.root, temp, f.public, in.Path, true); e != nil {
			return nil, e
		}
		return map[string]any{"path": in.Path, "backup": backup}, nil
	case "mkdir":
		if e := mkdirRootPathNoLinks(f.public, in.Path, 0755); e != nil {
			return nil, e
		}
		dir, e := openRootPathNoLinks(f.public, in.Path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return nil, e
		}
		defer dir.Close()
		if e = dir.Chown(f.uid, f.gid); e != nil {
			return nil, e
		}
		return map[string]bool{"ok": true}, dir.Chmod(0755)
	case "mkdirs":
		return f.mkdirs(in.Path)
	case "rename":
		if !core.ValidFilePath(in.Destination, false) || in.Destination == in.Path {
			return nil, errors.New("无效目标路径")
		}
		if e := renameNoReplace(f.public, in.Path, in.Destination); e != nil {
			return nil, e
		}
		return map[string]bool{"ok": true}, f.movePins(in.Path, in.Destination)
	case "copy":
		if !core.ValidFilePath(in.Destination, false) || in.Destination == in.Path || strings.HasPrefix(in.Destination, in.Path+"/") {
			return nil, errors.New("无效复制目标路径")
		}
		return f.copyEntry(in.Path, in.Destination)
	case "chmod":
		mode, e := strconv.ParseUint(in.Mode, 8, 32)
		if e != nil || len(in.Mode) < 3 || len(in.Mode) > 4 || mode > 0777 {
			return nil, errors.New("权限必须为 0000–0777 八进制，不允许特殊权限位")
		}
		file, e := openRootPathNoLinks(f.public, in.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return nil, e
		}
		defer file.Close()
		st, e := file.Stat()
		if e != nil || (!st.IsDir() && !st.Mode().IsRegular()) {
			return nil, errors.New("不能修改链接或特殊文件权限")
		}
		return map[string]bool{"ok": true}, file.Chmod(os.FileMode(mode))
	case "trash":
		st, e := f.public.Lstat(in.Path)
		if e != nil {
			return nil, e
		}
		result, e := f.retain(in.Path, "delete", fileKind(st.Mode()), nil)
		if e != nil {
			return nil, e
		}
		return result, f.movePins(in.Path, "")
	case "restore":
		item, e := f.trashItem(in.TrashID)
		if e != nil {
			return nil, e
		}
		dest := item.Path
		if in.Destination != "" {
			dest = in.Destination
		}
		if !core.ValidFilePath(dest, false) {
			return nil, errors.New("无效恢复路径")
		}
		dir := filePrivate + "/trash/" + item.ID
		if item.Reason == "edit" {
			file, e := regularFile(f.root, dir+"/payload")
			if e != nil {
				return nil, e
			}
			defer file.Close()
			st, _ := file.Stat()
			mode, e := strconv.ParseUint(item.Mode, 8, 32)
			if e != nil {
				return nil, errors.New("回收文件权限元数据无效")
			}
			return f.upload(dest, "", file, st.Size(), os.FileMode(mode))
		}
		if e = renameBetween(f.root, dir+"/payload", f.public, dest, false); e != nil {
			return nil, fmt.Errorf("恢复不会覆盖现有内容: %w", e)
		}
		if e = f.root.Remove(dir + "/meta.json"); e != nil {
			return nil, e
		}
		return map[string]bool{"ok": true}, f.root.Remove(dir)
	case "purge":
		item, e := f.trashItem(in.TrashID)
		if e != nil {
			return nil, e
		}
		return map[string]bool{"ok": true}, f.root.RemoveAll(filePrivate + "/trash/" + item.ID)
	case "compress":
		return f.compress(in.Path, in.Destination)
	case "pin":
		return f.setPin(in.Path, true)
	case "unpin":
		return f.setPin(in.Path, false)
	case "share_prepare":
		return f.prepareShare(in.Path, in.ShareID)
	case "share_purge":
		return f.purgeShare(in.ShareID)
	case "extract":
		return f.extract(in.Path, in.Destination)
	default:
		return nil, errors.New("文件操作不在允许范围")
	}
}

func (f *siteFiles) mkdirs(path string) (any, error) {
	root, e := openRootPathNoLinks(f.public, ".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	parent := int(root.Fd())
	opened := -1
	defer func() {
		if opened >= 0 {
			unix.Close(opened)
		}
	}()
	for _, part := range strings.Split(path, "/") {
		e = unix.Mkdirat(parent, part, 0755)
		if e != nil && !errors.Is(e, unix.EEXIST) {
			return nil, e
		}
		next, err := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		if e == nil {
			err = unix.Fchown(next, f.uid, f.gid)
			if err == nil {
				err = unix.Fchmod(next, 0755)
			}
		}
		if opened >= 0 {
			unix.Close(opened)
		}
		opened = next
		parent = next
		if err != nil {
			return nil, err
		}
	}
	return map[string]bool{"ok": true}, nil
}

func (f *siteFiles) copyEntry(src, dest string) (any, error) {
	st, e := f.public.Lstat(src)
	if e != nil {
		return nil, e
	}
	if st.Mode().IsRegular() {
		if st.Size() > core.MaxFileUpload {
			return nil, errors.New("复制内容超过 512 MiB")
		}
		file, err := regularFile(f.public, src)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return f.upload(dest, "", file, st.Size(), st.Mode().Perm())
	}
	if !st.IsDir() {
		return nil, errors.New("不能复制链接或特殊文件")
	}
	if e = f.privateDir("tmp"); e != nil {
		return nil, e
	}
	stage := filePrivate + "/tmp/" + core.ID()
	if e = f.root.Mkdir(stage, 0700); e != nil {
		return nil, e
	}
	defer f.root.RemoveAll(stage)
	root, e := f.root.OpenRoot(stage)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	var total int64
	count := 0
	directoryModes := map[string]os.FileMode{".": st.Mode().Perm()}
	e = fs.WalkDir(f.public.FS(), src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 10000 {
			return errors.New("复制文件数超过 10000")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			directoryModes[rel] = info.Mode().Perm()
			if rel != "." {
				return root.MkdirAll(rel, 0755)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("不能复制链接或特殊文件")
		}
		if info.Size() > core.MaxFileUpload-total {
			return errors.New("复制内容超过 512 MiB")
		}
		total += info.Size()
		if err = root.MkdirAll(filepath.Dir(rel), 0755); err != nil {
			return err
		}
		from, err := regularFile(f.public, path)
		if err != nil {
			return err
		}
		out, err := openRootPathNoLinks(root, rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			from.Close()
			return err
		}
		_, err = io.CopyN(out, from, info.Size())
		if err == nil {
			err = out.Chown(f.uid, f.gid)
		}
		if err == nil {
			err = out.Chmod(info.Mode().Perm() & 0755)
		}
		if ce := out.Close(); err == nil {
			err = ce
		}
		if ce := from.Close(); err == nil {
			err = ce
		}
		return err
	})
	if e != nil {
		return nil, e
	}
	e = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		dir, err := openRootPathNoLinks(root, path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer dir.Close()
		if err = dir.Chown(f.uid, f.gid); err != nil {
			return err
		}
		return dir.Chmod(directoryModes[path] & 0755)
	})
	if e != nil {
		return nil, e
	}
	return map[string]any{"path": dest, "entries": count, "bytes": total}, renameBetween(f.root, stage, f.public, dest, false)
}
func (f *siteFiles) compress(src, dest string) (any, error) {
	lower := strings.ToLower(dest)
	zipFormat := strings.HasSuffix(lower, ".zip")
	targzFormat := strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
	tarbz2Format := strings.HasSuffix(lower, ".tar.bz2") || strings.HasSuffix(lower, ".tbz2")
	tarxzFormat := strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".txz")
	tarFormat := strings.HasSuffix(lower, ".tar")
	if !core.ValidFilePath(dest, false) || !(zipFormat || targzFormat || tarbz2Format || tarxzFormat || tarFormat) {
		return nil, errors.New("请选择尚不存在的 .zip、.tar、.tar.gz、.tar.bz2 或 .tar.xz 目标文件")
	}
	out, temp, e := f.temp()
	if e != nil {
		return nil, e
	}
	defer f.root.Remove(temp)
	var zipWriter *zip.Writer
	var tarWriter *tar.Writer
	var gzipWriter *gzip.Writer
	var bzip2Writer *bzip2writer.Writer
	var xzWriter *xz.Writer
	if zipFormat {
		zipWriter = zip.NewWriter(out)
	} else if targzFormat {
		gzipWriter = gzip.NewWriter(out)
		tarWriter = tar.NewWriter(gzipWriter)
	} else if tarbz2Format {
		bzip2Writer, e = bzip2writer.NewWriter(out, nil)
		if e != nil {
			out.Close()
			return nil, e
		}
		tarWriter = tar.NewWriter(bzip2Writer)
	} else if tarxzFormat {
		xzWriter, e = xz.NewWriter(out)
		if e != nil {
			out.Close()
			return nil, e
		}
		tarWriter = tar.NewWriter(xzWriter)
	} else {
		tarWriter = tar.NewWriter(out)
	}
	var total int64
	count := 0
	e = fs.WalkDir(f.public.FS(), src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 10000 {
			return errors.New("压缩文件数超过 10000")
		}
		st, e := entry.Info()
		if e != nil {
			return e
		}
		if !st.IsDir() && !st.Mode().IsRegular() {
			return errors.New("压缩不包含符号链接和特殊文件")
		}
		rel, e := filepath.Rel(filepath.Dir(src), path)
		if e != nil {
			return e
		}
		var w io.Writer
		if zipWriter != nil {
			h, err := zip.FileInfoHeader(st)
			if err != nil {
				return err
			}
			h.Name = rel
			if st.IsDir() {
				h.Name += "/"
			} else {
				h.Method = zip.Deflate
			}
			w, err = zipWriter.CreateHeader(h)
			if err != nil {
				return err
			}
		} else {
			h, err := tar.FileInfoHeader(st, "")
			if err != nil {
				return err
			}
			h.Name = filepath.ToSlash(rel)
			if st.IsDir() {
				h.Name += "/"
			}
			if err = tarWriter.WriteHeader(h); err != nil {
				return err
			}
			w = tarWriter
		}
		if st.IsDir() {
			return nil
		}
		if st.Size() > core.MaxFileUpload-total {
			return errors.New("压缩前内容超过 512 MiB")
		}
		total += st.Size()
		file, e := regularFile(f.public, path)
		if e != nil {
			return e
		}
		_, e = io.CopyN(w, file, st.Size())
		if closeErr := file.Close(); e == nil {
			e = closeErr
		}
		return e
	})
	var archiveCloseErr error
	if zipWriter != nil {
		archiveCloseErr = zipWriter.Close()
	} else {
		archiveCloseErr = tarWriter.Close()
		if gzipWriter != nil {
			if ce := gzipWriter.Close(); archiveCloseErr == nil {
				archiveCloseErr = ce
			}
		}
		if bzip2Writer != nil {
			if ce := bzip2Writer.Close(); archiveCloseErr == nil {
				archiveCloseErr = ce
			}
		}
		if xzWriter != nil {
			if ce := xzWriter.Close(); archiveCloseErr == nil {
				archiveCloseErr = ce
			}
		}
	}
	if e == nil {
		e = archiveCloseErr
	}
	if e == nil {
		st, statErr := out.Stat()
		if statErr != nil {
			e = statErr
		} else if st.Size() > core.MaxFileUpload {
			e = errors.New("压缩包超过 512 MiB")
		}
	}
	if e == nil {
		e = out.Chown(f.uid, f.gid)
	}
	if e == nil {
		e = out.Chmod(0644)
	}
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e != nil {
		return nil, e
	}
	if ce != nil {
		return nil, ce
	}
	return map[string]any{"path": dest, "entries": count, "source_bytes": total}, renameBetween(f.root, temp, f.public, dest, false)
}
func (f *siteFiles) extract(src, dest string) (any, error) {
	if !core.ValidFilePath(dest, false) {
		return nil, errors.New("请选择尚不存在的解压目录")
	}
	if archiveTarKind(src) != "" {
		return f.extractTar(src, dest)
	}
	if !strings.HasSuffix(strings.ToLower(src), ".zip") {
		return nil, errors.New("支持 ZIP、TAR、TAR.GZ、TAR.BZ2 和 TAR.XZ 压缩包")
	}
	file, e := regularFile(f.public, src)
	if e != nil {
		return nil, e
	}
	defer file.Close()
	st, e := file.Stat()
	if e != nil {
		return nil, e
	}
	if st.Size() > core.MaxFileUpload {
		return nil, errors.New("ZIP 文件超过 512 MiB")
	}
	zr, e := zip.NewReader(file, st.Size())
	if e != nil {
		return nil, errors.New("当前只支持标准 ZIP 压缩包")
	}
	if len(zr.File) > 10000 {
		return nil, errors.New("解压文件数超过 10000")
	}
	if e = f.privateDir("tmp"); e != nil {
		return nil, e
	}
	stage := filePrivate + "/tmp/" + core.ID()
	if e = f.root.Mkdir(stage, 0700); e != nil {
		return nil, e
	}
	defer f.root.RemoveAll(stage)
	root, e := f.root.OpenRoot(stage)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	var total uint64
	seen := map[string]bool{}
	directoryModes := map[string]os.FileMode{".": 0755}
	for _, z := range zr.File {
		rel := strings.TrimSuffix(z.Name, "/")
		if !core.ValidFilePath(rel, false) {
			return nil, errors.New("ZIP 包包含越界或保留路径")
		}
		mode := z.Mode()
		if !mode.IsDir() && !mode.IsRegular() {
			return nil, errors.New("ZIP 包包含链接或特殊文件")
		}
		if seen[rel] && !mode.IsDir() {
			return nil, errors.New("ZIP 包包含重复文件")
		}
		seen[rel] = true
		if z.UncompressedSize64 > uint64(core.MaxFileUpload)-total {
			return nil, errors.New("解压后内容超过 512 MiB")
		}
		total += z.UncompressedSize64
		if mode.IsDir() {
			directoryModes[rel] = (mode.Perm() & 0755) | 0700
			if e = root.MkdirAll(rel, 0755); e != nil {
				return nil, e
			}
			continue
		}
		if e = root.MkdirAll(filepath.Dir(rel), 0755); e != nil {
			return nil, e
		}
		destFile, e := openRootPathNoLinks(root, rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if e != nil {
			return nil, e
		}
		reader, e := z.Open()
		if e != nil {
			destFile.Close()
			return nil, e
		}
		n, e := io.Copy(destFile, io.LimitReader(reader, int64(z.UncompressedSize64)+1))
		re := reader.Close()
		if e == nil {
			e = re
		}
		if e == nil && uint64(n) != z.UncompressedSize64 {
			e = errors.New("解压长度不匹配")
		}
		if e == nil {
			e = destFile.Chown(f.uid, f.gid)
		}
		if e == nil {
			e = destFile.Chmod(mode.Perm() & 0755)
		}
		ce := destFile.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
	}
	// The staging tree is root-only until complete. Set ownership via opened file
	// descriptors before its single atomic publication into the site's public tree.
	e = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		dir, e := openRootPathNoLinks(root, path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		defer dir.Close()
		if e = dir.Chown(f.uid, f.gid); e != nil {
			return e
		}
		mode := os.FileMode(0755)
		if desired, ok := directoryModes[path]; ok {
			mode = desired
		}
		return dir.Chmod(mode)
	})
	if e != nil {
		return nil, e
	}
	return map[string]any{"path": dest, "entries": len(zr.File), "bytes": total}, renameBetween(f.root, stage, f.public, dest, false)
}

func archiveTarKind(name string) string {
	name = strings.ToLower(name)
	switch {
	case strings.HasSuffix(name, ".tar"):
		return "tar"
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return "gzip"
	case strings.HasSuffix(name, ".tar.bz2"), strings.HasSuffix(name, ".tbz2"):
		return "bzip2"
	case strings.HasSuffix(name, ".tar.xz"), strings.HasSuffix(name, ".txz"):
		return "xz"
	default:
		return ""
	}
}

func (f *siteFiles) extractTar(src, dest string) (any, error) {
	file, e := regularFile(f.public, src)
	if e != nil {
		return nil, e
	}
	defer file.Close()
	st, e := file.Stat()
	if e != nil {
		return nil, e
	}
	if st.Size() > core.MaxFileUpload {
		return nil, errors.New("压缩包超过 512 MiB")
	}

	var stream io.Reader = file
	switch archiveTarKind(src) {
	case "gzip":
		gz, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		stream = gz
	case "bzip2":
		stream = bzip2.NewReader(file)
	case "xz":
		stream, e = xz.NewReader(file)
		if e != nil {
			return nil, e
		}
	}
	if e = f.privateDir("tmp"); e != nil {
		return nil, e
	}
	stage := filePrivate + "/tmp/" + core.ID()
	if e = f.root.Mkdir(stage, 0700); e != nil {
		return nil, e
	}
	defer f.root.RemoveAll(stage)
	root, e := f.root.OpenRoot(stage)
	if e != nil {
		return nil, e
	}
	defer root.Close()

	reader := tar.NewReader(stream)
	var total int64
	count := 0
	seen := map[string]byte{}
	directoryModes := map[string]os.FileMode{".": 0755}
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		count++
		if count > 10000 {
			return nil, errors.New("解压文件数超过 10000")
		}
		isDir := h.Typeflag == tar.TypeDir
		if !isDir && h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return nil, errors.New("TAR 包包含链接或特殊文件")
		}
		rel := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		if isDir && (rel == "" || rel == ".") {
			continue
		}
		if !core.ValidFilePath(rel, false) {
			return nil, errors.New("TAR 包包含越界或保留路径")
		}
		if isDir {
			if seen[rel] == 'f' {
				return nil, errors.New("TAR 包包含重复路径")
			}
			seen[rel] = 'd'
			directoryModes[rel] = (os.FileMode(h.Mode) & 0755) | 0700
			if e = root.MkdirAll(rel, 0755); e != nil {
				return nil, e
			}
			continue
		}
		if seen[rel] != 0 {
			return nil, errors.New("TAR 包包含重复路径")
		}
		seen[rel] = 'f'
		if h.Size < 0 || h.Size > core.MaxFileUpload-total {
			return nil, errors.New("解压后内容超过 512 MiB")
		}
		total += h.Size
		if e = root.MkdirAll(filepath.Dir(rel), 0755); e != nil {
			return nil, e
		}
		out, err := openRootPathNoLinks(root, rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, err = io.CopyN(out, reader, h.Size)
		if err == nil {
			err = out.Chown(f.uid, f.gid)
		}
		if err == nil {
			err = out.Chmod(os.FileMode(h.Mode) & 0755)
		}
		if ce := out.Close(); err == nil {
			err = ce
		}
		if err != nil {
			return nil, err
		}
	}
	// Force the decompressor to consume its trailer (including gzip CRC). Reject
	// an archive with an unbounded amount of data after the TAR end marker.
	remaining, e := io.Copy(io.Discard, io.LimitReader(stream, 1024*1024+1))
	if e != nil {
		return nil, e
	}
	if remaining > 1024*1024 {
		return nil, errors.New("TAR 包尾部数据过长")
	}
	e = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		dir, err := openRootPathNoLinks(root, path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer dir.Close()
		if err = dir.Chown(f.uid, f.gid); err != nil {
			return err
		}
		mode := os.FileMode(0755)
		if desired, ok := directoryModes[path]; ok {
			mode = desired
		}
		return dir.Chmod(mode)
	})
	if e != nil {
		return nil, e
	}
	return map[string]any{"path": dest, "entries": count, "bytes": total}, renameBetween(f.root, stage, f.public, dest, false)
}

func filePage[T any](r *http.Request, entries []T) map[string]any {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 100
	}
	total := len(entries)
	// Clamp before multiplying so an untrusted page cannot overflow an int.
	last := (total + limit - 1) / limit
	if last < 1 {
		last = 1
	}
	if page > last {
		page = last
	}
	start := (page - 1) * limit
	end := start + limit
	if end > total {
		end = total
	}
	return map[string]any{"entries": entries[start:end], "total": total, "page": page, "limit": limit}
}
func (s *Service) fileRoutes(m *http.ServeMux) {
	s.fileCloudRoutes(m)
	s.siteBackupRoutes(m)
	s.siteRestoreRoutes(m)
	s.logCleanupRoutes(m)
	s.adminScriptRoutes(m)
	s.remoteBackupRoutes(m)
	s.panelAccessRoutes(m)
	for _, suffix := range []string{"", "/text", "/trash", "/size"} {
		suffix := suffix
		m.HandleFunc("GET /v1/sites/{id}/files"+suffix, func(w http.ResponseWriter, r *http.Request) {
			f, e := s.openFiles(r.PathValue("id"))
			if e != nil {
				respond(w, 404, map[string]string{"error": e.Error()})
				return
			}
			defer f.Close()
			var out any
			switch suffix {
			case "":
				var listing map[string]any
				if r.URL.Query().Get("recursive") == "1" && strings.TrimSpace(r.URL.Query().Get("search")) != "" {
					ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
					listing, e = f.SearchTree(ctx, r.URL.Query().Get("path"), r.URL.Query().Get("search"))
					cancel()
				} else {
					listing, e = f.List(r.URL.Query().Get("path"), r.URL.Query().Get("search"))
				}
				if e == nil {
					result := filePage(r, listing["entries"].([]core.FileEntry))
					for _, key := range []string{"path", "directory", "summary", "scanned", "truncated"} {
						result[key] = listing[key]
					}
					out = result
				}
			case "/text":
				out, e = f.Text(r.URL.Query().Get("path"))
			case "/trash":
				var items []core.TrashEntry
				items, e = f.Trash()
				if e == nil {
					out = filePage(r, items)
				}
			case "/size":
				ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
				out, e = f.DirectorySize(ctx, r.URL.Query().Get("path"))
				cancel()
			}
			if e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
			respond(w, 200, out)
		})
	}
	m.HandleFunc("POST /v1/sites/{id}/files/action", func(w http.ResponseWriter, r *http.Request) {
		var in core.FileAction
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF {
			respond(w, 400, map[string]string{"error": "无效文件请求"})
			return
		}
		lock := fileMutex(r.PathValue("id"))
		lock.Lock()
		defer lock.Unlock()
		f, e := s.openFiles(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": e.Error()})
			return
		}
		defer f.Close()
		out, e := f.Action(in)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/sites/{id}/files/upload", func(w http.ResponseWriter, r *http.Request) {
		ctrl := http.NewResponseController(w)
		_ = ctrl.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_ = ctrl.SetWriteDeadline(time.Now().Add(5 * time.Minute))
		lock := fileMutex(r.PathValue("id"))
		lock.Lock()
		defer lock.Unlock()
		f, e := s.openFiles(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": e.Error()})
			return
		}
		defer f.Close()
		out, e := f.Upload(r.URL.Query().Get("path"), r.URL.Query().Get("sha256"), http.MaxBytesReader(w, r.Body, core.MaxFileUpload), r.ContentLength)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, out)
	})
	m.HandleFunc("GET /v1/sites/{id}/files/download", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if !core.ValidFilePath(path, false) {
			respond(w, 400, map[string]string{"error": "无效文件路径"})
			return
		}
		f, e := s.openFiles(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": e.Error()})
			return
		}
		defer f.Close()
		file, e := regularFile(f.public, path)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		defer file.Close()
		st, e := file.Stat()
		if e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(path)}))
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		w.WriteHeader(200)
		_, _ = io.CopyN(w, file, st.Size())
	})
	m.HandleFunc("GET /v1/sites/{id}/files/shares/{shareID}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("shareID")
		if !core.ValidID(id) {
			respond(w, 404, map[string]string{"error": "分享不存在"})
			return
		}
		f, e := s.openFiles(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "分享不存在"})
			return
		}
		defer f.Close()
		file, e := regularFile(f.root, filePrivate+"/shares/"+id+"/payload")
		if e != nil {
			respond(w, 404, map[string]string{"error": "分享不存在"})
			return
		}
		defer file.Close()
		st, e := file.Stat()
		if e != nil {
			respond(w, 404, map[string]string{"error": "分享不存在"})
			return
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		w.WriteHeader(200)
		_, _ = io.CopyN(w, file, st.Size())
	})
}
