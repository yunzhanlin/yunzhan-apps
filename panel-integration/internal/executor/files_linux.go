//go:build linux

package executor

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	file, e := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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
func (f *siteFiles) List(path, search string) (map[string]any, error) {
	if !core.ValidFilePath(path, true) || len(search) > 128 {
		return nil, errors.New("无效目录或搜索条件")
	}
	if path == "" {
		path = "."
	}
	dir, e := f.public.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	info, e := dir.Stat()
	if e != nil || !info.IsDir() {
		return nil, errors.New("请选择目录")
	}
	entries, e := dir.ReadDir(10001)
	if e != nil && e != io.EOF {
		return nil, e
	}
	truncated := len(entries) > 10000
	if truncated {
		entries = entries[:10000]
	}
	out := []core.FileEntry{}
	for _, entry := range entries {
		if !core.ValidFilePath(filepath.Join(path, entry.Name()), false) || !strings.Contains(strings.ToLower(entry.Name()), strings.ToLower(search)) {
			continue
		}
		st, e := entry.Info()
		if e != nil {
			continue
		}
		out = append(out, core.FileEntry{Name: entry.Name(), Path: filepath.Join(path, entry.Name()), Kind: fileKind(st.Mode()), Size: st.Size(), Mode: fmt.Sprintf("%04o", st.Mode().Perm()), ModifiedAt: st.ModTime().UTC().Format(time.RFC3339)})
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Kind == "directory") != (out[j].Kind == "directory") {
			return out[i].Kind == "directory"
		}
		return out[i].Name < out[j].Name
	})
	return map[string]any{"path": path, "directory": core.FileEntry{Name: filepath.Base(path), Path: path, Kind: "directory", Size: info.Size(), Mode: fmt.Sprintf("%04o", info.Mode().Perm()), ModifiedAt: info.ModTime().UTC().Format(time.RFC3339)}, "entries": out, "truncated": truncated, "scanned": len(entries)}, nil
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
	out, e := f.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	return out, name, e
}

// Open parent directory descriptors under os.Root, then ask the kernel for an
// atomic no-replace rename. A concurrent target creation never gets overwritten.
func renameNoReplace(root *os.Root, src, dst string) error {
	return renameBetween(root, src, root, dst, false)
}
func renameBetween(source *os.Root, src string, target *os.Root, dst string, replace bool) error {
	a, e := source.OpenFile(filepath.Dir(src), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer a.Close()
	b, e := target.OpenFile(filepath.Dir(dst), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
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
		out, e := f.root.OpenFile(dir+"/payload", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
	if in.Action != "restore" && in.Action != "purge" && !core.ValidFilePath(in.Path, false) {
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
		if e := f.public.Mkdir(in.Path, 0755); e != nil {
			return nil, e
		}
		dir, e := f.public.OpenFile(in.Path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return nil, e
		}
		defer dir.Close()
		if e = dir.Chown(f.uid, f.gid); e != nil {
			return nil, e
		}
		return map[string]bool{"ok": true}, dir.Chmod(0755)
	case "rename":
		if !core.ValidFilePath(in.Destination, false) || in.Destination == in.Path {
			return nil, errors.New("无效目标路径")
		}
		return map[string]bool{"ok": true}, renameNoReplace(f.public, in.Path, in.Destination)
	case "chmod":
		mode, e := strconv.ParseUint(in.Mode, 8, 32)
		if e != nil || len(in.Mode) < 3 || len(in.Mode) > 4 || mode > 0777 {
			return nil, errors.New("权限必须为 0000–0777 八进制，不允许特殊权限位")
		}
		file, e := f.public.OpenFile(in.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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
		return f.retain(in.Path, "delete", fileKind(st.Mode()), nil)
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
	case "extract":
		return f.extract(in.Path, in.Destination)
	default:
		return nil, errors.New("文件操作不在允许范围")
	}
}
func (f *siteFiles) compress(src, dest string) (any, error) {
	if !core.ValidFilePath(dest, false) || !strings.HasSuffix(strings.ToLower(dest), ".zip") {
		return nil, errors.New("请选择尚不存在的 .zip 目标文件")
	}
	out, temp, e := f.temp()
	if e != nil {
		return nil, e
	}
	defer f.root.Remove(temp)
	writer := zip.NewWriter(out)
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
		h, e := zip.FileInfoHeader(st)
		if e != nil {
			return e
		}
		h.Name = rel
		if st.IsDir() {
			h.Name += "/"
		} else {
			h.Method = zip.Deflate
		}
		w, e := writer.CreateHeader(h)
		if e != nil {
			return e
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
		defer file.Close()
		_, e = io.CopyN(w, file, st.Size())
		return e
	})
	ce := writer.Close()
	if e == nil {
		e = ce
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
	ce = out.Close()
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
		destFile, e := root.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
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
		dir, e := root.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
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
	s.siteBackupRoutes(m)
	s.siteRestoreRoutes(m)
	s.logCleanupRoutes(m)
	s.adminScriptRoutes(m)
	s.remoteBackupRoutes(m)
	s.panelAccessRoutes(m)
	for _, suffix := range []string{"", "/text", "/trash"} {
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
				listing, e = f.List(r.URL.Query().Get("path"), r.URL.Query().Get("search"))
				if e == nil {
					result := filePage(r, listing["entries"].([]core.FileEntry))
					for _, key := range []string{"path", "directory", "scanned", "truncated"} {
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
}
