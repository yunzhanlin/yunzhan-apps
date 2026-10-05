//go:build linux

package executor

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"local/panel/internal/core"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

var siteBackups = "/var/backups/panel/sites"

func (s *Service) createSiteBackup(ctx context.Context, expected core.SiteBackup) (core.SiteBackup, error) {
	if !core.ValidID(expected.ID) || !core.ValidID(expected.SiteID) {
		return expected, errors.New("网站备份标识无效")
	}
	f, e := s.openFiles(expected.SiteID)
	if e != nil {
		return expected, e
	}
	defer f.Close()
	if e = os.MkdirAll(siteBackups, 0700); e != nil {
		return expected, e
	}
	dir := filepath.Join(siteBackups, expected.SiteID)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return expected, e
	}
	_ = os.Chmod(siteBackups, 0700)
	_ = os.Chmod(dir, 0700)
	metaPath, archivePath := filepath.Join(dir, expected.ID+".json"), filepath.Join(dir, expected.ID+".zip")
	if _, e = os.Stat(metaPath); e == nil {
		return verifySiteBackup(ctx, expected)
	} else if !errors.Is(e, os.ErrNotExist) {
		return expected, e
	}
	part := archivePath + ".part"
	// A prior executor crash can leave an incomplete part without a manifest.
	// The per-site lock ensures no live backup for this site is using it.
	if e = os.Remove(part); e != nil && !errors.Is(e, os.ErrNotExist) {
		return expected, e
	}
	out, e := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return expected, e
	}
	defer os.Remove(part)
	hash := sha256.New()
	counter := &countingWriter{Writer: io.MultiWriter(out, hash)}
	writer := zip.NewWriter(counter)
	var sourceBytes int64
	files := 0
	e = fs.WalkDir(f.public.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("网站备份不跟随符号链接或特殊文件")
		}
		if path == "." {
			return nil
		}
		files++
		if files > 100000 {
			return errors.New("网站备份条目超过 100000")
		}
		if !info.IsDir() {
			if info.Size() > 2*1024*1024*1024-sourceBytes {
				return errors.New("网站备份源文件超过 2 GiB")
			}
			sourceBytes += info.Size()
		}
		header, e := zip.FileInfoHeader(info)
		if e != nil {
			return e
		}
		header.Name = "public/" + filepath.ToSlash(path)
		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}
		entryWriter, e := writer.CreateHeader(header)
		if e != nil || info.IsDir() {
			return e
		}
		file, e := regularFile(f.public, path)
		if e != nil {
			return e
		}
		_, copyErr := io.CopyN(entryWriter, file, info.Size())
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	closeZip := writer.Close()
	if e == nil {
		e = closeZip
	}
	if e == nil {
		e = out.Sync()
	}
	closeFile := out.Close()
	if e == nil {
		e = closeFile
	}
	if e != nil {
		return expected, e
	}
	if e = os.Rename(part, archivePath); e != nil {
		return expected, e
	}
	expected.Format = "zip"
	expected.Files = files
	expected.SourceBytes = sourceBytes
	expected.Bytes = counter.N
	expected.SHA256 = hex.EncodeToString(hash.Sum(nil))
	if expected.CreatedAt == "" {
		expected.CreatedAt = core.Now()
	}
	raw, _ := json.Marshal(expected)
	if e = atomicWrite(metaPath, raw, 0600); e != nil {
		return expected, e
	}
	return expected, nil
}

type countingWriter struct {
	io.Writer
	N int64
}

type siteBackupDeletionReceipt struct {
	Backup core.SiteBackup `json:"backup"`
	State  string          `json:"state"`
}

func deleteVerifiedSiteBackup(ctx context.Context, expected core.SiteBackup) error {
	if !core.ValidID(expected.ID) || !core.ValidID(expected.SiteID) || expected.Bytes < 0 || len(expected.SHA256) != 64 {
		return errors.New("网站备份清理身份无效")
	}
	dir := filepath.Join(siteBackups, expected.SiteID)
	receiptPath := filepath.Join(dir, ".deleted-"+expected.ID+".json")
	var receipt siteBackupDeletionReceipt
	if info, e := os.Lstat(receiptPath); e == nil {
		if e = privateBackupEntry(info, false); e != nil {
			return e
		}
		raw, e := os.ReadFile(receiptPath)
		if e != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Backup != expected || (receipt.State != "pending" && receipt.State != "deleted") {
			return errors.New("网站备份清理回执与请求不一致")
		}
		if receipt.State == "deleted" {
			return nil
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	_, e := verifySiteBackup(ctx, expected)
	if e != nil {
		if receipt.State == "pending" && errors.Is(e, os.ErrNotExist) {
			if e = removeSiteBackupPair(dir, expected.ID); e != nil {
				return e
			}
			receipt.State = "deleted"
			raw, _ := json.Marshal(receipt)
			return atomicWrite(receiptPath, raw, 0600)
		}
		return e
	}
	receipt = siteBackupDeletionReceipt{Backup: expected, State: "pending"}
	raw, _ := json.Marshal(receipt)
	if e = atomicWrite(receiptPath, raw, 0600); e != nil {
		return e
	}
	if e = removeSiteBackupPair(dir, expected.ID); e != nil {
		return e
	}
	receipt.State = "deleted"
	raw, _ = json.Marshal(receipt)
	return atomicWrite(receiptPath, raw, 0600)
}

func removeSiteBackupPair(dir, id string) error {
	root, e := os.OpenRoot(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	for _, name := range []string{id + ".zip", id + ".json"} {
		if e = root.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	folder, e := os.Open(dir)
	if e == nil {
		e = folder.Sync()
		folder.Close()
	}
	return e
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, e := w.Writer.Write(p)
	w.N += int64(n)
	return n, e
}

func verifySiteBackup(ctx context.Context, expected core.SiteBackup) (core.SiteBackup, error) {
	var actual core.SiteBackup
	if !core.ValidID(expected.ID) || !core.ValidID(expected.SiteID) {
		return actual, errors.New("网站备份标识无效")
	}
	dir := filepath.Join(siteBackups, expected.SiteID)
	if e := ownedRuntimePath(siteBackups, true); e != nil {
		return actual, e
	}
	if info, e := os.Stat(dir); e != nil || privateBackupEntry(info, true) != nil {
		return actual, errors.New("网站备份目录异常")
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return actual, e
	}
	defer root.Close()
	open := func(name string) (*os.File, error) {
		file, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return nil, e
		}
		info, e := file.Stat()
		if e == nil {
			e = privateBackupEntry(info, false)
		}
		if e != nil {
			file.Close()
		}
		return file, e
	}
	meta, e := open(expected.ID + ".json")
	if e != nil {
		return actual, e
	}
	raw, e := io.ReadAll(io.LimitReader(meta, 16385))
	meta.Close()
	if e != nil || len(raw) > 16384 || json.Unmarshal(raw, &actual) != nil {
		return actual, errors.New("网站备份清单无效")
	}
	if actual.ID != expected.ID || actual.SiteID != expected.SiteID || actual.Format != "zip" || actual.Bytes < 0 || len(actual.SHA256) != 64 || (expected.SHA256 != "" && (actual.SHA256 != expected.SHA256 || actual.Bytes != expected.Bytes)) {
		return actual, errors.New("网站备份清单与请求不一致")
	}
	archive, e := open(expected.ID + ".zip")
	if e != nil {
		return actual, e
	}
	defer archive.Close()
	h := sha256.New()
	buffer := make([]byte, 256*1024)
	var size int64
	for {
		if e = ctx.Err(); e != nil {
			return actual, e
		}
		n, readErr := archive.Read(buffer)
		if n > 0 {
			size += int64(n)
			_, _ = h.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return actual, readErr
		}
	}
	if size != actual.Bytes || hex.EncodeToString(h.Sum(nil)) != actual.SHA256 {
		return actual, errors.New("网站备份大小或 SHA-256 不匹配")
	}
	return actual, nil
}

func (s *Service) siteBackupRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sites/{id}/backups", func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
		var expected core.SiteBackup
		if !readJSON(w, r, &expected) {
			return
		}
		if expected.SiteID != r.PathValue("id") {
			respond(w, 400, map[string]string{"error": "网站备份归属不匹配"})
			return
		}
		lock := fileMutex(expected.SiteID)
		lock.Lock()
		defer lock.Unlock()
		backup, e := s.createSiteBackup(r.Context(), expected)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, backup)
	})
	m.HandleFunc("GET /v1/sites/{site}/backups/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		bytes, e := strconv.ParseInt(q.Get("bytes"), 10, 64)
		if e != nil {
			respond(w, 400, map[string]string{"error": "网站备份大小无效"})
			return
		}
		expected := core.SiteBackup{ID: r.PathValue("id"), SiteID: r.PathValue("site"), Bytes: bytes, SHA256: q.Get("sha256")}
		actual, e := verifySiteBackup(r.Context(), expected)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		file, e := os.Open(filepath.Join(siteBackups, actual.SiteID, actual.ID+".zip"))
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		defer file.Close()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "site-" + actual.SiteID[:8] + "-" + actual.ID[:8] + ".zip"}))
		w.Header().Set("Content-Length", strconv.FormatInt(actual.Bytes, 10))
		w.Header().Set("X-Content-SHA256", actual.SHA256)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		_, _ = io.CopyN(w, file, actual.Bytes)
	})
	m.HandleFunc("DELETE /v1/sites/{site}/backups/{id}", func(w http.ResponseWriter, r *http.Request) {
		bytes, e := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if e != nil {
			respond(w, 400, map[string]string{"error": "网站备份大小无效"})
			return
		}
		expected := core.SiteBackup{ID: r.PathValue("id"), SiteID: r.PathValue("site"), Bytes: bytes, SHA256: r.URL.Query().Get("sha256")}
		lock := fileMutex(expected.SiteID)
		lock.Lock()
		defer lock.Unlock()
		if e = deleteVerifiedSiteBackup(r.Context(), expected); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]bool{"deleted": true})
	})
}
