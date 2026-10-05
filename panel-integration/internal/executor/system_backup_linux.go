//go:build linux

package executor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"local/panel/internal/core"
	"mime"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/scrypt"
)

const systemBackupDir = "/var/backups/panel/system"
const systemBackupMagic = "PNLBKP01"
const systemBackupMax = 256 * 1024 * 1024

type systemBackupEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type systemBackupManifest struct {
	Format    string              `json:"format"`
	CreatedAt string              `json:"created_at"`
	Schema    int                 `json:"schema"`
	Arch      string              `json:"arch"`
	Entries   []systemBackupEntry `json:"entries"`
}
type systemSource struct{ archive, path string }

func validateBackupPassphrase(value string) error {
	if len(value) < 12 || len(value) > 256 {
		return errors.New("备份密码应为 12–256 个字符")
	}
	return nil
}
func encryptSystemBundle(plain []byte, passphrase string) ([]byte, error) {
	if e := validateBackupPassphrase(passphrase); e != nil {
		return nil, e
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	key, e := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	header := append([]byte(systemBackupMagic), salt...)
	header = append(header, nonce...)
	return append(header, a.Seal(nil, nonce, plain, header)...), nil
}
func decryptSystemBundle(data []byte, passphrase string) ([]byte, error) {
	if e := validateBackupPassphrase(passphrase); e != nil {
		return nil, e
	}
	if len(data) < 8+16+12+16 || string(data[:8]) != systemBackupMagic {
		return nil, errors.New("不是受支持的面板备份")
	}
	salt, nonce := data[8:24], data[24:36]
	key, e := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	plain, e := a.Open(nil, nonce, data[36:], data[:36])
	if e != nil {
		return nil, errors.New("备份密码错误或归档已经损坏")
	}
	return plain, nil
}

func collectSystemSources(dbSnapshot string) ([]systemSource, error) {
	out := []systemSource{{"var/lib/panel/panel.db", dbSnapshot}, {"var/lib/panel/credential-key", "/var/lib/panel/credential-key"}}
	roots := []struct{ archive, path string }{{"etc/panel", "/etc/panel"}}
	for _, root := range roots {
		e := filepath.WalkDir(root.path, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if path == root.path {
				return nil
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("系统备份拒绝符号链接: %s", path)
			}
			if d.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("系统备份拒绝特殊文件: %s", path)
			}
			rel, e := filepath.Rel(root.path, path)
			if e != nil {
				return e
			}
			out = append(out, systemSource{filepath.ToSlash(filepath.Join(root.archive, rel)), path})
			return nil
		})
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}

func makeSystemArchive(sources []systemSource, schema int) ([]byte, systemBackupManifest, error) {
	manifest := systemBackupManifest{Format: "panel-backup-v1", CreatedAt: core.Now(), Schema: schema, Arch: runtime.GOARCH, Entries: []systemBackupEntry{}}
	contents := make([][]byte, 0, len(sources))
	var total int64
	for _, source := range sources {
		if strings.HasPrefix(source.archive, "/") || strings.Contains(source.archive, "../") {
			return nil, manifest, errors.New("归档路径无效")
		}
		info, e := os.Lstat(source.path)
		if e != nil {
			return nil, manifest, e
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 {
			return nil, manifest, errors.New("归档源文件类型或链接数异常")
		}
		if info.Size() > 64*1024*1024 {
			return nil, manifest, errors.New("单个元数据文件超过 64 MiB")
		}
		data, e := os.ReadFile(source.path)
		if e != nil {
			return nil, manifest, e
		}
		total += int64(len(data))
		if total > 128*1024*1024 {
			return nil, manifest, errors.New("元数据归档超过 128 MiB")
		}
		sum := sha256.Sum256(data)
		manifest.Entries = append(manifest.Entries, systemBackupEntry{Path: source.archive, Mode: uint32(info.Mode().Perm()), Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
		contents = append(contents, data)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	raw, _ := json.Marshal(manifest)
	if e := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(raw)), ModTime: time.Unix(0, 0)}); e != nil {
		return nil, manifest, e
	}
	if _, e := tw.Write(raw); e != nil {
		return nil, manifest, e
	}
	for i, entry := range manifest.Entries {
		if e := tw.WriteHeader(&tar.Header{Name: entry.Path, Mode: int64(entry.Mode), Size: entry.Size, ModTime: time.Unix(0, 0)}); e != nil {
			return nil, manifest, e
		}
		if _, e := tw.Write(contents[i]); e != nil {
			return nil, manifest, e
		}
	}
	if e := tw.Close(); e != nil {
		return nil, manifest, e
	}
	if e := gz.Close(); e != nil {
		return nil, manifest, e
	}
	return compressed.Bytes(), manifest, nil
}

func (s *Service) createSystemBackup(ctx context.Context, in core.SystemBackupCreateRequest) (core.SystemBackup, error) {
	var result core.SystemBackup
	if !core.ValidID(in.ID) {
		return result, errors.New("系统备份标识无效")
	}
	if e := validateBackupPassphrase(in.Passphrase); e != nil {
		return result, e
	}
	if e := os.MkdirAll(systemBackupDir, 0700); e != nil {
		return result, e
	}
	tmp, e := os.CreateTemp("/var/lib/panel-executor", "panel-db-snapshot-*.db")
	if e != nil {
		return result, e
	}
	snapshot := tmp.Name()
	tmp.Close()
	os.Remove(snapshot)
	defer os.Remove(snapshot)
	command := fmt.Sprintf(".backup '%s'", strings.ReplaceAll(snapshot, "'", "''"))
	if _, e = s.Config.Run(ctx, "/usr/bin/sqlite3", "/var/lib/panel/panel.db", command); e != nil {
		return result, fmt.Errorf("创建 SQLite 一致快照失败: %w", e)
	}
	out, e := s.Config.Run(ctx, "/usr/bin/sqlite3", snapshot, "SELECT max(version) FROM schema_migrations; PRAGMA integrity_check;")
	if e != nil {
		return result, e
	}
	lines := strings.Fields(out)
	if len(lines) < 2 || lines[len(lines)-1] != "ok" {
		return result, errors.New("SQLite 快照完整性检查失败")
	}
	schema, e := strconv.Atoi(lines[0])
	if e != nil {
		return result, e
	}
	sources, e := collectSystemSources(snapshot)
	if e != nil {
		return result, e
	}
	plain, manifest, e := makeSystemArchive(sources, schema)
	if e != nil {
		return result, e
	}
	encrypted, e := encryptSystemBundle(plain, in.Passphrase)
	if e != nil {
		return result, e
	}
	dest := filepath.Join(systemBackupDir, in.ID+".pbackup")
	if e = atomicWrite(dest, encrypted, 0600); e != nil {
		return result, e
	}
	sum := sha256.Sum256(encrypted)
	return core.SystemBackup{ID: in.ID, Format: manifest.Format, Bytes: int64(len(encrypted)), SHA256: hex.EncodeToString(sum[:]), Files: len(manifest.Entries), Schema: schema, Arch: manifest.Arch, CreatedAt: manifest.CreatedAt}, nil
}

func extractSystemBundle(bundle, passphrase, destination string) (systemBackupManifest, error) {
	var manifest systemBackupManifest
	info, e := os.Lstat(destination)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return manifest, errors.New("恢复目标必须是已存在的普通目录")
	}
	entries, e := os.ReadDir(destination)
	if e != nil || len(entries) != 0 {
		return manifest, errors.New("恢复目标必须为空")
	}
	file, e := os.Open(bundle)
	if e != nil {
		return manifest, e
	}
	data, e := io.ReadAll(io.LimitReader(file, systemBackupMax+1))
	file.Close()
	if e != nil {
		return manifest, e
	}
	if len(data) > systemBackupMax {
		return manifest, errors.New("系统备份超过 256 MiB")
	}
	plain, e := decryptSystemBundle(data, passphrase)
	if e != nil {
		return manifest, e
	}
	gz, e := gzip.NewReader(bytes.NewReader(plain))
	if e != nil {
		return manifest, errors.New("备份压缩层损坏")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	modes := map[string]uint32{}
	for {
		header, re := tr.Next()
		if re == io.EOF {
			break
		}
		if re != nil {
			return manifest, re
		}
		name := filepath.ToSlash(filepath.Clean(header.Name))
		if name == "." || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") || header.Typeflag != tar.TypeReg {
			return manifest, errors.New("备份包含不安全路径或文件类型")
		}
		if _, exists := files[name]; exists {
			return manifest, errors.New("备份包含重复路径")
		}
		if header.Size < 0 || header.Size > 64*1024*1024 {
			return manifest, errors.New("备份文件大小无效")
		}
		content, re := io.ReadAll(io.LimitReader(tr, header.Size+1))
		if re != nil || int64(len(content)) != header.Size {
			return manifest, errors.New("备份文件读取不完整")
		}
		files[name] = content
		modes[name] = uint32(header.Mode) & 0777
	}
	raw, ok := files["manifest.json"]
	if !ok || json.Unmarshal(raw, &manifest) != nil || manifest.Format != "panel-backup-v1" {
		return manifest, errors.New("备份清单无效")
	}
	if len(files) != len(manifest.Entries)+1 {
		return manifest, errors.New("备份清单与文件数量不一致")
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		content, ok := files[entry.Path]
		sum := sha256.Sum256(content)
		if !ok || seen[entry.Path] || int64(len(content)) != entry.Size || hex.EncodeToString(sum[:]) != entry.SHA256 || modes[entry.Path] != entry.Mode {
			return manifest, errors.New("备份文件与清单不一致")
		}
		seen[entry.Path] = true
		target := filepath.Join(destination, filepath.FromSlash(entry.Path))
		rel, _ := filepath.Rel(destination, target)
		if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return manifest, errors.New("恢复路径越界")
		}
		if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
			return manifest, e
		}
		if e = os.WriteFile(target, content, fs.FileMode(entry.Mode)); e != nil {
			return manifest, e
		}
	}
	account, e := user.Lookup("panel")
	if e != nil {
		return manifest, errors.New("恢复前必须存在 panel 系统账户")
	}
	uid, e1 := strconv.Atoi(account.Uid)
	gid, e2 := strconv.Atoi(account.Gid)
	if e1 != nil || e2 != nil {
		return manifest, errors.New("panel 系统账户标识无效")
	}
	dataDir := filepath.Join(destination, "var/lib/panel")
	if e = filepath.Walk(dataDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("恢复数据目录包含符号链接")
		}
		return os.Chown(path, uid, gid)
	}); e != nil {
		return manifest, e
	}
	if e = os.Chmod(dataDir, 0750); e != nil {
		return manifest, e
	}
	return manifest, nil
}

func RestoreSystemBackup(bundle, passphraseFile, destination string) error {
	info, e := os.Lstat(passphraseFile)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("密码文件必须是权限 0600 的普通文件")
	}
	raw, e := os.ReadFile(passphraseFile)
	if e != nil {
		return e
	}
	pass := strings.TrimRight(string(raw), "\r\n")
	_, e = extractSystemBundle(bundle, pass, destination)
	return e
}

func openSystemBackup(id string, size int64, digest string) (*os.File, error) {
	if !core.ValidID(id) || size < 1 || size > systemBackupMax || len(digest) != 64 {
		return nil, errors.New("系统备份参数无效")
	}
	path := filepath.Join(systemBackupDir, id+".pbackup")
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || stat.Nlink != 1 || info.Size() != size {
		return nil, errors.New("系统备份权限、类型或大小异常")
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	h := sha256.New()
	if _, e = io.Copy(h, file); e != nil {
		file.Close()
		return nil, e
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		file.Close()
		return nil, errors.New("系统备份摘要不匹配")
	}
	_, e = file.Seek(0, io.SeekStart)
	if e != nil {
		file.Close()
	}
	return file, e
}

func (s *Service) systemBackupRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/system-backups/create", func(w http.ResponseWriter, r *http.Request) {
		var in core.SystemBackupCreateRequest
		if !readJSON(w, r, &in) {
			return
		}
		result, e := s.createSystemBackup(r.Context(), in)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, result)
	})
	m.HandleFunc("GET /v1/system-backups/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		size, e := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if e != nil {
			respond(w, 400, map[string]string{"error": "备份大小无效"})
			return
		}
		file, e := openSystemBackup(r.PathValue("id"), size, r.URL.Query().Get("sha256"))
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "panel-system-" + r.PathValue("id")[:8] + ".pbackup"}))
		http.ServeContent(w, r, "", time.Time{}, file)
	})
}
