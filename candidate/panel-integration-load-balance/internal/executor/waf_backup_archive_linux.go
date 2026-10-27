//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func (s *Service) wafBackupArchiveInstalled() error {
	raw, err := apacheWAFHistoryRead(s.softwareManifestPath("nginx-waf"), 512<<10)
	if err != nil {
		return errors.New("须先核对现有防火墙安装身份；未接管或创建记录")
	}
	var manifest softwareManifest
	if decodeApacheWAFPrivateJSON(raw, &manifest, map[string]bool{"id": true, "version": true, "settings": true, "installed_at": true}, 32768) != nil || manifest.ID != "nginx-waf" || manifest.Version != core.WAFVersion || len(manifest.Previous) != 0 {
		return errors.New("现有防火墙安装身份或版本不可核对")
	}
	at, err := time.Parse(time.RFC3339, manifest.InstalledAt)
	if err != nil || at.IsZero() || len(manifest.InstalledAt) > 40 {
		return errors.New("现有防火墙安装时间不可核对")
	}
	_, err = core.DecodeWAFConfig(manifest.Settings)
	return err
}

func (s *Service) wafBackupArchiveNoPending() error {
	for _, path := range []string{s.wafPendingPath(), s.analyticsHTMLTransactionService().wafPendingPath()} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("有待恢复或不可核对的原配置标记；禁止归档证据")
		}
		parent := filepath.Dir(path)
		for {
			_, err := os.Lstat(parent)
			if err == nil {
				if err = s.wafOwnedDirectory(parent, false); err != nil {
					return err
				}
				break
			}
			if !errors.Is(err, os.ErrNotExist) || filepath.Dir(parent) == parent {
				return errors.New("待恢复配置的祖先身份不可核对")
			}
			parent = filepath.Dir(parent)
		}
	}
	return nil
}

type wafArchiveFileIdentity struct {
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
	Mode   os.FileMode
	Size   int64
}

func wafArchiveSnapshotIdentity(root *os.Root, name string) (map[string]wafArchiveFileIdentity, error) {
	path := filepath.Join(root.Name(), name)
	if _, err := wafBackupPrivateDirectory(path); err != nil {
		return nil, err
	}
	entries, err := wafBackupDirectoryEntries(path, wafBackupFileSlots+1)
	if err != nil {
		return nil, err
	}
	out := map[string]wafArchiveFileIdentity{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, errors.New("原快照含未知类型")
		}
		f, err := root.OpenFile(filepath.Join(name, entry.Name()), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !st.Mode().IsRegular() || st.Mode() != 0600 || !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || st.Size() < 0 || st.Size() > 8<<20 {
			f.Close()
			return nil, errors.New("原快照文件身份不可核对")
		}
		identity := wafArchiveFileIdentity{uint64(owner.Dev), owner.Ino, owner.Uid, owner.Gid, st.Mode(), st.Size()}
		err = f.Sync()
		f.Close()
		if err != nil {
			return nil, err
		}
		out[entry.Name()] = identity
	}
	return out, nil
}

type wafBackupArchiveIO struct {
	rename        func(int, string, int, string, uint) error
	syncDirectory func(*os.File) error
}

// All production entry points use these fixed syscalls. The internal seam is
// only for native fault-injection tests; no route or configuration selects it.
func (s *Service) archiveWAFBackup(ctx context.Context, in core.WAFBackupArchiveInput) (map[string]any, error) {
	return s.archiveWAFBackupWithIO(ctx, in, wafBackupArchiveIO{rename: unix.Renameat2, syncDirectory: (*os.File).Sync})
}

// This operation never applies an old
// configuration or deletes bytes: one verified original directory moves via
// a same-filesystem, no-overwrite rename, then persistence and identity checks.
func (s *Service) archiveWAFBackupWithIO(ctx context.Context, in core.WAFBackupArchiveInput, operation wafBackupArchiveIO) (map[string]any, error) {
	if operation.rename == nil || operation.syncDirectory == nil {
		return nil, errors.New("原归档固定交接操作不可用")
	}
	if err := core.ValidateWAFBackupArchive(in); err != nil {
		return nil, err
	}
	lock, lockInfo, err := s.openExistingWAFBackupLock(ctx, syscall.LOCK_EX)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err = s.wafBackupArchiveInstalled(); err != nil {
		return nil, err
	}
	if err = s.wafBackupArchiveNoPending(); err != nil {
		return nil, err
	}
	active, err := s.scanWAFBackupSelection(ctx, "waf-backups", in.ID)
	if err != nil {
		return nil, err
	}
	archived, err := s.scanWAFBackupSelection(ctx, "waf-backup-archive", "")
	if err != nil {
		return nil, err
	}
	var original *wafBackupInventoryRow
	for i := range archived.Entries {
		if archived.Entries[i].ID == in.ID {
			original = &archived.Entries[i]
			break
		}
	}
	replayed := len(active.Entries) == 0 && original != nil
	if len(active.Entries) == 1 && original != nil {
		return nil, errors.New("活动和归档标识冲突；保留双方原证据，不覆盖")
	}
	if !replayed {
		if len(active.Entries) != 1 || active.Entries[0].SHA != in.SHA {
			return nil, errors.New("所选完整原快照缺失或摘要改变；未归档")
		}
		if len(archived.Entries) >= 100 || archived.Bytes > wafBackupInventoryBytes-active.Entries[0].Bytes {
			return nil, errors.New("归档已达 100 份或 128 MiB 逻辑上限；未删除原证据")
		}
		original = &active.Entries[0]
	} else if original.SHA != in.SHA {
		return nil, errors.New("原归档摘要不匹配；未重建或覆盖")
	}
	base := s.Config.SecurityDir
	baseInfo, err := os.Lstat(base)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	parent, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	unchangedBase := func() error {
		if err := s.wafOwnedDirectory(base, false); err != nil {
			return err
		}
		for _, read := range []func() (os.FileInfo, error){parent.Stat, func() (os.FileInfo, error) { return os.Lstat(base) }} {
			after, err := read()
			if err != nil || !os.SameFile(baseInfo, after) || baseInfo.Mode() != after.Mode() {
				return errors.New("原配置安全目录交接期间改变")
			}
			a, aok := baseInfo.Sys().(*syscall.Stat_t)
			b, bok := after.Sys().(*syscall.Stat_t)
			if !aok || !bok || a.Uid != b.Uid || a.Gid != b.Gid {
				return errors.New("原配置安全目录所有者改变")
			}
		}
		return nil
	}
	if err = unchangedBase(); err != nil {
		return nil, err
	}
	if !replayed {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if err = root.Mkdir("waf-backup-archive", 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	openDir := func(name string) (*os.File, error) {
		before, err := wafBackupPrivateDirectory(filepath.Join(base, name))
		if err != nil {
			return nil, err
		}
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		after, err := f.Stat()
		if err != nil || !os.SameFile(before, after) {
			f.Close()
			return nil, errors.New("原配置备份目录打开期间改变")
		}
		return f, nil
	}
	target, err := openDir("waf-backup-archive")
	if err != nil {
		return nil, err
	}
	defer target.Close()
	var source *os.File
	location := "waf-backup-archive/" + in.ID
	if !replayed {
		location = "waf-backups/" + in.ID
		source, err = openDir("waf-backups")
		if err != nil {
			return nil, err
		}
		defer source.Close()
	}
	before, err := wafBackupPrivateDirectory(filepath.Join(base, location))
	if err != nil {
		return nil, err
	}
	files, err := wafArchiveSnapshotIdentity(root, location)
	if err != nil {
		return nil, err
	}
	for _, dir := range []*os.File{source, target, parent} {
		if dir != nil {
			if err = operation.syncDirectory(dir); err != nil {
				return nil, err
			}
		}
	}
	if err = wafBackupLockUnchanged(lock, filepath.Join(base, "waf-configuration.lock"), lockInfo); err != nil {
		return nil, err
	}
	if err = unchangedBase(); err != nil {
		return nil, err
	}
	if !replayed {
		fresh, err := s.scanWAFBackupSelection(ctx, "waf-backups", in.ID)
		if err != nil || len(fresh.Entries) != 1 || fresh.Entries[0] != *original {
			return nil, errors.New("所选完整原快照改变；未交接")
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if err = operation.rename(int(source.Fd()), in.ID, int(target.Fd()), in.ID, unix.RENAME_NOREPLACE); err != nil {
			return nil, errors.New("归档目标存在、跨文件系统或无覆盖交接不受支持；未覆盖证据")
		}
	}
	// Never abandon persistence merely because the browser disconnected after
	// handoff. The original ID and full SHA are the only replay identity.
	for _, dir := range []*os.File{source, target, parent} {
		if dir != nil {
			if err = operation.syncDirectory(dir); err != nil {
				return nil, errors.New("原快照可能已交接，但持久化未确认；按原标识和摘要核对")
			}
		}
	}
	finish, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	final, err := s.scanWAFBackupSelection(finish, "waf-backup-archive", in.ID)
	if err != nil || len(final.Entries) != 1 || final.Entries[0] != *original {
		return nil, errors.New("原归档完整内容尚未确认；原证据保留")
	}
	after, err := wafBackupPrivateDirectory(filepath.Join(base, "waf-backup-archive", in.ID))
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return nil, errors.New("原归档目录身份尚未确认；原证据保留")
	}
	oldOwner := before.Sys().(*syscall.Stat_t)
	newOwner := after.Sys().(*syscall.Stat_t)
	actual, err := wafArchiveSnapshotIdentity(root, "waf-backup-archive/"+in.ID)
	if err != nil || oldOwner.Uid != newOwner.Uid || oldOwner.Gid != newOwner.Gid || !reflect.DeepEqual(files, actual) {
		return nil, errors.New("原归档文件身份尚未确认；原证据保留")
	}
	if err = finish.Err(); err != nil {
		return nil, errors.New("归档后核对超时；须按原标识和摘要核对，不能宣称失败未移动")
	}
	if err = unchangedBase(); err != nil {
		return nil, errors.New("归档后安全目录身份不可确认；须按原标识和摘要核对")
	}
	if err = wafBackupLockUnchanged(lock, filepath.Join(base, "waf-configuration.lock"), lockInfo); err != nil {
		return nil, errors.New("归档后原配置锁身份不可确认；须按原标识和摘要核对")
	}
	return map[string]any{"snapshot": final.Entries[0], "archived": true, "replayed": replayed, "records_retained": true, "configuration_changed": false}, nil
}

func (s *Service) wafBackupArchiveRoutes(m *http.ServeMux) {
	for _, selected := range []bool{false, true} {
		path := "/v1/software/nginx-waf/config-backup-archive"
		if selected {
			path += "/{id}"
		}
		m.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			id := r.PathValue("id")
			if r.URL.RawQuery != "" || r.URL.ForceQuery || selected && !core.ValidID(id) {
				respond(w, 400, map[string]string{"error": "原归档标识或查询字段无效"})
				return
			}
			out, err := s.readWAFBackupNamespace(r.Context(), "waf-backup-archive", id)
			if err != nil {
				respond(w, 409, map[string]string{"error": "原归档未完整核验；不返回配置正文或部分库存"})
				return
			}
			if selected {
				if !out.Available || len(out.Entries) != 1 || out.Entries[0].ID != id {
					respond(w, 404, map[string]string{"error": "所选原归档不可核对；未创建或修复证据"})
					return
				}
				respond(w, 200, out.Entries[0])
				return
			}
			respond(w, 200, out)
		})
	}
	m.HandleFunc("POST /v1/software/nginx-waf/archive-config-backup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "原快照归档不接受查询字段"})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			respond(w, 400, map[string]string{"error": "原快照归档超过 4 KiB 或不可读取"})
			return
		}
		in, err := core.DecodeWAFBackupArchive(raw)
		if err != nil {
			respond(w, 400, map[string]string{"error": "原标识、摘要或归档确认不可核对"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		out, err := s.archiveWAFBackup(ctx, in)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原归档未确认；保留原标识和摘要核对，未删除证据，不宣称未移动"})
			return
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			respond(w, 503, map[string]string{"error": "原归档回执不可读取；须按原标识和摘要核对"})
			return
		}
		closed, err := core.DecodeWAFBackupArchiveResult(encoded, in)
		if err != nil {
			respond(w, 503, map[string]string{"error": "原归档回执不可核对；须按原标识和摘要核对"})
			return
		}
		respond(w, 200, closed)
	})
}
