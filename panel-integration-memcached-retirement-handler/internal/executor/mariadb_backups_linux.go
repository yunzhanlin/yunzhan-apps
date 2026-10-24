//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const mariadbBackupsRoot = "/var/backups/panel/mariadb"

func mariaDBBackupDir(instanceID string) string { return filepath.Join(mariadbBackupsRoot, instanceID) }

func validMariaDBBackup(backup core.MariaDBBackup) bool {
	return core.ValidID(backup.ID) && core.ValidID(backup.DatabaseID) && core.ValidID(backup.InstanceID) && core.ValidDatabaseName(backup.DatabaseName) && backup.Bytes >= 0 && len(backup.SHA256) == 64 && backup.CreatedAt != ""
}

func readMariaDBBackup(instanceID, id string) (core.MariaDBBackup, error) {
	var backup core.MariaDBBackup
	if !core.ValidID(instanceID) || !core.ValidID(id) {
		return backup, errors.New("MariaDB 备份标识无效")
	}
	b, e := os.ReadFile(filepath.Join(mariaDBBackupDir(instanceID), id+".json"))
	if e == nil {
		e = json.Unmarshal(b, &backup)
	}
	if e == nil && (!validMariaDBBackup(backup) || backup.ID != id || backup.InstanceID != instanceID) {
		e = errors.New("MariaDB 备份清单不匹配")
	}
	return backup, e
}

func findMariaDBBackup(id string) (core.MariaDBBackup, error) {
	var empty core.MariaDBBackup
	entries, e := os.ReadDir(mariadbBackupsRoot)
	if errors.Is(e, os.ErrNotExist) {
		return empty, os.ErrNotExist
	}
	if e != nil {
		return empty, e
	}
	for _, entry := range entries {
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			continue
		}
		backup, er := readMariaDBBackup(entry.Name(), id)
		if er == nil {
			return backup, nil
		}
		if !errors.Is(er, os.ErrNotExist) {
			return empty, er
		}
	}
	return empty, os.ErrNotExist
}

func listMariaDBBackups() ([]core.MariaDBBackup, error) {
	instances, e := os.ReadDir(mariadbBackupsRoot)
	if errors.Is(e, os.ErrNotExist) {
		return []core.MariaDBBackup{}, nil
	}
	if e != nil {
		return nil, e
	}
	out := []core.MariaDBBackup{}
	for _, instance := range instances {
		if !instance.IsDir() || !core.ValidID(instance.Name()) {
			continue
		}
		entries, er := os.ReadDir(mariaDBBackupDir(instance.Name()))
		if er != nil {
			return nil, er
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			backup, er := readMariaDBBackup(instance.Name(), strings.TrimSuffix(entry.Name(), ".json"))
			if er != nil {
				return nil, er
			}
			out = append(out, backup)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

func dumpMariaDB(ctx context.Context, instance core.MariaDBInstance, database, path string) (int64, string, error) {
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "mariadb" {
		return 0, "", errors.New("MariaDB 运行环境不存在")
	}
	f, e := os.OpenFile(path+".part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return 0, "", e
	}
	defer os.Remove(path + ".part")
	h := sha256.New()
	writer := &limitBackupWriter{w: io.MultiWriter(f, h), remaining: 4 * 1024 * 1024 * 1024}
	cmd := exec.CommandContext(ctx, release.Prefix()+"/bin/mariadb-dump", "--no-defaults", "--socket=/run/panel-mariadb-"+instance.ID+"/mariadb.sock", "--user=root", "--single-transaction", "--routines", "--triggers", "--events", "--hex-blob", database)
	cmd.Env = mariadbEnv(release)
	cmd.Stdout = writer
	var stderr strings.Builder
	cmd.Stderr = &stderr
	e = cmd.Run()
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return 0, "", fmt.Errorf("MariaDB 备份失败: %w: %s", e, strings.TrimSpace(stderr.String()))
	}
	if closeErr != nil {
		return 0, "", closeErr
	}
	if e = os.Rename(path+".part", path); e != nil {
		return 0, "", e
	}
	return 4*1024*1024*1024 - writer.remaining, hex.EncodeToString(h.Sum(nil)), nil
}

func createMariaDBBackupFor(ctx context.Context, manifest mariaDBDatabaseManifest, instance core.MariaDBInstance, requestedID string) (core.MariaDBBackup, error) {
	id := requestedID
	if id == "" {
		id = core.ID()
	}
	backup := core.MariaDBBackup{ID: id, DatabaseID: manifest.Database.ID, InstanceID: instance.ID, DatabaseName: manifest.Database.Name, Version: strings.TrimPrefix(instance.ReleaseID, "mariadb-"), CreatedAt: core.Now()}
	dir := mariaDBBackupDir(instance.ID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return backup, e
	}
	path := filepath.Join(dir, backup.ID+".sql")
	manifestPath := filepath.Join(dir, backup.ID+".json")
	if requestedID != "" {
		if existing, e := readMariaDBBackup(instance.ID, requestedID); e == nil {
			if existing.DatabaseID != manifest.Database.ID || existing.DatabaseName != manifest.Database.Name || existing.Version != strings.TrimPrefix(instance.ReleaseID, "mariadb-") || verifyMariaDBBackup(existing) != nil {
				return backup, errors.New("MariaDB 预留备份身份已被不同产物使用")
			}
			return existing, nil
		}
		_ = os.Remove(path)
		_ = os.Remove(manifestPath)
	}
	var e error
	backup.Bytes, backup.SHA256, e = dumpMariaDB(ctx, instance, backup.DatabaseName, path)
	if e != nil {
		_ = os.Remove(path)
		return backup, e
	}
	if e = writeJSON(manifestPath, backup); e != nil {
		_ = os.Remove(path)
		return backup, e
	}
	return backup, nil
}

func createMariaDBBackup(ctx context.Context, databaseID, requestedID string) (core.MariaDBBackup, error) {
	if requestedID != "" && !core.ValidID(requestedID) {
		return core.MariaDBBackup{}, errors.New("MariaDB 预留备份标识无效")
	}
	manifest, instance, e := findMariaDBDatabase(databaseID)
	if e != nil {
		return core.MariaDBBackup{}, e
	}
	if e = mariadbPing(ctx, instance); e != nil {
		return core.MariaDBBackup{}, e
	}
	return createMariaDBBackupFor(ctx, manifest, instance, requestedID)
}

func verifyMariaDBBackup(backup core.MariaDBBackup) error {
	path := filepath.Join(mariaDBBackupDir(backup.InstanceID), backup.ID+".sql")
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 4*1024*1024*1024+1))
	if e != nil {
		return e
	}
	if n != backup.Bytes || hex.EncodeToString(h.Sum(nil)) != backup.SHA256 {
		return errors.New("MariaDB 备份大小或 SHA-256 不匹配")
	}
	return nil
}

func restoreMariaDBBackup(ctx context.Context, databaseID, backupID, confirm string) (core.MariaDBBackup, error) {
	manifest, instance, e := findMariaDBDatabase(databaseID)
	if e != nil {
		return core.MariaDBBackup{}, e
	}
	if confirm != manifest.Database.Name {
		return core.MariaDBBackup{}, errors.New("请输入完整数据库名称确认恢复")
	}
	backup, e := findMariaDBBackup(backupID)
	if e != nil || backup.DatabaseID != databaseID || backup.InstanceID != instance.ID || backup.DatabaseName != manifest.Database.Name || backup.Version != strings.TrimPrefix(instance.ReleaseID, "mariadb-") {
		return core.MariaDBBackup{}, errors.New("备份不属于当前数据库和精确版本")
	}
	if e = verifyMariaDBBackup(backup); e != nil {
		return core.MariaDBBackup{}, e
	}
	safety, e := createMariaDBBackupFor(ctx, manifest, instance, "")
	if e != nil {
		return safety, errors.New("恢复前安全备份失败，数据库未改变")
	}
	recreate := func(callCtx context.Context) error {
		_, er := mariaDBSQL(callCtx, instance, "DROP DATABASE `"+manifest.Database.Name+"`; CREATE DATABASE `"+manifest.Database.Name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
		return er
	}
	if e = recreate(ctx); e == nil {
		e = importMariaDBDump(ctx, instance, manifest.Database.Name, filepath.Join(mariaDBBackupDir(instance.ID), backup.ID+".sql"))
	}
	if e == nil {
		return safety, nil
	}
	failed := e
	rollback := recreate(context.Background())
	if rollback == nil {
		rollback = importMariaDBDump(context.Background(), instance, manifest.Database.Name, filepath.Join(mariaDBBackupDir(instance.ID), safety.ID+".sql"))
	}
	if rollback == nil {
		return safety, fmt.Errorf("MariaDB 恢复失败，已用恢复前安全备份回滚: %w", failed)
	}
	return safety, fmt.Errorf("MariaDB 恢复失败且安全备份回滚失败: %v；回滚错误: %w", failed, rollback)
}

func deleteMariaDBBackup(id, confirm string) error {
	backup, e := findMariaDBBackup(id)
	if e != nil {
		return e
	}
	if confirm != backup.DatabaseName {
		return errors.New("请输入完整数据库名称确认删除备份")
	}
	for _, ext := range []string{".sql", ".json"} {
		if e = os.Remove(filepath.Join(mariaDBBackupDir(backup.InstanceID), backup.ID+ext)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	return nil
}
