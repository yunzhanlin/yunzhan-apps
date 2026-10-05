//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type mariaDBDatabaseManifest struct {
	Database core.MariaDBDatabase `json:"database"`
	Password string               `json:"password"`
}

func mariaDBDatabasesDir(instanceID string) string {
	return filepath.Join(mariadbConfig(instanceID), "databases")
}

func mariaDBSQL(ctx context.Context, instance core.MariaDBInstance, query string) (string, error) {
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "mariadb" {
		return "", errors.New("MariaDB 运行环境不存在")
	}
	cmd := exec.CommandContext(ctx, release.Prefix()+"/bin/mariadb", "--no-defaults", "--socket=/run/panel-mariadb-"+instance.ID+"/mariadb.sock", "--user=root", "--batch", "--skip-column-names", "-e", query)
	cmd.Env = mariadbEnv(release)
	out, e := cmd.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("MariaDB SQL 执行失败: %w: %s", e, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func readMariaDBDatabase(instanceID, id string) (mariaDBDatabaseManifest, error) {
	var manifest mariaDBDatabaseManifest
	if !core.ValidID(instanceID) || !core.ValidID(id) {
		return manifest, errors.New("MariaDB 数据库标识无效")
	}
	b, e := os.ReadFile(filepath.Join(mariaDBDatabasesDir(instanceID), id+".json"))
	if e == nil {
		e = json.Unmarshal(b, &manifest)
	}
	if e == nil && (manifest.Database.ID != id || manifest.Database.InstanceID != instanceID || core.ValidateMariaDBDatabase(manifest.Database) != nil || len(manifest.Password) != 64) {
		e = errors.New("MariaDB 数据库清单不匹配")
	}
	return manifest, e
}

func findMariaDBDatabase(id string) (mariaDBDatabaseManifest, core.MariaDBInstance, error) {
	var empty mariaDBDatabaseManifest
	if !core.ValidID(id) {
		return empty, core.MariaDBInstance{}, errors.New("MariaDB 数据库标识无效")
	}
	entries, e := os.ReadDir(mariadbRoot)
	if e != nil {
		return empty, core.MariaDBInstance{}, e
	}
	for _, entry := range entries {
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			continue
		}
		manifest, er := readMariaDBDatabase(entry.Name(), id)
		if er == nil {
			instance, er := readMariaDB(entry.Name())
			return manifest, instance, er
		}
		if !errors.Is(er, os.ErrNotExist) {
			return empty, core.MariaDBInstance{}, er
		}
	}
	return empty, core.MariaDBInstance{}, os.ErrNotExist
}

func listMariaDBDatabases() ([]core.MariaDBDatabase, error) {
	instances, e := os.ReadDir(mariadbRoot)
	if errors.Is(e, os.ErrNotExist) {
		return []core.MariaDBDatabase{}, nil
	}
	if e != nil {
		return nil, e
	}
	out := []core.MariaDBDatabase{}
	for _, instance := range instances {
		if !instance.IsDir() || !core.ValidID(instance.Name()) {
			continue
		}
		entries, er := os.ReadDir(mariaDBDatabasesDir(instance.Name()))
		if errors.Is(er, os.ErrNotExist) {
			continue
		}
		if er != nil {
			return nil, er
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			id := strings.TrimSuffix(entry.Name(), ".json")
			manifest, er := readMariaDBDatabase(instance.Name(), id)
			if er != nil {
				return nil, er
			}
			out = append(out, manifest.Database)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func createMariaDBDatabase(ctx context.Context, instance core.MariaDBInstance, name string) (core.MariaDBDatabase, error) {
	database := core.MariaDBDatabase{ID: core.ID(), InstanceID: instance.ID, Name: name, CreatedAt: core.Now()}
	database.Username = "mdb_" + database.ID[:20]
	if e := core.ValidateMariaDBDatabase(database); e != nil {
		return database, e
	}
	if e := mariadbPing(ctx, instance); e != nil {
		return database, e
	}
	count, e := mariaDBSQL(ctx, instance, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+database.Name+"';")
	if e != nil {
		return database, e
	}
	if count != "0" {
		return database, errors.New("该实例已有同名数据库")
	}
	dir := mariaDBDatabasesDir(instance.ID)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return database, e
	}
	password := core.ID() + core.ID()
	query := "CREATE DATABASE `" + database.Name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" +
		" CREATE USER '" + database.Username + "'@'localhost' IDENTIFIED BY '" + password + "';" +
		" CREATE USER '" + database.Username + "'@'127.0.0.1' IDENTIFIED BY '" + password + "';" +
		" GRANT ALL PRIVILEGES ON `" + database.Name + "`.* TO '" + database.Username + "'@'localhost';" +
		" GRANT ALL PRIVILEGES ON `" + database.Name + "`.* TO '" + database.Username + "'@'127.0.0.1';"
	if _, e = mariaDBSQL(ctx, instance, query); e != nil {
		return database, e
	}
	manifest := mariaDBDatabaseManifest{Database: database, Password: password}
	if e = writeJSON(filepath.Join(dir, database.ID+".json"), manifest); e != nil {
		_, _ = mariaDBSQL(context.Background(), instance, "DROP DATABASE IF EXISTS `"+database.Name+"`; DROP USER IF EXISTS '"+database.Username+"'@'localhost','"+database.Username+"'@'127.0.0.1';")
		return database, e
	}
	return database, nil
}

func deleteMariaDBDatabase(ctx context.Context, id, confirm string) error {
	manifest, instance, e := findMariaDBDatabase(id)
	if e != nil {
		return e
	}
	if manifest.Database.Name != confirm {
		return errors.New("请输入完整数据库名称确认删除")
	}
	if e = mariadbPing(ctx, instance); e != nil {
		return e
	}
	if _, e = mariaDBSQL(ctx, instance, "DROP DATABASE `"+manifest.Database.Name+"`; DROP USER IF EXISTS '"+manifest.Database.Username+"'@'localhost','"+manifest.Database.Username+"'@'127.0.0.1';"); e != nil {
		return e
	}
	return os.Remove(filepath.Join(mariaDBDatabasesDir(instance.ID), id+".json"))
}

func rotateMariaDBCredential(ctx context.Context, id, confirm string) (map[string]any, error) {
	manifest, instance, e := findMariaDBDatabase(id)
	if e != nil {
		return nil, e
	}
	if manifest.Database.Name != confirm {
		return nil, errors.New("请输入完整数据库名称确认重置密码")
	}
	if e = mariadbPing(ctx, instance); e != nil {
		return nil, e
	}
	old := manifest.Password
	next := core.ID() + core.ID()
	alter := func(password string) error {
		_, er := mariaDBSQL(ctx, instance, "ALTER USER '"+manifest.Database.Username+"'@'localhost' IDENTIFIED BY '"+password+"', '"+manifest.Database.Username+"'@'127.0.0.1' IDENTIFIED BY '"+password+"';")
		return er
	}
	if e = alter(next); e != nil {
		return nil, e
	}
	manifest.Password = next
	path := filepath.Join(mariaDBDatabasesDir(instance.ID), id+".json")
	if e = writeJSON(path, manifest); e != nil {
		if rollback := alter(old); rollback != nil {
			return nil, fmt.Errorf("新密码未持久化且旧密码恢复失败: %v", rollback)
		}
		return nil, errors.New("新密码未持久化，已恢复原密码")
	}
	return map[string]any{"host": "127.0.0.1", "port": instance.Port, "database": manifest.Database.Name, "username": manifest.Database.Username, "password": next}, nil
}
