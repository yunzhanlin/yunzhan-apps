package core

import (
	"errors"
	"io"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var mariadbInstanceName = regexp.MustCompile(`^[\p{Han}A-Za-z0-9][\p{Han}A-Za-z0-9_. -]{0,39}$`)

type MariaDBInstance struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ReleaseID   string `json:"release_id"`
	Port        int    `json:"port"`
	MemoryMB    int    `json:"memory_mb"`
	CreatedAt   string `json:"created_at"`
	Status      string `json:"status,omitempty"`
	Connections int    `json:"connections,omitempty"`
	DataBytes   int64  `json:"data_bytes,omitempty"`
}

type MariaDBDatabase struct {
	ID         string `json:"id"`
	InstanceID string `json:"instance_id"`
	Name       string `json:"name"`
	Username   string `json:"username"`
	CreatedAt  string `json:"created_at"`
}

type MariaDBBackup struct {
	ID           string `json:"id"`
	DatabaseID   string `json:"database_id"`
	InstanceID   string `json:"instance_id"`
	DatabaseName string `json:"database_name"`
	Version      string `json:"version"`
	Bytes        int64  `json:"bytes"`
	SHA256       string `json:"sha256"`
	CreatedAt    string `json:"created_at"`
}

type MySQLToMariaDBMigration struct {
	SourceServer     DatabaseServer `json:"source_server"`
	SourceDatabase   Database       `json:"source_database"`
	TargetInstanceID string         `json:"target_instance_id"`
	TargetName       string         `json:"target_name"`
}

type CrossEngineMigrationResult struct {
	Database MariaDBDatabase `json:"database"`
	Rows     int64           `json:"rows"`
	Tables   int             `json:"tables"`
	Source   string          `json:"source"`
	Target   string          `json:"target"`
}

func ValidateMariaDBDatabase(v MariaDBDatabase) error {
	if !ValidID(v.ID) || !ValidID(v.InstanceID) || !ValidDatabaseName(v.Name) || !regexp.MustCompile(`^mdb_[a-f0-9]{20}$`).MatchString(v.Username) || strings.TrimSpace(v.CreatedAt) == "" {
		return errors.New("MariaDB 数据库标识、名称或账号无效")
	}
	return nil
}

func ValidateMariaDBInstance(v MariaDBInstance) error {
	if !ValidID(v.ID) || !mariadbInstanceName.MatchString(v.Name) || v.Port < 13000 || v.Port > 13999 || v.MemoryMB < 128 || v.MemoryMB > 32768 {
		return errors.New("MariaDB 实例名称、端口或内存配置无效")
	}
	r, ok := runtimecatalog.Find(v.ReleaseID)
	if !ok || r.Family != "mariadb" {
		return errors.New("请选择已安装的 MariaDB 版本")
	}
	return nil
}

func (a *Server) mariadbRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/mariadb/databases/{id}/migrations/mysql", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			TargetServerID string `json:"target_server_id"`
			TargetName     string `json:"target_name"`
			ConfirmName    string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		var inventory struct {
			Databases []MariaDBDatabase `json:"databases"`
		}
		var instances struct {
			Instances []MariaDBInstance `json:"instances"`
		}
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/mariadb/databases", nil, &inventory); e != nil {
			fail(w, 503, e.Error())
			return
		}
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/mariadb/instances", nil, &instances); e != nil {
			fail(w, 503, e.Error())
			return
		}
		var source MariaDBDatabase
		for _, item := range inventory.Databases {
			if item.ID == r.PathValue("id") {
				source = item
				break
			}
		}
		var sourceInstance MariaDBInstance
		for _, item := range instances.Instances {
			if item.ID == source.InstanceID {
				sourceInstance = item
				break
			}
		}
		target, e := a.Store.DatabaseServer(in.TargetServerID)
		in.TargetName = strings.TrimSpace(in.TargetName)
		if e != nil || ValidateMariaDBDatabase(source) != nil || ValidateMariaDBInstance(sourceInstance) != nil || source.Name != in.ConfirmName || !ValidDatabaseName(in.TargetName) || target.Status != "running" {
			fail(w, 400, "请选择运行中的 MySQL 目标、有效目标库名并输入完整 MariaDB 源数据库名")
			return
		}
		a.queueDatabase(w, r, u, DatabaseOperation{Action: "migrate_mariadb_database", Server: target, Database: Database{Name: in.TargetName}, SourceMariaDB: &MariaDBMigrationSource{Instance: sourceInstance, Database: source}})
	}))
	m.HandleFunc("POST /api/mariadb/databases/{id}/import", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id, confirm := r.PathValue("id"), r.URL.Query().Get("confirm_name")
		size := r.ContentLength
		if raw := r.URL.Query().Get("bytes"); raw != "" {
			var e error
			size, e = strconv.ParseInt(raw, 10, 64)
			if e != nil || (r.ContentLength > 0 && r.ContentLength != size) {
				fail(w, 400, "MariaDB SQL 导入文件大小不一致")
				return
			}
		}
		if !ValidID(id) || !ValidDatabaseName(confirm) || size < 1 || size > 4*1024*1024*1024 {
			fail(w, 400, "MariaDB SQL 导入参数或文件大小无效")
			return
		}
		deadline := time.Now().Add(30 * time.Minute)
		ctrl := http.NewResponseController(w)
		_ = ctrl.SetReadDeadline(deadline)
		_ = ctrl.SetWriteDeadline(deadline)
		q := url.Values{"confirm_name": {confirm}, "bytes": {strconv.FormatInt(size, 10)}}
		req, e := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://executor/v1/mariadb/databases/"+id+"/import?"+q.Encode(), http.MaxBytesReader(w, r.Body, 4*1024*1024*1024))
		if e != nil {
			fail(w, 500, "无法准备 MariaDB SQL 传输")
			return
		}
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
		client := &http.Client{Transport: a.Executor.Client.Transport, Timeout: 30 * time.Minute}
		response, e := client.Do(req)
		if e != nil {
			fail(w, 502, "MariaDB SQL 上传中断，在线数据库未确认改变")
			return
		}
		defer response.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024))
		if readErr != nil {
			fail(w, 502, "无法读取 MariaDB 导入结果")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(body)
		result := "succeeded"
		if response.StatusCode >= 400 {
			result = "failed"
		}
		_ = a.Store.Audit(u.Username, "mariadb.database.import", id, result)
	}))
	m.HandleFunc("GET /api/mariadb/backups/{id}/download", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		if !ValidID(id) {
			fail(w, 400, "MariaDB 备份标识无效")
			return
		}
		var list struct {
			Backups []MariaDBBackup `json:"backups"`
		}
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/mariadb/backups", nil, &list); e != nil {
			fail(w, 503, e.Error())
			return
		}
		var backup *MariaDBBackup
		for i := range list.Backups {
			if list.Backups[i].ID == id {
				backup = &list.Backups[i]
				break
			}
		}
		if backup == nil {
			fail(w, 404, "MariaDB 备份不存在")
			return
		}
		values := url.Values{"database_id": {backup.DatabaseID}, "database_name": {backup.DatabaseName}, "sha256": {backup.SHA256}, "bytes": {strconv.FormatInt(backup.Bytes, 10)}, "version": {backup.Version}}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
		sent, e := a.proxyStream(w, r, "/v1/mariadb/backups/"+backup.InstanceID+"/"+backup.ID+"/download?"+values.Encode(), 30*time.Minute)
		result := "succeeded"
		if e != nil {
			result = "failed"
			if !sent {
				fail(w, 502, e.Error())
			}
		}
		_ = a.Store.Audit(u.Username, "mariadb.backup.download", id, result)
	}))
	m.HandleFunc("GET /api/mariadb/backups", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/mariadb/backups", nil, &out); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/mariadb/databases/{id}/backup", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !ValidID(r.PathValue("id")) {
			fail(w, 400, "MariaDB 数据库标识无效")
			return
		}
		var out MariaDBBackup
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/mariadb/databases/"+r.PathValue("id")+"/backup", map[string]any{}, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.database.backup", r.PathValue("id"), "succeeded")
		send(w, 201, out)
	}))
	m.HandleFunc("POST /api/mariadb/databases/{id}/restore", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			BackupID    string `json:"backup_id"`
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) || !ValidID(r.PathValue("id")) || !ValidID(in.BackupID) || !ValidDatabaseName(in.ConfirmName) {
			fail(w, 400, "MariaDB 恢复参数无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/mariadb/databases/"+r.PathValue("id")+"/restore", in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.database.restore", r.PathValue("id"), "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/mariadb/backups/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) || !ValidID(r.PathValue("id")) || !ValidDatabaseName(in.ConfirmName) {
			fail(w, 400, "MariaDB 备份删除确认无效")
			return
		}
		var activePlans int
		if e := a.Store.DB.QueryRow(`SELECT count(*) FROM schedule_artifacts sa JOIN schedules s ON s.id=sa.schedule_id WHERE sa.artifact_id=? AND sa.kind='mariadb_backup' AND s.deleted_at=0`, r.PathValue("id")).Scan(&activePlans); e != nil {
			fail(w, 500, "无法核对 MariaDB 备份计划引用")
			return
		}
		if activePlans > 0 {
			fail(w, 409, "该备份由计划任务管理，请先删除计划或由保留策略清理")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/mariadb/backups/"+r.PathValue("id"), in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		tx, e := a.Store.DB.Begin()
		if e != nil {
			fail(w, 500, "MariaDB 备份文件已删除，但控制记录待核对")
			return
		}
		defer tx.Rollback()
		_, e = tx.Exec(`DELETE FROM schedule_artifacts WHERE artifact_id=? AND kind='mariadb_backup'`, r.PathValue("id"))
		if e == nil {
			_, e = tx.Exec(`DELETE FROM mariadb_schedule_cleanup_jobs WHERE artifact_id=?`, r.PathValue("id"))
		}
		if e == nil {
			_, e = tx.Exec(`DELETE FROM mariadb_schedule_backups WHERE id=?`, r.PathValue("id"))
		}
		if e != nil || tx.Commit() != nil {
			fail(w, 500, "MariaDB 备份文件已删除，但控制记录待核对")
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.backup.delete", r.PathValue("id"), "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/mariadb/instances/{id}/migrations/mysql", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			SourceDatabaseID string `json:"source_database_id"`
			TargetName       string `json:"target_name"`
			ConfirmName      string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		database, e := a.Store.Database(in.SourceDatabaseID)
		if e != nil || database.Status != "ready" {
			fail(w, 404, "可迁移的 MySQL 源数据库不存在")
			return
		}
		server, e := a.Store.DatabaseServer(database.ServerID)
		if e != nil {
			fail(w, 404, "MySQL 源实例不存在")
			return
		}
		in.TargetName = strings.TrimSpace(in.TargetName)
		if !ValidID(r.PathValue("id")) || !ValidDatabaseName(in.TargetName) || in.ConfirmName != database.Name {
			fail(w, 400, "请选择目标实例、有效目标库名并输入完整源数据库名确认")
			return
		}
		request := MySQLToMariaDBMigration{SourceServer: server, SourceDatabase: database, TargetInstanceID: r.PathValue("id"), TargetName: in.TargetName}
		var out CrossEngineMigrationResult
		if e = a.Executor.Call(r.Context(), http.MethodPost, "/v1/mariadb/migrations/mysql", request, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "database.migrate.mysql_to_mariadb", database.ID, "succeeded")
		send(w, 201, out)
	}))
	m.HandleFunc("GET /api/mariadb/databases", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/mariadb/databases", nil, &out); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/mariadb/instances/{id}/databases", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &in) {
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		if !ValidID(r.PathValue("id")) || !ValidDatabaseName(in.Name) {
			fail(w, 400, "数据库名需为小写字母开头的 1–32 位字母、数字、下划线")
			return
		}
		var out MariaDBDatabase
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/mariadb/instances/"+r.PathValue("id")+"/databases", in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.database.create", out.ID, "succeeded")
		send(w, 201, out)
	}))
	m.HandleFunc("POST /api/mariadb/databases/{id}/credentials", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !ValidID(r.PathValue("id")) {
			fail(w, 400, "MariaDB 数据库标识无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/mariadb/databases/"+r.PathValue("id")+"/credentials", map[string]any{}, &out); e != nil {
			fail(w, 404, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.database.credentials", r.PathValue("id"), "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/mariadb/databases/{id}/credentials/rotate", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) || !ValidID(r.PathValue("id")) || !ValidDatabaseName(in.ConfirmName) {
			fail(w, 400, "MariaDB 密码重置确认无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/mariadb/databases/"+r.PathValue("id")+"/credentials/rotate", in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.database.credentials.rotate", r.PathValue("id"), "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/mariadb/databases/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) || !ValidID(r.PathValue("id")) || !ValidDatabaseName(in.ConfirmName) {
			fail(w, 400, "MariaDB 数据库删除确认无效")
			return
		}
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/mariadb/databases/"+r.PathValue("id"), in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.database.delete", r.PathValue("id"), "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/mariadb/instances", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var out any
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/mariadb/instances", nil, &out); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/mariadb/instances", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in MariaDBInstance
		if !decode(w, r, &in) {
			return
		}
		in.ID = ID()
		in.CreatedAt = Now()
		if e := ValidateMariaDBInstance(in); e != nil {
			fail(w, 400, e.Error())
			return
		}
		var out MariaDBInstance
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/mariadb/instances", in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.instance.create", in.Name, "succeeded")
		send(w, 201, out)
	}))
	m.HandleFunc("POST /api/mariadb/instances/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id, action := r.PathValue("id"), r.PathValue("action")
		if !ValidID(id) || (action != "start" && action != "stop" && action != "restart") {
			fail(w, 400, "MariaDB 实例操作无效")
			return
		}
		var out MariaDBInstance
		if e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/mariadb/instances/"+id+"/"+action, map[string]any{}, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.instance."+action, id, "succeeded")
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/mariadb/instances/{id}/logs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !ValidID(r.PathValue("id")) {
			fail(w, 400, "MariaDB 实例标识无效")
			return
		}
		var out map[string]string
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/mariadb/instances/"+r.PathValue("id")+"/logs", nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("DELETE /api/mariadb/instances/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) || !mariadbInstanceName.MatchString(in.ConfirmName) {
			fail(w, 400, "MariaDB 删除确认无效")
			return
		}
		var out map[string]bool
		if e := a.Executor.Call(r.Context(), http.MethodDelete, "/v1/mariadb/instances/"+id, in, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "mariadb.instance.delete", in.ConfirmName, "succeeded")
		send(w, 200, out)
	}))
}
