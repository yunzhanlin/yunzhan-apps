package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/runtimecatalog"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type DatabaseServer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ReleaseID string `json:"release_id"`
	Port      int    `json:"port"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}
type Database struct {
	Revision  int64  `json:"revision,omitempty"`
	LastJobID string `json:"last_job_id,omitempty"`
	ID        string `json:"id"`
	ServerID  string `json:"server_id"`
	Name      string `json:"name"`
	Username  string `json:"username"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}
type DatabaseBackup struct {
	ID         string `json:"id"`
	DatabaseID string `json:"database_id"`
	ServerID   string `json:"server_id"`
	Version    string `json:"version"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	CreatedAt  string `json:"created_at"`
}
type DatabaseOperation struct {
	PreviousDatabase *Database               `json:"previous_database,omitempty"`
	Account          *DatabaseAccount        `json:"account,omitempty"`
	PreviousAccount  *DatabaseAccount        `json:"previous_account,omitempty"`
	Import           *DatabaseImport         `json:"import,omitempty"`
	TargetServer     DatabaseServer          `json:"target_server"`
	TargetDatabase   Database                `json:"target_database"`
	SourceMariaDB    *MariaDBMigrationSource `json:"source_mariadb,omitempty"`
	JobID            string                  `json:"job_id"`
	Action           string                  `json:"action"`
	Server           DatabaseServer          `json:"server"`
	Database         Database                `json:"database"`
	Backup           DatabaseBackup          `json:"backup"`
}

type MariaDBMigrationSource struct {
	Instance MariaDBInstance `json:"instance"`
	Database MariaDBDatabase `json:"database"`
}
type DatabaseResult struct {
	DatabaseStatus string         `json:"database_status,omitempty"`
	State          string         `json:"state"`
	Error          string         `json:"error"`
	Steps          []Step         `json:"steps"`
	ServerStatus   string         `json:"server_status"`
	Backup         DatabaseBackup `json:"backup"`
}

var databaseName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func ValidDatabaseName(s string) bool { return databaseName.MatchString(s) }
func ValidDatabaseServer(s DatabaseServer) bool {
	r, ok := runtimecatalog.Find(s.ReleaseID)
	return ValidID(s.ID) && len([]rune(s.Name)) >= 1 && len([]rune(s.Name)) <= 40 && ok && r.Family == "mysql" && s.Port >= 13306 && s.Port <= 13999
}
func (s *Store) migrateDatabases() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS mysql_servers(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,release_id TEXT NOT NULL REFERENCES runtime_installations(id),port INTEGER NOT NULL UNIQUE,status TEXT NOT NULL,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS mysql_databases(id TEXT PRIMARY KEY,server_id TEXT NOT NULL REFERENCES mysql_servers(id),name TEXT NOT NULL,username TEXT NOT NULL UNIQUE,status TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(server_id,name));
 CREATE TABLE IF NOT EXISTS mysql_backups(id TEXT PRIMARY KEY,database_id TEXT NOT NULL REFERENCES mysql_databases(id),server_id TEXT NOT NULL REFERENCES mysql_servers(id),version TEXT NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS mysql_jobs(id TEXT PRIMARY KEY,target_id TEXT NOT NULL REFERENCES mysql_servers(id),kind TEXT NOT NULL,state TEXT NOT NULL,payload TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',steps TEXT NOT NULL DEFAULT '[]',idempotency_key TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
 CREATE UNIQUE INDEX IF NOT EXISTS one_active_mysql_job ON mysql_jobs(target_id) WHERE state IN ('queued','running');
 INSERT OR IGNORE INTO schema_migrations VALUES(3,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}
func (s *Store) DatabaseServers() ([]DatabaseServer, error) {
	rows, e := s.DB.Query(`SELECT id,name,release_id,port,status,created_at FROM mysql_servers ORDER BY created_at,id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []DatabaseServer{}
	for rows.Next() {
		var x DatabaseServer
		if e = rows.Scan(&x.ID, &x.Name, &x.ReleaseID, &x.Port, &x.Status, &x.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) DatabaseServer(id string) (DatabaseServer, error) {
	var x DatabaseServer
	e := s.DB.QueryRow(`SELECT id,name,release_id,port,status,created_at FROM mysql_servers WHERE id=?`, id).Scan(&x.ID, &x.Name, &x.ReleaseID, &x.Port, &x.Status, &x.CreatedAt)
	return x, e
}
func (s *Store) Databases() ([]Database, error) {
	rows, e := s.DB.Query(databaseLifecycleSelect + ` ORDER BY d.created_at,d.id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Database{}
	for rows.Next() {
		x, e := scanLifecycleDatabase(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) Database(id string) (Database, error) {
	return scanLifecycleDatabase(s.DB.QueryRow(databaseLifecycleSelect+` WHERE d.id=?`, id))
}
func (s *Store) DatabaseBackups() ([]DatabaseBackup, error) {
	rows, e := s.DB.Query(`SELECT id,database_id,server_id,version,bytes,sha256,created_at FROM mysql_backups ORDER BY created_at DESC,id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []DatabaseBackup{}
	for rows.Next() {
		var x DatabaseBackup
		if e = rows.Scan(&x.ID, &x.DatabaseID, &x.ServerID, &x.Version, &x.Bytes, &x.SHA256, &x.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) DatabaseBackupJobs() ([]Job, error) {
	rows, err := s.DB.Query(`SELECT j.id,j.target_id,s.name,j.kind,j.state,j.error,j.created_at,j.updated_at,j.steps,j.payload,b.bytes
 FROM mysql_jobs j JOIN mysql_servers s ON s.id=j.target_id
 LEFT JOIN mysql_backups b ON b.id=CASE WHEN json_valid(j.payload) THEN json_extract(j.payload,'$.backup.id') ELSE NULL END
 WHERE j.kind='backup_database' ORDER BY j.created_at DESC,j.id DESC LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var job Job
		var steps string
		var bytes sql.NullInt64
		if err = rows.Scan(&job.ID, &job.TargetID, &job.SiteName, &job.Kind, &job.State, &job.Error, &job.CreatedAt, &job.UpdatedAt, &steps, &job.Payload, &bytes); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(steps), &job.Steps)
		addDatabaseJobSummary(&job)
		if job.State == "succeeded" && bytes.Valid && bytes.Int64 >= 0 {
			value := bytes.Int64
			job.BackupBytes = &value
		}
		out = append(out, job)
	}
	return out, rows.Err()
}
func (s *Store) QueueDatabase(op DatabaseOperation, key, actor string) (string, error) {
	if key == "" || len(key) > 128 {
		return "", errors.New("请提供有效幂等键")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var id, raw string
	e = tx.QueryRow(`SELECT id,payload FROM mysql_jobs WHERE idempotency_key=?`, key).Scan(&id, &raw)
	if e == nil {
		var old DatabaseOperation
		_ = json.Unmarshal([]byte(raw), &old)
		same := old.Action == op.Action && old.Server.ID == op.Server.ID && old.Database.ID == op.Database.ID && old.Backup.ID == op.Backup.ID && old.TargetServer.ID == op.TargetServer.ID
		if accountAction(op.Action) {
			same = sameAccountRequest(old, op)
		}
		if databaseLifecycleAction(op.Action) {
			same = same && old.PreviousDatabase != nil && old.PreviousDatabase.Revision == op.Database.Revision
		}
		if op.Action == "create_instance" {
			same = old.Action == op.Action && old.Server.Name == op.Server.Name && old.Server.ReleaseID == op.Server.ReleaseID && old.Server.Port == op.Server.Port
		}
		if op.Action == "import_database" {
			same = old.Action == op.Action && old.Import != nil && op.Import != nil && old.Import.ID == op.Import.ID
		}
		if op.Action == "overwrite_database" {
			same = same && old.Import != nil && op.Import != nil && SameDatabaseImportIdentity(*old.Import, *op.Import) && old.PreviousDatabase != nil && old.PreviousDatabase.Revision == op.Database.Revision
		}
		if op.Action == "create_database" {
			same = old.Action == op.Action && old.Server.ID == op.Server.ID && old.Database.Name == op.Database.Name
		}
		if op.Action == "migrate_mariadb_database" {
			same = old.Action == op.Action && old.Server.ID == op.Server.ID && old.Database.Name == op.Database.Name && old.SourceMariaDB != nil && op.SourceMariaDB != nil && old.SourceMariaDB.Database.ID == op.SourceMariaDB.Database.ID
		}
		if !same {
			return "", errors.New("幂等键已用于其他请求")
		}
		return id, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	if op.Action == "create_instance" {
		op.Server.ID = ID()
		op.Server.Name = strings.TrimSpace(op.Server.Name)
		op.Server.Status = "creating"
		op.Server.CreatedAt = Now()
		if !ValidDatabaseServer(op.Server) {
			return "", errors.New("请选择已安装 MySQL，实例名称 1–40 字，端口 13306–13999")
		}
		_, e = tx.Exec(`INSERT INTO mysql_servers VALUES(?,?,?,?,?,?)`, op.Server.ID, op.Server.Name, op.Server.ReleaseID, op.Server.Port, op.Server.Status, op.Server.CreatedAt)
		if e != nil {
			return "", errors.New("实例名称或端口已占用，或目标版本未安装")
		}
	} else if !ValidDatabaseServer(op.Server) {
		return "", errors.New("实例不存在或参数无效")
	}
	lockIDs := []string{op.Server.ID}
	if op.TargetServer.ID != "" {
		lockIDs = append(lockIDs, op.TargetServer.ID)
	}
	for _, lockID := range lockIDs {
		var n int
		if e = tx.QueryRow(`SELECT count(*) FROM mysql_jobs WHERE state IN ('queued','running') AND (target_id=? OR json_extract(payload,'$.target_server.id')=?)`, lockID, lockID).Scan(&n); e != nil {
			return "", e
		}
		if n > 0 {
			return "", errors.New("源或目标实例已有进行中的任务")
		}
	}
	switch op.Action {
	case "overwrite_database":
		if e = queueDatabaseOverwrite(tx, &op); e != nil {
			return "", e
		}
	case "quarantine_database", "recover_database":
		if e = queueDatabaseLifecycle(tx, &op); e != nil {
			return "", e
		}
	case "create_account", "update_account", "rotate_account", "enable_account", "disable_account", "quarantine_account", "restore_account":
		if e = queueDatabaseAccount(tx, &op); e != nil {
			return "", e
		}
	case "migrate_database":
		if !ValidDatabaseServer(op.TargetServer) || op.TargetServer.ID == op.Server.ID || op.Server.ReleaseID != "mysql-8.0.46" || op.TargetServer.ReleaseID != "mysql-8.4.11" || !ValidID(op.Database.ID) || op.Database.ServerID != op.Server.ID || !ValidDatabaseName(op.Database.Name) {
			return "", errors.New("当前迁移支持 MySQL 8.0 到独立 8.4 实例，请选择有效的源数据库")
		}
		op.TargetDatabase = Database{ID: ID(), ServerID: op.TargetServer.ID, Name: op.Database.Name, Status: "migrating", CreatedAt: Now()}
		op.TargetDatabase.Username = "db_" + op.TargetDatabase.ID[:20]
		_, e = tx.Exec(`INSERT INTO mysql_databases VALUES(?,?,?,?,?,?)`, op.TargetDatabase.ID, op.TargetDatabase.ServerID, op.TargetDatabase.Name, op.TargetDatabase.Username, op.TargetDatabase.Status, op.TargetDatabase.CreatedAt)
		if e != nil {
			return "", errors.New("目标实例已有同名数据库，请选择空目标")
		}
	case "migrate_mariadb_database":
		if op.SourceMariaDB == nil || ValidateMariaDBInstance(op.SourceMariaDB.Instance) != nil || ValidateMariaDBDatabase(op.SourceMariaDB.Database) != nil || op.SourceMariaDB.Database.InstanceID != op.SourceMariaDB.Instance.ID || !ValidDatabaseName(op.Database.Name) {
			return "", errors.New("MariaDB 源数据库或 MySQL 目标参数无效")
		}
		op.Database = Database{ID: ID(), ServerID: op.Server.ID, Name: op.Database.Name, Status: "migrating", CreatedAt: Now()}
		op.Database.Username = "db_" + op.Database.ID[:20]
		_, e = tx.Exec(`INSERT INTO mysql_databases VALUES(?,?,?,?,?,?)`, op.Database.ID, op.Database.ServerID, op.Database.Name, op.Database.Username, op.Database.Status, op.Database.CreatedAt)
		if e != nil {
			return "", errors.New("MySQL 目标实例已有同名数据库，请选择空目标")
		}
	case "create_instance", "start_instance", "stop_instance", "restart_instance":
	case "create_database", "import_database":
		if op.Action == "import_database" {
			if op.Import == nil || op.Import.TargetDatabaseID != "" || !ValidDatabaseImport(*op.Import, true) || op.Import.ServerID != op.Server.ID || op.Import.Name != op.Database.Name {
				return "", errors.New("导入文件与目标不匹配")
			}
			var state, sha string
			if e = tx.QueryRow(`SELECT state,sha256 FROM mysql_imports WHERE id=?`, op.Import.ID).Scan(&state, &sha); e != nil {
				return "", e
			}
			if state != "staged" || sha != op.Import.SHA256 {
				return "", errors.New("导入文件尚未上传或已用于其他任务")
			}
		}
		if !ValidDatabaseName(op.Database.Name) {
			return "", errors.New("数据库名需为小写字母开头的 1–32 位字母、数字、下划线")
		}
		op.Database.ID = ID()
		op.Database.ServerID = op.Server.ID
		op.Database.Username = "db_" + op.Database.ID[:20]
		op.Database.Status = "creating"
		if op.Action == "import_database" {
			op.Database.Status = "importing"
		}
		op.Database.CreatedAt = Now()
		_, e = tx.Exec(`INSERT INTO mysql_databases VALUES(?,?,?,?,?,?)`, op.Database.ID, op.Database.ServerID, op.Database.Name, op.Database.Username, op.Database.Status, op.Database.CreatedAt)
		if e != nil {
			return "", errors.New("该实例已有同名数据库")
		}
	case "backup_database":
		op.Backup = DatabaseBackup{ID: ID(), DatabaseID: op.Database.ID, ServerID: op.Server.ID, CreatedAt: Now()}
	case "restore_database":
		if !ValidID(op.Backup.ID) || op.Backup.DatabaseID != op.Database.ID || op.Backup.ServerID != op.Server.ID {
			return "", errors.New("备份不属于该数据库")
		}
	default:
		return "", errors.New("操作不在允许范围")
	}
	if (op.Action == "backup_database" || op.Action == "restore_database") && (!ValidID(op.Database.ID) || op.Database.ServerID != op.Server.ID) {
		return "", errors.New("数据库不属于该实例")
	}
	op.JobID = ID()
	if databaseLifecycleAction(op.Action) || op.Action == "overwrite_database" {
		op.Database.LastJobID = op.JobID
	}
	if op.Action == "import_database" || op.Action == "overwrite_database" {
		if _, e = tx.Exec(`UPDATE mysql_imports SET state='queued',job_id=? WHERE id=?`, op.JobID, op.Import.ID); e != nil {
			return "", e
		}
	}
	b, _ := json.Marshal(op)
	_, e = tx.Exec(`INSERT INTO mysql_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,?,?,'queued',?,?,?,?)`, op.JobID, op.Server.ID, op.Action, string(b), key, Now(), Now())
	if e != nil {
		return "", errors.New("该实例已有进行中的任务")
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,'queued',?)`, actor, "mysql."+op.Action, op.Server.Name, Now())
	if e != nil {
		return "", e
	}
	return op.JobID, tx.Commit()
}
func (s *Store) FinishDatabase(op DatabaseOperation, result DatabaseResult) error {
	b, _ := json.Marshal(result.Steps)
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if op.Action == "overwrite_database" {
		var state string
		if e = tx.QueryRow(`SELECT state FROM mysql_jobs WHERE id=?`, op.JobID).Scan(&state); e != nil {
			return e
		}
		if state == "succeeded" {
			return nil
		}
		// Failed/restored operations do not advance the database revision. A later
		// overwrite can therefore have the same original revision. Only the latest
		// database-changing task may close its maintenance state; an older recovery
		// result must not publish readiness for the later operation.
		var latest string
		if e = tx.QueryRow(`SELECT id FROM mysql_jobs WHERE json_extract(payload,'$.database.id')=? AND kind!='backup_database' ORDER BY rowid DESC LIMIT 1`, op.Database.ID).Scan(&latest); e != nil {
			return e
		}
		if latest != op.JobID {
			return nil
		}
		if state == "failed" {
			d, e := scanLifecycleDatabase(tx.QueryRow(databaseLifecycleSelect+` WHERE d.id=?`, op.Database.ID))
			if e != nil || op.PreviousDatabase == nil || d.Revision != op.PreviousDatabase.Revision || d.Status != "needs_attention" || result.DatabaseStatus != "ready" {
				return nil
			}
		}
	}
	// A released import has already been delivered by both journals. A delayed
	// completion must not overwrite later database lifecycle state or its audit.
	if op.Action == "import_database" && op.Import != nil {
		var released int
		if e = tx.QueryRow(`SELECT count(*) FROM mysql_imports WHERE id=? AND job_id=? AND state='released'`, op.Import.ID, op.JobID).Scan(&released); e != nil {
			return e
		}
		if released != 0 {
			return nil
		}
	}
	_, e = tx.Exec(`UPDATE mysql_jobs SET state=?,error=?,steps=?,updated_at=? WHERE id=?`, result.State, result.Error, string(b), Now(), op.JobID)
	if e != nil {
		return e
	}
	if result.State == "succeeded" {
		if result.ServerStatus != "" {
			_, e = tx.Exec(`UPDATE mysql_servers SET status=? WHERE id=?`, result.ServerStatus, op.Server.ID)
			if e != nil {
				return e
			}
		}
		if op.Action == "create_instance" {
			id := op.Server.ID
			_, e = tx.Exec(`INSERT INTO runtime_instances(id,installation_id,family,name,service_name,socket_path,data_dir,config_path) VALUES(?,?,'mysql',?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, id, op.Server.ReleaseID, op.Server.Name, "panel-mysql@"+id+".service", "/run/panel-mysql-"+id+"/mysql.sock", "/srv/panel/mysql/"+id+"/data", "/etc/panel/mysql/"+id+"/my.cnf")
			if e != nil {
				return e
			}
			_, e = tx.Exec(`INSERT INTO database_instances VALUES(?,'mysql',?) ON CONFLICT(id) DO NOTHING`, id, "mysql/"+id+"/root.cnf")
			if e != nil {
				return e
			}
		}
		if op.Action == "migrate_database" {
			_, e = tx.Exec(`UPDATE mysql_databases SET status='ready' WHERE id=?`, op.TargetDatabase.ID)
			if e != nil {
				return e
			}
		}
		if op.Action == "create_database" || op.Action == "import_database" || op.Action == "migrate_mariadb_database" {
			_, e = tx.Exec(`UPDATE mysql_databases SET status='ready' WHERE id=?`, op.Database.ID)
			if e != nil {
				return e
			}
		}
	} else if op.Action == "create_instance" {
		_, e = tx.Exec(`UPDATE mysql_servers SET status='needs_attention' WHERE id=?`, op.Server.ID)
	} else if op.Action == "migrate_database" {
		_, e = tx.Exec(`UPDATE mysql_databases SET status='needs_attention' WHERE id=?`, op.TargetDatabase.ID)
	} else if op.Action == "create_database" || op.Action == "import_database" || op.Action == "migrate_mariadb_database" {
		_, e = tx.Exec(`UPDATE mysql_databases SET status='needs_attention' WHERE id=?`, op.Database.ID)
	}
	if e != nil {
		return e
	}
	if (op.Action == "import_database" || op.Action == "overwrite_database") && op.Import != nil {
		if _, e = tx.Exec(`UPDATE mysql_imports SET state=? WHERE id=? AND job_id=? AND state!='released'`, result.State, op.Import.ID, op.JobID); e != nil {
			return e
		}
	}
	if op.Action == "overwrite_database" {
		if e = finishDatabaseOverwrite(tx, op, result); e != nil {
			return e
		}
	}
	if accountAction(op.Action) {
		if e = finishDatabaseAccount(tx, op, result); e != nil {
			return e
		}
	}
	if databaseLifecycleAction(op.Action) {
		if e = finishDatabaseLifecycle(tx, op, result); e != nil {
			return e
		}
	}
	if x := result.Backup; ValidID(x.ID) && x.Bytes > 0 && len(x.SHA256) == 64 && x.ServerID == op.Server.ID && x.DatabaseID == op.Database.ID {
		_, e = tx.Exec(`INSERT INTO mysql_backups VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, x.ID, x.DatabaseID, x.ServerID, x.Version, x.Bytes, x.SHA256, x.CreatedAt)
		if e != nil {
			return e
		}
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('executor',?,?,?,?)`, "mysql."+op.Action, op.Server.Name, result.State, Now())
	if e != nil {
		return e
	}
	return tx.Commit()
}
func RunDatabaseWorker(ctx context.Context, s *Store, ex *ExecutorClient) {
	go RunDatabaseOverwriteReconciler(ctx, s, ex)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		var raw, id string
		if e := s.DB.QueryRow(`SELECT id,payload FROM mysql_jobs WHERE state='queued' ORDER BY created_at,rowid LIMIT 1`).Scan(&id, &raw); e != nil {
			continue
		}
		var op DatabaseOperation
		if e := json.Unmarshal([]byte(raw), &op); e != nil {
			continue
		}
		r, e := s.DB.Exec(`UPDATE mysql_jobs SET state='running',updated_at=? WHERE id=? AND state='queued'`, Now(), id)
		if e != nil {
			continue
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			continue
		}
		result := DatabaseResult{}
		e = ex.Call(ctx, "POST", "/v1/databases/jobs", op, &result)
		for e == nil && result.State != "succeeded" && result.State != "failed" {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			e = ex.Call(ctx, "GET", "/v1/databases/jobs/"+id, nil, &result)
			steps, _ := json.Marshal(result.Steps)
			_, _ = s.DB.Exec(`UPDATE mysql_jobs SET steps=?,updated_at=? WHERE id=?`, string(steps), Now(), id)
		}
		if ctx.Err() != nil {
			return
		}
		if e != nil {
			result.State = "failed"
			result.Error = e.Error()
		}
		if err := s.FinishDatabase(op, result); err != nil {
			log.Printf("persist database job %s: %v", op.JobID, err)
		}
	}
}
func (a *Server) databaseRoutes(m *http.ServeMux) {
	a.databaseDownloadRoutes(m)
	a.databaseImportRoutes(m)
	a.databaseAccountRoutes(m)
	a.databaseLifecycleRoutes(m)
	m.HandleFunc("GET /api/databases/backup-jobs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		jobs, err := a.Store.DatabaseBackupJobs()
		if err != nil {
			fail(w, 500, "读取数据库备份任务失败")
			return
		}
		send(w, 200, jobs)
	}))
	m.HandleFunc("GET /api/databases", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		servers, e := a.Store.DatabaseServers()
		if e != nil {
			fail(w, 500, "读取实例失败")
			return
		}
		dbs, e := a.Store.Databases()
		if e != nil {
			fail(w, 500, "读取数据库失败")
			return
		}
		backups, e := a.Store.DatabaseBackups()
		if e != nil {
			fail(w, 500, "读取备份失败")
			return
		}
		var actual map[string]any
		if e = a.Executor.Call(r.Context(), "GET", "/v1/databases", nil, &actual); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, map[string]any{"servers": servers, "databases": dbs, "backups": backups, "actual": actual})
	}))
	m.HandleFunc("POST /api/databases/instances", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Name      string `json:"name"`
			ReleaseID string `json:"release_id"`
			Port      int    `json:"port"`
		}
		if !decode(w, r, &in) {
			return
		}
		op := DatabaseOperation{Action: "create_instance", Server: DatabaseServer{Name: strings.TrimSpace(in.Name), ReleaseID: in.ReleaseID, Port: in.Port}}
		a.queueDatabase(w, r, u, op)
	}))
	m.HandleFunc("POST /api/databases/instances/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		server, e := a.Store.DatabaseServer(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "实例不存在")
			return
		}
		action := r.PathValue("action")
		op := DatabaseOperation{Server: server}
		if action == "databases" {
			var in struct {
				Name string `json:"name"`
			}
			if !decode(w, r, &in) {
				return
			}
			op.Action = "create_database"
			op.Database.Name = in.Name
		} else {
			if action != "start" && action != "stop" && action != "restart" {
				fail(w, 404, "操作不存在")
				return
			}
			op.Action = action + "_instance"
		}
		a.queueDatabase(w, r, u, op)
	}))
	m.HandleFunc("POST /api/databases/items/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		db, e := a.Store.Database(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "数据库不存在")
			return
		}
		server, e := a.Store.DatabaseServer(db.ServerID)
		if e != nil {
			fail(w, 404, "实例不存在")
			return
		}
		if db.Status != "ready" {
			fail(w, 409, "数据库尚未交付，请先完成创建、迁移或导入任务")
			return
		}
		op := DatabaseOperation{Server: server, Database: db}
		switch r.PathValue("action") {
		case "backup":
			op.Action = "backup_database"
		case "restore":
			var in struct {
				BackupID    string `json:"backup_id"`
				ConfirmName string `json:"confirm_name"`
			}
			if !decode(w, r, &in) {
				return
			}
			if in.ConfirmName != db.Name {
				fail(w, 400, "请输入数据库名称确认恢复")
				return
			}
			xs, e := a.Store.DatabaseBackups()
			if e != nil {
				fail(w, 500, "读取备份失败")
				return
			}
			for _, x := range xs {
				if x.ID == in.BackupID {
					op.Backup = x
				}
			}
			op.Action = "restore_database"
		case "migrate":
			var in struct {
				TargetID    string `json:"target_id"`
				ConfirmName string `json:"confirm_name"`
			}
			if !decode(w, r, &in) {
				return
			}
			if in.ConfirmName != db.Name {
				fail(w, 400, "请输入源数据库名称确认迁移")
				return
			}
			target, e := a.Store.DatabaseServer(in.TargetID)
			if e != nil {
				fail(w, 404, "目标实例不存在")
				return
			}
			op.Action = "migrate_database"
			op.TargetServer = target
		case "credentials":
			var out map[string]string
			if e = a.Executor.Call(r.Context(), "POST", "/v1/databases/credentials", map[string]string{"server_id": server.ID, "database_id": db.ID}, &out); e != nil {
				fail(w, 503, e.Error())
				return
			}
			_ = a.Store.Audit(u.Username, "mysql.credentials.read", db.ID, "success")
			send(w, 200, out)
			return
		default:
			fail(w, 404, "操作不存在")
			return
		}
		a.queueDatabase(w, r, u, op)
	}))
}
func (a *Server) queueDatabase(w http.ResponseWriter, r *http.Request, u identity, op DatabaseOperation) {
	id, e := a.Store.QueueDatabase(op, r.Header.Get("Idempotency-Key"), u.Username)
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	send(w, 202, map[string]string{"job_id": id})
}
func (s *Store) RetryDatabase(id, actor string) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var raw, state string
	if e = tx.QueryRow(`SELECT payload,state FROM mysql_jobs WHERE id=?`, id).Scan(&raw, &state); e != nil {
		return fmt.Errorf("数据库任务不存在")
	}
	if state != "failed" && state != "needs_attention" {
		return fmt.Errorf("数据库任务不能重试")
	}
	var op DatabaseOperation
	if e = json.Unmarshal([]byte(raw), &op); e != nil {
		return e
	}
	if op.Action == "overwrite_database" {
		d, e := scanLifecycleDatabase(tx.QueryRow(databaseLifecycleSelect+` WHERE d.id=?`, op.Database.ID))
		if e != nil || op.PreviousDatabase == nil || d.Revision != op.PreviousDatabase.Revision || d.Status != "needs_attention" {
			return errors.New("覆盖任务已交付、已恢复或目标已变化；再次导入请新建上传")
		}
		if _, e = tx.Exec(`UPDATE mysql_databases SET status='updating' WHERE id=?`, d.ID); e != nil {
			return e
		}
	}
	ids := []string{op.Server.ID}
	if op.TargetServer.ID != "" {
		ids = append(ids, op.TargetServer.ID)
	}
	for _, server := range ids {
		var n int
		if e = tx.QueryRow(`SELECT count(*) FROM mysql_jobs WHERE state IN ('queued','running') AND (target_id=? OR json_extract(payload,'$.target_server.id')=?)`, server, server).Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			return errors.New("源或目标实例已有进行中的任务")
		}
	}
	if _, e = tx.Exec(`UPDATE mysql_jobs SET state='queued',error='',updated_at=? WHERE id=?`, Now(), id); e != nil {
		return e
	}
	if accountAction(op.Action) && op.Account != nil {
		status := "updating"
		if op.Action == "create_account" {
			status = "creating"
		}
		if _, e = tx.Exec(`UPDATE mysql_accounts SET status=? WHERE id=?`, status, op.Account.ID); e != nil {
			return e
		}
	}
	if databaseLifecycleAction(op.Action) {
		if _, e = tx.Exec(`UPDATE mysql_databases SET status='updating' WHERE id=?`, op.Database.ID); e != nil {
			return e
		}
	}
	if (op.Action == "import_database" || op.Action == "overwrite_database") && op.Import != nil {
		if _, e = tx.Exec(`UPDATE mysql_imports SET state='queued' WHERE id=? AND job_id=?`, op.Import.ID, id); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'job.retry',?,'queued',?)`, actor, id, Now()); e != nil {
		return e
	}
	return tx.Commit()
}
