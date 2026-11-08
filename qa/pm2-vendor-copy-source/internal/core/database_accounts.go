package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"
)

// Accounts are scoped to one server and explicit database identities. Passwords
// belong only to the executor; a job never contains a password or its hash.
type DatabaseAccount struct {
	ID          string   `json:"id"`
	ServerID    string   `json:"server_id"`
	Name        string   `json:"name"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	DatabaseIDs []string `json:"database_ids"`
	Enabled     bool     `json:"enabled"`
	Status      string   `json:"status"`
	Revision    int64    `json:"revision"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type DatabaseAccountReference struct {
	Kind     string `json:"kind"`
	Database string `json:"database"`
	Name     string `json:"name"`
}
type DatabaseAccountRemovalPlan struct {
	AccountID      string                     `json:"account_id"`
	Revision       int64                      `json:"revision"`
	Status         string                     `json:"status"`
	Connections    int                        `json:"connections"`
	References     []DatabaseAccountReference `json:"references"`
	BlockedReasons []string                   `json:"blocked_reasons"`
}

func DatabaseAccountFinalStatus(action string) string {
	if action == "quarantine_account" {
		return "quarantined"
	}
	return "ready"
}

func ValidDatabaseAccount(a DatabaseAccount) bool {
	if !ValidID(a.ID) || !ValidID(a.ServerID) || a.Username != "app_"+a.ID[:20] || strings.TrimSpace(a.Name) != a.Name || !utf8.ValidString(a.Name) || len([]rune(a.Name)) < 1 || len([]rune(a.Name)) > 40 || a.Revision < 1 {
		return false
	}
	for _, r := range a.Name {
		if r < 32 || r == 127 {
			return false
		}
	}
	if a.Role != "readonly" && a.Role != "readwrite" && a.Role != "manager" {
		return false
	}
	if len(a.DatabaseIDs) < 1 || len(a.DatabaseIDs) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range a.DatabaseIDs {
		if !ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func (s *Store) migrateDatabaseAccounts() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS mysql_accounts(id TEXT PRIMARY KEY,server_id TEXT NOT NULL REFERENCES mysql_servers(id),name TEXT NOT NULL,username TEXT NOT NULL,role TEXT NOT NULL,database_ids TEXT NOT NULL,enabled INTEGER NOT NULL,status TEXT NOT NULL,revision INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(server_id,name),UNIQUE(server_id,username));
 INSERT OR IGNORE INTO schema_migrations VALUES(11,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}
func scanDatabaseAccount(row interface{ Scan(...any) error }) (DatabaseAccount, error) {
	var a DatabaseAccount
	var ids string
	e := row.Scan(&a.ID, &a.ServerID, &a.Name, &a.Username, &a.Role, &ids, &a.Enabled, &a.Status, &a.Revision, &a.CreatedAt, &a.UpdatedAt)
	if e == nil {
		e = json.Unmarshal([]byte(ids), &a.DatabaseIDs)
	}
	return a, e
}

const accountColumns = "id,server_id,name,username,role,database_ids,enabled,status,revision,created_at,updated_at"

func (s *Store) DatabaseAccount(id string) (DatabaseAccount, error) {
	return scanDatabaseAccount(s.DB.QueryRow(`SELECT `+accountColumns+` FROM mysql_accounts WHERE id=?`, id))
}
func (s *Store) DatabaseAccounts() ([]DatabaseAccount, error) {
	rows, e := s.DB.Query(`SELECT ` + accountColumns + ` FROM mysql_accounts ORDER BY created_at DESC,id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []DatabaseAccount{}
	for rows.Next() {
		a, e := scanDatabaseAccount(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func accountAction(action string) bool {
	switch action {
	case "create_account", "update_account", "rotate_account", "enable_account", "disable_account", "quarantine_account", "restore_account":
		return true
	}
	return false
}

// Called inside the same transaction and instance lock as every MySQL operation.
func queueDatabaseAccount(tx *sql.Tx, op *DatabaseOperation) error {
	if op.Account == nil {
		return errors.New("缺少账号参数")
	}
	a := *op.Account
	a.DatabaseIDs = append([]string(nil), a.DatabaseIDs...)
	sort.Strings(a.DatabaseIDs)
	if op.Action == "create_account" {
		a.ID = ID()
		a.ServerID = op.Server.ID
		a.Username = "app_" + a.ID[:20]
		a.Name = strings.TrimSpace(a.Name)
		a.Revision = 1
		a.Enabled = true
		a.Status = "creating"
		a.CreatedAt = Now()
		a.UpdatedAt = a.CreatedAt
	} else {
		old, e := scanDatabaseAccount(tx.QueryRow(`SELECT `+accountColumns+` FROM mysql_accounts WHERE id=?`, a.ID))
		if e != nil {
			return errors.New("账号不存在")
		}
		expectedStatus := "ready"
		if op.Action == "restore_account" {
			expectedStatus = "quarantined"
		}
		if old.ServerID != op.Server.ID || a.Revision != old.Revision || old.Status != expectedStatus {
			return errors.New("账号状态已变化，或前一任务尚未完成")
		}
		op.PreviousAccount = &old
		requestedRole, requestedIDs := a.Role, a.DatabaseIDs
		a = old
		a.Revision++
		a.UpdatedAt = Now()
		a.Status = "updating"
		switch op.Action {
		case "update_account":
			a.Role = requestedRole
			a.DatabaseIDs = requestedIDs
		case "enable_account":
			a.Enabled = true
		case "disable_account":
			a.Enabled = false
		case "rotate_account":
		case "quarantine_account":
			a.Status = "quarantined"
		case "restore_account":
			a.Status = "ready"
		default:
			return errors.New("账号操作无效")
		}
	}
	if !ValidDatabaseAccount(a) {
		return errors.New("账号名称 1–40 字，请选择有效权限及 1–32 个数据库")
	}
	for _, id := range a.DatabaseIDs {
		var server, state string
		if e := tx.QueryRow(`SELECT server_id,status FROM mysql_databases WHERE id=?`, id).Scan(&server, &state); e != nil || server != a.ServerID || state != "ready" {
			return errors.New("所有授权库必须属于同一实例且已经交付")
		}
	}
	if op.Action == "create_account" {
		ids, _ := json.Marshal(a.DatabaseIDs)
		if _, e := tx.Exec(`INSERT INTO mysql_accounts VALUES(?,?,?,?,?,?,?,?,?,?,?)`, a.ID, a.ServerID, a.Name, a.Username, a.Role, string(ids), a.Enabled, a.Status, a.Revision, a.CreatedAt, a.UpdatedAt); e != nil {
			return errors.New("该实例已存在同名账号")
		}
	} else {
		if _, e := tx.Exec(`UPDATE mysql_accounts SET status='updating' WHERE id=?`, a.ID); e != nil {
			return e
		}
	}
	op.Account = &a
	return nil
}
func finishDatabaseAccount(tx *sql.Tx, op DatabaseOperation, result DatabaseResult) error {
	if op.Account == nil {
		return errors.New("账号任务缺少身份")
	}
	a := *op.Account
	if result.State != "succeeded" {
		_, e := tx.Exec(`UPDATE mysql_accounts SET status='needs_attention' WHERE id=?`, a.ID)
		return e
	}
	ids, _ := json.Marshal(a.DatabaseIDs)
	_, e := tx.Exec(`UPDATE mysql_accounts SET name=?,role=?,database_ids=?,enabled=?,status=?,revision=?,updated_at=? WHERE id=? AND server_id=?`, a.Name, a.Role, string(ids), a.Enabled, DatabaseAccountFinalStatus(op.Action), a.Revision, Now(), a.ID, a.ServerID)
	return e
}

func sameAccountRequest(old, request DatabaseOperation) bool {
	if old.Action != request.Action || old.Server.ID != request.Server.ID || old.Account == nil || request.Account == nil {
		return false
	}
	a, b := old.Account, request.Account
	sameIDs := func(x, y []string) bool {
		left, right := append([]string(nil), x...), append([]string(nil), y...)
		sort.Strings(left)
		sort.Strings(right)
		if len(left) != len(right) {
			return false
		}
		for i := range left {
			if left[i] != right[i] {
				return false
			}
		}
		return true
	}
	if request.Action == "create_account" {
		return a.Name == strings.TrimSpace(b.Name) && a.Role == b.Role && sameIDs(a.DatabaseIDs, b.DatabaseIDs)
	}
	if a.ID != b.ID || old.PreviousAccount == nil || old.PreviousAccount.Revision != b.Revision {
		return false
	}
	if request.Action == "update_account" {
		return a.Role == b.Role && sameIDs(a.DatabaseIDs, b.DatabaseIDs)
	}
	return true
}
