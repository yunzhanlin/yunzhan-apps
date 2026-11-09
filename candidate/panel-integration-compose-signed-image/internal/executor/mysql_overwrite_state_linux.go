//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
)

const mysqlOverwrites = "/var/lib/panel-executor/mysql-overwrites"
const maxOverwriteJournal = 2 * 1024 * 1024

var mysqlSchemaOption = regexp.MustCompile(`^[a-zA-Z0-9_]{1,64}$`)

type mysqlOverwriteJournal struct {
	Operation core.DatabaseOperation `json:"operation"`
	Phase     string                 `json:"phase"`
	Backup    core.DatabaseBackup    `json:"backup"`
	Before    mysqlFingerprint       `json:"before"`
	Imported  mysqlFingerprint       `json:"imported"`
	Charset   string                 `json:"charset"`
	Collation string                 `json:"collation"`
	// Only typed, explicitly supported database privileges can be replayed.
	Grants    map[string][]string `json:"grants"`
	UpdatedAt string              `json:"updated_at"`
}

func validDatabaseOverwriteOperation(op core.DatabaseOperation) bool {
	if op.Action != "overwrite_database" || !core.ValidID(op.JobID) || !core.ValidDatabaseServer(op.Server) || op.Import == nil || !core.ValidDatabaseImport(*op.Import, true) || op.PreviousDatabase == nil {
		return false
	}
	old := *op.PreviousDatabase
	if !core.ValidID(old.ID) || old.ServerID != op.Server.ID || !core.ValidDatabaseName(old.Name) || old.Username != "db_"+old.ID[:20] || old.Status != "ready" || old.Revision < 1 {
		return false
	}
	expected := old
	expected.Revision++
	expected.LastJobID = op.JobID
	return sameLifecycleDatabase(expected, op.Database) && op.Import.TargetDatabaseID == old.ID && op.Import.TargetRevision == old.Revision && op.Import.ServerID == old.ServerID && op.Import.Name == old.Name
}
func overwriteRecoveryAction(phase string) string {
	switch phase {
	case "prepared", "secured", "backup_ready", "aborting":
		return "abort"
	case "importing", "rolling_back":
		return "rollback"
	case "imported":
		return "commit"
	case "restored":
		return "restore_access"
	case "completed", "rolled_back":
		return "none"
	}
	return "invalid"
}
func validOverwriteGrants(grants map[string][]string) bool {
	if len(grants) != 2 {
		return false
	}
	for _, host := range []string{"127.0.0.1", "localhost"} {
		ps, ok := grants[host]
		if !ok || len(ps) == 0 {
			return false
		}
		seen := map[string]bool{}
		for _, p := range ps {
			if seen[p] || !slices.Contains(accountPrivileges("manager"), p) {
				return false
			}
			seen[p] = true
		}
	}
	return true
}
func validOverwriteJournal(j mysqlOverwriteJournal) bool {
	if !validDatabaseOverwriteOperation(j.Operation) || overwriteRecoveryAction(j.Phase) == "invalid" || !mysqlSchemaOption.MatchString(j.Charset) || !mysqlSchemaOption.MatchString(j.Collation) || !validOverwriteGrants(j.Grants) {
		return false
	}
	if j.Backup.ID != "" {
		b := j.Backup
		r, _ := runtimecatalog.Find(j.Operation.Server.ReleaseID)
		if b.ID != j.Operation.JobID || b.ServerID != j.Operation.Server.ID || b.DatabaseID != j.Operation.Database.ID || b.Bytes <= 0 || b.Bytes > 4*1024*1024*1024 || b.Version != r.Version || len(b.SHA256) != 64 || !core.ValidID(b.SHA256[:32]) || !core.ValidID(b.SHA256[32:]) || len(j.Before.Sum) != 64 || j.Before.Rows < 0 {
			return false
		}
	}
	if slices.Contains([]string{"backup_ready", "importing", "imported", "completed", "rolling_back"}, j.Phase) && j.Backup.ID == "" {
		return false
	}
	if (j.Phase == "imported" || j.Phase == "completed") && (len(j.Imported.Sum) != 64 || j.Imported.Rows < 0) {
		return false
	}
	return true
}
func readOverwriteJournal(base, id string) (mysqlOverwriteJournal, error) {
	var j mysqlOverwriteJournal
	if !core.ValidID(id) {
		return j, errors.New("覆盖任务标识无效")
	}
	root, e := importRoot(base)
	if e != nil {
		return j, e
	}
	defer root.Close()
	f, e := openImportFile(root, id+".json")
	if e != nil {
		return j, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, maxOverwriteJournal+1))
	if e != nil {
		return j, e
	}
	if len(raw) > maxOverwriteJournal || json.Unmarshal(raw, &j) != nil || !validOverwriteJournal(j) || j.Operation.JobID != id {
		return j, errors.New("覆盖任务恢复日志归属或阶段无效")
	}
	return j, nil
}
func saveOverwriteJournal(base string, j mysqlOverwriteJournal) error {
	if !validOverwriteJournal(j) {
		return errors.New("不能保存无效覆盖任务恢复日志")
	}
	root, e := importRoot(base)
	if e != nil {
		return e
	}
	defer root.Close()
	raw, e := json.Marshal(j)
	if e != nil {
		return e
	}
	if len(raw) > maxOverwriteJournal {
		return errors.New("覆盖任务对象元数据超过 2 MiB 上限")
	}
	return atomicWrite(filepath.Join(base, j.Operation.JobID+".json"), raw, 0600)
}
func sameOverwriteOperation(a, b core.DatabaseOperation) bool {
	first, _ := json.Marshal(a)
	second, _ := json.Marshal(b)
	return string(first) == string(second)
}
func overwriteTransitionAllowed(from, to string) bool {
	next := map[string][]string{
		"prepared": {"secured", "aborting"}, "secured": {"backup_ready", "aborting"}, "backup_ready": {"importing", "aborting"},
		"importing": {"imported", "rolling_back"}, "imported": {"completed", "rolling_back"}, "aborting": {"restored"}, "rolling_back": {"restored"}, "restored": {"rolled_back"},
	}
	return slices.Contains(next[from], to)
}
func transitionOverwrite(base string, j *mysqlOverwriteJournal, to string) error {
	if !overwriteTransitionAllowed(j.Phase, to) {
		return errors.New("覆盖恢复阶段不能跳转或重新执行")
	}
	current, e := readOverwriteJournal(base, j.Operation.JobID)
	if e != nil {
		return e
	}
	if current.Phase != j.Phase || !sameOverwriteOperation(current.Operation, j.Operation) {
		return errors.New("覆盖任务日志已变化")
	}
	next := *j
	next.Phase = to
	next.UpdatedAt = core.Now()
	if e = saveOverwriteJournal(base, next); e != nil {
		return e
	}
	*j = next
	return nil
}
func overwriteCredential(base string, op core.DatabaseOperation) (mysqlCredential, error) {
	var c mysqlCredential
	if !validDatabaseOverwriteOperation(op) {
		return c, errors.New("覆盖任务身份无效")
	}
	root, e := importRoot(base)
	if e != nil {
		return c, e
	}
	defer root.Close()
	name := op.JobID + ".credential.json"
	f, e := openImportFile(root, name)
	if e == nil {
		raw, err := io.ReadAll(io.LimitReader(f, 4097))
		f.Close()
		if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &c) != nil || c.Username != op.Database.Username || len(c.Password) != 64 || !core.ValidID(c.Password[:32]) || !core.ValidID(c.Password[32:]) {
			return c, errors.New("覆盖任务临时凭据归属无效")
		}
		return c, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return c, e
	}
	c = mysqlCredential{Username: op.Database.Username, Password: core.ID() + core.ID()}
	if e = writeJSON(filepath.Join(base, name), c); e != nil {
		return c, e
	}
	return c, nil
}
