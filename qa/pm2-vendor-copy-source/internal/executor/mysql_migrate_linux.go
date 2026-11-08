//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Hold a connection-scoped global read lock during the snapshot and checks.
// If this worker exits, systemd and Pdeathsig kill the client: MySQL releases
// its locks. No persistent read_only setting can strand the source instance.
func mysqlReadLock(ctx context.Context, s core.DatabaseServer) (func(), error) {
	r, _ := runtimecatalog.Find(s.ReleaseID)
	cmd := exec.CommandContext(ctx, r.CLI(), "--defaults-file="+mysqlConfig(s.ID)+"/root.cnf", "--batch", "--skip-column-names", "--unbuffered")
	cmd.Env = mysqlEnv(r)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 2 * time.Second
	stdin, e := cmd.StdinPipe()
	if e != nil {
		return nil, e
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return nil, e
	}
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	release := func() { _, _ = io.WriteString(stdin, "UNLOCK TABLES;\n"); _ = stdin.Close(); _ = cmd.Wait() }
	if _, e = io.WriteString(stdin, "SET SESSION lock_wait_timeout=10; FLUSH TABLES WITH READ LOCK; SELECT 'panel-migration-lock-held';\n"); e != nil {
		_ = cmd.Process.Kill()
		release()
		return nil, e
	}
	ready := make(chan bool, 1)
	go func() {
		line, e := bufio.NewReader(stdout).ReadString('\n')
		ready <- e == nil && strings.TrimSpace(line) == "panel-migration-lock-held"
	}()
	select {
	case yes := <-ready:
		if yes {
			return release, nil
		}
	case <-ctx.Done():
	case <-time.After(15 * time.Second):
	}
	_ = cmd.Process.Kill()
	release()
	return nil, errors.New("未能及时取得源实例读锁，迁移尚未改变目标数据")
}

type mysqlFingerprint struct {
	Rows    int64
	Sum     string
	Objects string
}
type rowFingerprintWriter struct {
	pending []byte
	sum     big.Int
	rows    int64
}

func (w *rowFingerprintWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			w.pending = append(w.pending, p...)
			if len(w.pending) > 16*1024*1024 {
				return 0, errors.New("单行数据超过迁移核对的 16 MiB 限制")
			}
			break
		}
		if len(w.pending)+i > 16*1024*1024 {
			return 0, errors.New("单行数据超过迁移核对的 16 MiB 限制")
		}
		w.pending = append(w.pending, p[:i]...)
		if strings.HasPrefix(string(w.pending), "INSERT INTO ") {
			h := sha256.Sum256(w.pending)
			v := new(big.Int).SetBytes(h[:])
			w.sum.Add(&w.sum, v)
			mod := new(big.Int).Lsh(big.NewInt(1), 256)
			w.sum.Mod(&w.sum, mod)
			w.rows++
		}
		w.pending = w.pending[:0]
		p = p[i+1:]
	}
	return n, nil
}
func fingerprintMySQL(ctx context.Context, s core.DatabaseServer, db core.Database) (mysqlFingerprint, error) {
	var f mysqlFingerprint
	w := &rowFingerprintWriter{}
	e := mysqlCommand(ctx, s, "mysqldump", []string{"--compact", "--no-create-info", "--skip-triggers", "--skip-extended-insert", "--skip-add-locks", "--hex-blob", "--skip-comments", "--set-gtid-purged=OFF", "--column-statistics=0", "--no-tablespaces", "--skip-lock-tables", db.Name}, nil, w)
	if e != nil {
		return f, e
	}
	if len(w.pending) > 0 {
		return f, errors.New("数据核对输出不完整")
	}
	f.Rows = w.rows
	f.Sum = hex.EncodeToString(w.sum.FillBytes(make([]byte, 32)))
	q := "SELECT CONCAT('table:',TABLE_NAME,':',TABLE_TYPE) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + db.Name + "' UNION ALL SELECT CONCAT('routine:',ROUTINE_NAME,':',ROUTINE_TYPE) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='" + db.Name + "' UNION ALL SELECT CONCAT('trigger:',TRIGGER_NAME) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='" + db.Name + "' UNION ALL SELECT CONCAT('event:',EVENT_NAME) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='" + db.Name + "' ORDER BY 1;"
	f.Objects, e = mysqlQuery(ctx, s, q)
	return f, e
}
func migrateMySQL(ctx context.Context, op core.DatabaseOperation, add func(string)) (core.DatabaseBackup, error) {
	b := core.DatabaseBackup{ID: core.ID(), ServerID: op.Server.ID, DatabaseID: op.Database.ID, CreatedAt: core.Now()}
	if op.Server.ReleaseID != "mysql-8.0.46" || op.TargetServer.ReleaseID != "mysql-8.4.11" || op.TargetServer.ID == op.Server.ID || op.TargetDatabase.ServerID != op.TargetServer.ID || op.TargetDatabase.Name != op.Database.Name {
		return b, errors.New("迁移必须使用独立 MySQL 8.0 源与 8.4 空目标数据库")
	}
	source, e := readOwnedDatabase(op.Server, op.Database.ID)
	if e != nil {
		return b, e
	}
	if source.Name != op.Database.Name {
		return b, errors.New("源数据库名称不匹配")
	}
	target, e := readMySQL(op.TargetServer.ID)
	if e != nil {
		return b, e
	}
	if !target.Ready || target.Server.ReleaseID != op.TargetServer.ReleaseID || target.Server.Port != op.TargetServer.Port {
		return b, errors.New("目标实例尚未就绪或绑定不一致")
	}
	if e = waitMySQL(ctx, op.Server); e != nil {
		return b, e
	}
	if e = waitMySQL(ctx, op.TargetServer); e != nil {
		return b, e
	}
	add("源与目标精确版本、认证和实例绑定核对通过；申请短期源实例读锁")
	release, e := mysqlReadLock(ctx, op.Server)
	if e != nil {
		return b, e
	}
	defer release()
	add("源实例写入已暂停；任务结束或进程中断会自动释放读锁")
	before, e := fingerprintMySQL(ctx, op.Server, source)
	if e != nil {
		return b, e
	}
	// The generated source account may appear as a view/routine definer. It is
	// replicated as a locked, schema-scoped definer account, without copying its
	// login password or granting global privileges. Arbitrary definers fail closed.
	defs, e := mysqlQuery(ctx, op.Server, "SELECT DEFINER FROM information_schema.VIEWS WHERE TABLE_SCHEMA='"+source.Name+"' UNION SELECT DEFINER FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='"+source.Name+"' UNION SELECT DEFINER FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='"+source.Name+"' UNION SELECT DEFINER FROM information_schema.EVENTS WHERE EVENT_SCHEMA='"+source.Name+"';")
	if e != nil {
		return b, e
	}
	for _, def := range strings.Split(defs, "\n") {
		if def != "" && def != "root@localhost" && def != source.Username+"@localhost" && def != source.Username+"@127.0.0.1" {
			return b, errors.New("源库含其他账号的 DEFINER，请先核对对象权限再迁移")
		}
	}
	b, e = backupMySQL(ctx, op.Server, source, b)
	if e != nil {
		return b, e
	}
	add("源库一致性备份完成，已记录逐行数据指纹与对象清单")
	if e = createMySQLDatabase(ctx, op.TargetServer, op.TargetDatabase); e != nil {
		return b, e
	}
	// Only a task-owned target is replaceable on retry. The source is never reset.
	owned, e := readOwnedDatabase(op.TargetServer, op.TargetDatabase.ID)
	if e != nil || owned.Name != source.Name {
		return b, errors.New("目标数据库归属不匹配")
	}
	for _, host := range []string{"localhost", "127.0.0.1"} {
		if !strings.Contains("\n"+defs+"\n", "\n"+source.Username+"@"+host+"\n") {
			continue
		}
		aliasDir := mysqlConfig(op.TargetServer.ID) + "/migration-definers"
		if e = os.MkdirAll(aliasDir, 0700); e != nil {
			return b, e
		}
		marker := aliasDir + "/" + source.Username + "-" + host + ".json"
		wanted := op.Server.ID + ":" + source.ID + ":" + op.TargetDatabase.ID
		if raw, er := os.ReadFile(marker); er == nil {
			if string(raw) != wanted {
				return b, errors.New("目标定义者账号已有其他资源归属")
			}
		} else if !errors.Is(er, os.ErrNotExist) {
			return b, er
		} else {
			count, er := mysqlQuery(ctx, op.TargetServer, "SELECT COUNT(*) FROM mysql.user WHERE User='"+source.Username+"' AND Host='"+host+"';")
			if er != nil {
				return b, er
			}
			if count != "0" {
				return b, errors.New("目标已有不属于本迁移的定义者账号")
			}
			if er = atomicWrite(marker, []byte(wanted), 0600); er != nil {
				return b, er
			}
		}
		_, e = mysqlQuery(ctx, op.TargetServer, "CREATE USER IF NOT EXISTS '"+source.Username+"'@'"+host+"' ACCOUNT LOCK; GRANT ALL PRIVILEGES ON `"+source.Name+"`.* TO '"+source.Username+"'@'"+host+"';")
		if e != nil {
			return b, e
		}
	}
	if e = verifyMySQLBackup(b); e != nil {
		return b, e
	}
	if _, e = mysqlQuery(ctx, op.TargetServer, "DROP DATABASE `"+source.Name+"`; CREATE DATABASE `"+source.Name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"); e != nil {
		return b, e
	}
	file, e := os.Open(mysqlBackups + "/" + op.Server.ID + "/" + b.ID + ".sql")
	if e != nil {
		return b, e
	}
	e = mysqlCommand(ctx, op.TargetServer, "mysql", []string{"--binary-mode", "--database=" + source.Name}, file, io.Discard)
	file.Close()
	if e != nil {
		return b, e
	}
	after, e := fingerprintMySQL(ctx, op.TargetServer, op.TargetDatabase)
	if e != nil {
		return b, e
	}
	if before != after {
		return b, errors.New("源与目标逐行数据指纹或对象清单不一致，保留原库与备份，拒绝标记迁移完成")
	}
	add(fmt.Sprintf("数据核对通过：%d 行、SHA-256 多重集指纹与表/视图/过程/触发器/事件清单一致", before.Rows))
	add("独立目标数据库已就绪；原库与备份保留。应用需核对新连接信息后切换，原实例可继续用于回退")
	return b, nil
}
