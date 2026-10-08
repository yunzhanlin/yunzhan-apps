package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var outboundKinds = []string{"schedule", "remote", "monitor", "integrity", "sync", "daily", "php-security"}

type NotificationChannel struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	EndpointHost    string                  `json:"endpoint_host"`
	Enabled         bool                    `json:"enabled"`
	Kinds           []string                `json:"kinds"`
	Revision        int64                   `json:"revision"`
	SecretSet       bool                    `json:"secret_set"`
	UpdatedAt       string                  `json:"updated_at"`
	StartedAt       int64                   `json:"-"`
	Type            string                  `json:"type"`
	SMTP            *SMTPNotificationPublic `json:"smtp,omitempty"`
	CredentialError string                  `json:"credential_error,omitempty"`
}
type NotificationChannelInput struct {
	Name     string                 `json:"name"`
	URL      string                 `json:"url"`
	Secret   string                 `json:"secret"`
	Enabled  bool                   `json:"enabled"`
	Kinds    []string               `json:"kinds"`
	Revision int64                  `json:"revision"`
	Type     string                 `json:"type,omitempty"`
	SMTP     *SMTPNotificationInput `json:"smtp,omitempty"`
}
type notificationCredential struct {
	URL, Secret string
	Type        string                 `json:"type,omitempty"`
	SMTP        *SMTPNotificationInput `json:"smtp,omitempty"`
}

func (v notificationCredential) channelType() string {
	if v.Type == "" {
		return "webhook" // Original encrypted URL/Secret envelopes are unchanged.
	}
	return v.Type
}

type OutboundMessage struct {
	SchemaVersion int                   `json:"schema_version"`
	EventID       string                `json:"event_id"`
	Kind          string                `json:"kind"`
	Title         string                `json:"title"`
	Message       string                `json:"message"`
	Severity      string                `json:"severity"`
	CreatedAt     int64                 `json:"created_at"`
	Report        *OutboundDailySummary `json:"report,omitempty"`
	Test          bool                  `json:"test,omitempty"`
}
type OutboundDailySummary struct {
	Day               string `json:"day"`
	Sites             int    `json:"sites"`
	RunningSites      int    `json:"running_sites"`
	FailedSiteJobs    int    `json:"failed_site_jobs"`
	FailedRuntimeJobs int    `json:"failed_runtime_jobs"`
	AuditEvents       int    `json:"audit_events_24h"`
	CertificatesDue   int    `json:"certificates_due_14_days"`
	Resources         struct {
		CPU    *float64 `json:"cpu_percent,omitempty"`
		Memory *float64 `json:"memory_percent,omitempty"`
		Disk   *float64 `json:"disk_percent,omitempty"`
	} `json:"resources"`
}

func (s *Store) migrateOutboundNotifications() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS notification_channels(id TEXT PRIMARY KEY,name TEXT NOT NULL,endpoint_host TEXT NOT NULL,credential BLOB NOT NULL,enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),kinds TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),watermark INTEGER NOT NULL DEFAULT 0,started_at INTEGER NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notification_deliveries(id TEXT PRIMARY KEY,channel_id TEXT NOT NULL REFERENCES notification_channels(id),channel_revision INTEGER NOT NULL,event_id TEXT NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','running','succeeded','failed','cancelled')),attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at INTEGER NOT NULL DEFAULT 0,lease_until INTEGER NOT NULL DEFAULT 0,http_status INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,completed_at INTEGER NOT NULL DEFAULT 0,UNIQUE(channel_id,event_id));
CREATE INDEX IF NOT EXISTS notification_delivery_due ON notification_deliveries(state,next_attempt_at);
CREATE TABLE IF NOT EXISTS app_notification_cursors(module_id TEXT PRIMARY KEY,cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS notification_dispatch_status(id INTEGER PRIMARY KEY CHECK(id=1),last_error TEXT NOT NULL,last_check_at TEXT NOT NULL);
INSERT OR IGNORE INTO notification_dispatch_status VALUES(1,'','');
INSERT OR IGNORE INTO schema_migrations VALUES(41,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	// Ordinary SQLite rowids can restart at one after retention removes the
	// entire source table. Keep a separate monotonic sequence and a delete
	// trigger so queue watermarks remain correct without retaining old notices.
	_, e = s.DB.Exec(`CREATE TABLE IF NOT EXISTS notification_sequence(id INTEGER PRIMARY KEY CHECK(id=1),last_sequence INTEGER NOT NULL);
INSERT OR IGNORE INTO notification_sequence SELECT 1,MAX(COALESCE((SELECT MAX(rowid) FROM notifications),0),COALESCE((SELECT MAX(watermark) FROM notification_channels),0));
CREATE TABLE IF NOT EXISTS notification_event_order(notification_id TEXT PRIMARY KEY,sequence INTEGER NOT NULL UNIQUE);
INSERT OR IGNORE INTO notification_event_order SELECT id,rowid FROM notifications;
CREATE TRIGGER IF NOT EXISTS notification_order_insert AFTER INSERT ON notifications BEGIN
 INSERT INTO notification_event_order VALUES(NEW.id,(SELECT last_sequence+1 FROM notification_sequence WHERE id=1));
 UPDATE notification_sequence SET last_sequence=last_sequence+1 WHERE id=1;
END;
CREATE TRIGGER IF NOT EXISTS notification_order_delete AFTER DELETE ON notifications BEGIN
 DELETE FROM notification_event_order WHERE notification_id=OLD.id;
END;
INSERT OR IGNORE INTO schema_migrations VALUES(42,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}
func validateWebhookURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("请输入有效的 HTTPS Webhook 地址")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host == "" || strings.ContainsAny(host, " \t\r\n\\%") {
		return nil, errors.New("Webhook 主机无效")
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, errors.New("Webhook 端口无效")
		}
	}
	// HTTP is an explicitly local integration destination; public recipients
	// always use authenticated TLS. No implicit proxy or redirect is used.
	if u.Scheme == "http" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("外部 Webhook 必须使用 HTTPS；HTTP 仅允许明确的回环地址")
	}
	return u, nil
}
func (s *Store) NotificationChannels() ([]NotificationChannel, error) {
	rows, e := s.DB.Query(`SELECT id,name,endpoint_host,enabled,kinds,revision,updated_at,started_at,credential FROM notification_channels ORDER BY rowid`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []NotificationChannel{}
	for rows.Next() {
		var c NotificationChannel
		var raw string
		var cipher []byte
		if e = rows.Scan(&c.ID, &c.Name, &c.EndpointHost, &c.Enabled, &raw, &c.Revision, &c.UpdatedAt, &c.StartedAt, &cipher); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(raw), &c.Kinds); e != nil {
			return nil, e
		}
		plain, err := decryptCredential(s.encryptionKey, "notification-channel:"+c.ID, cipher)
		var secret notificationCredential
		if err != nil || json.Unmarshal(plain, &secret) != nil {
			c.Type, c.CredentialError = "invalid", "通道凭据无法读取；不发送明文或猜测协议"
			out = append(out, c)
			continue // One damaged envelope must not block unrelated channels.
		}
		c.Type = secret.channelType()
		if (c.Type == "webhook" && secret.SMTP != nil) || (c.Type == "smtp" && (secret.URL != "" || secret.Secret != "")) {
			c.Type, c.CredentialError = "invalid", "推送凭据混合了不同协议，只允许停用保留证据"
			out = append(out, c)
			continue
		}
		if c.Type == "smtp" {
			if validateSMTPNotification(secret.SMTP) != nil {
				c.Type, c.CredentialError = "invalid", "SMTP 通道凭据不可读取"
				out = append(out, c)
				continue
			}
			c.SMTP = smtpPublic(secret.SMTP)
			c.SecretSet = secret.SMTP.Password != ""
		} else if c.Type == "webhook" {
			c.SecretSet = true
		} else {
			c.Type, c.CredentialError = "invalid", "推送通道类型无效"
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) SaveNotificationChannel(id string, in NotificationChannelInput) (NotificationChannel, error) {
	var empty NotificationChannel
	if len([]rune(strings.TrimSpace(in.Name))) < 1 || len([]rune(in.Name)) > 60 || len(in.Kinds) == 0 || len(in.Kinds) > len(outboundKinds) {
		return empty, errors.New("名称或事件范围无效")
	}
	seen := map[string]bool{}
	for _, k := range in.Kinds {
		if !containsMenu(outboundKinds, k) || seen[k] {
			return empty, errors.New("事件范围重复或无效")
		}
		seen[k] = true
	}
	if e := s.syncNotifications(); e != nil {
		return empty, e
	}
	create := id == ""
	if create {
		id = ID()
	} else if !ValidID(id) || in.Revision < 1 {
		return empty, errors.New("请读取当前通道版本")
	}
	var secret notificationCredential
	var previous []byte
	if !create {
		if e := s.DB.QueryRow(`SELECT credential FROM notification_channels WHERE id=?`, id).Scan(&previous); e != nil {
			return empty, e
		}
		b, e := decryptCredential(s.encryptionKey, "notification-channel:"+id, previous)
		if e != nil {
			if !in.Enabled && in.Type == "" && in.URL == "" && in.Secret == "" && in.SMTP == nil {
				return s.pauseUnreadableNotificationChannel(id, in, previous)
			}
			return empty, errors.New("通道凭据无法读取")
		}
		if e = json.Unmarshal(b, &secret); e != nil {
			if !in.Enabled && in.Type == "" && in.URL == "" && in.Secret == "" && in.SMTP == nil {
				return s.pauseUnreadableNotificationChannel(id, in, previous)
			}
			return empty, errors.New("通道凭据无法读取")
		}
		if (secret.channelType() != "webhook" && secret.channelType() != "smtp") || (secret.channelType() == "smtp" && (validateSMTPNotification(secret.SMTP) != nil || secret.URL != "" || secret.Secret != "")) || (secret.channelType() == "webhook" && secret.SMTP != nil) {
			if !in.Enabled && in.Type == "" && in.URL == "" && in.Secret == "" && in.SMTP == nil {
				return s.pauseUnreadableNotificationChannel(id, in, previous)
			}
			return empty, errors.New("通道凭据格式无效，只允许停用保留证据")
		}
	}
	typeName := in.Type
	if typeName == "" {
		typeName = secret.channelType()
	}
	if typeName != "webhook" && typeName != "smtp" {
		return empty, errors.New("推送通道只支持 Webhook 或 SMTP")
	}
	if !create && typeName != secret.channelType() {
		return empty, errors.New("现有通道不能更换协议，请新建通道")
	}
	secret.Type = typeName
	var endpointHost string
	if typeName == "smtp" {
		if in.URL != "" || in.Secret != "" {
			return empty, errors.New("SMTP 通道不使用 Webhook 地址或签名密钥")
		}
		if in.SMTP != nil {
			candidate := *in.SMTP
			candidate.To = append([]string(nil), in.SMTP.To...)
			if secret.SMTP != nil && candidate.AuthMode != "none" {
				if candidate.Username == "" {
					candidate.Username = secret.SMTP.Username
				}
				if candidate.Password == "" {
					candidate.Password = secret.SMTP.Password
				}
			}
			secret.SMTP = &candidate
		}
		if e := validateSMTPNotification(secret.SMTP); e != nil {
			return empty, e
		}
		endpointHost = net.JoinHostPort(secret.SMTP.Host, strconv.Itoa(secret.SMTP.Port))
	} else {
		if in.SMTP != nil {
			return empty, errors.New("Webhook 通道不能附带邮件凭据")
		}
		if in.URL != "" {
			secret.URL = strings.TrimSpace(in.URL)
		}
		if in.Secret != "" {
			secret.Secret = in.Secret
		}
		u, e := validateWebhookURL(secret.URL)
		if e != nil {
			return empty, e
		}
		if len(secret.Secret) < 16 || len(secret.Secret) > 512 {
			return empty, errors.New("签名密钥需要 16–512 字符")
		}
		endpointHost = u.Host
	}
	raw, _ := json.Marshal(secret)
	cipher, e := encryptCredential(s.encryptionKey, "notification-channel:"+id, raw)
	if e != nil {
		return empty, e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	var watermark int64
	if e = tx.QueryRow(`SELECT last_sequence FROM notification_sequence WHERE id=1`).Scan(&watermark); e != nil {
		return empty, e
	}
	kinds, _ := json.Marshal(in.Kinds)
	now := time.Now().Unix()
	if create {
		var count int
		if e = tx.QueryRow(`SELECT count(*) FROM notification_channels`).Scan(&count); e != nil {
			return empty, e
		}
		if count >= 8 {
			return empty, errors.New("最多配置 8 个推送通道")
		}
		_, e = tx.Exec(`INSERT INTO notification_channels VALUES(?,?,?,?,?,?,1,?,?,?)`, id, strings.TrimSpace(in.Name), endpointHost, cipher, in.Enabled, string(kinds), watermark, now, Now())
	} else {
		var result sql.Result
		result, e = tx.Exec(`UPDATE notification_channels SET name=?,endpoint_host=?,credential=?,enabled=?,kinds=?,revision=revision+1,watermark=?,started_at=?,updated_at=? WHERE id=? AND revision=?`, strings.TrimSpace(in.Name), endpointHost, cipher, in.Enabled, string(kinds), watermark, now, Now(), id, in.Revision)
		if e == nil {
			n, _ := result.RowsAffected()
			if n != 1 {
				return empty, errors.New("通道配置已变化，请重新读取")
			}
		}
		if e == nil {
			_, e = tx.Exec(`UPDATE notification_deliveries SET state='cancelled',completed_at=? WHERE channel_id=? AND state IN ('pending','running')`, now, id)
		}
	}
	if e != nil {
		return empty, e
	}
	if e = tx.Commit(); e != nil {
		return empty, e
	}
	channels, e := s.NotificationChannels()
	for _, c := range channels {
		if c.ID == id {
			return c, e
		}
	}
	return empty, sql.ErrNoRows
}

// A damaged envelope cannot be decrypted or replaced by guessing its protocol,
// but an administrator must still be able to pause it and retain all evidence.
func (s *Store) pauseUnreadableNotificationChannel(id string, in NotificationChannelInput, expectedCipher []byte) (NotificationChannel, error) {
	var empty NotificationChannel
	tx, err := s.DB.Begin()
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	var name, raw string
	var revision int64
	var currentCipher []byte
	if err = tx.QueryRow(`SELECT name,kinds,revision,credential FROM notification_channels WHERE id=?`, id).Scan(&name, &raw, &revision, &currentCipher); err != nil {
		return empty, err
	}
	var kinds []string
	if json.Unmarshal([]byte(raw), &kinds) != nil || name != in.Name || revision != in.Revision || len(kinds) != len(in.Kinds) || !bytes.Equal(currentCipher, expectedCipher) {
		return empty, errors.New("损坏通道只允许按当前修订停用，不改写配置或凭据")
	}
	for i, kind := range kinds {
		if kind != in.Kinds[i] {
			return empty, errors.New("损坏通道只允许停用，不改写事件范围")
		}
	}
	result, err := tx.Exec(`UPDATE notification_channels SET enabled=0,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND credential=?`, Now(), id, in.Revision, expectedCipher)
	if err != nil {
		return empty, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return empty, errors.New("通道配置已变化，请重新读取")
	}
	if _, err = tx.Exec(`UPDATE notification_deliveries SET state='cancelled',completed_at=?,lease_until=0 WHERE channel_id=? AND state IN ('pending','running')`, time.Now().Unix(), id); err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	channels, err := s.NotificationChannels()
	if err != nil {
		return empty, err
	}
	for _, channel := range channels {
		if channel.ID == id {
			return channel, nil
		}
	}
	return empty, sql.ErrNoRows
}

func safeOutboundMessage(n Notification) OutboundMessage {
	title, message := "云栈运维通知", "发生一条新的运维事件，请登录面板查看详情。"
	switch n.Kind {
	case "schedule":
		title, message = "计划任务失败", "计划任务执行失败，请查看面板中的运行记录。"
	case "remote":
		title, message = "远端备份失败", "远端备份传输失败，请查看面板中的备份记录。"
	case "monitor":
		title, message = "资源告警", "服务器资源或服务达到告警条件，请查看监控详情。"
	case "integrity":
		title, message = "网站文件变化", "文件监控或防篡改发现变化或检查失败，请查看应用记录。"
	case "sync":
		title, message = "文件同步需要处理", "文件同步发生冲突或失败，请查看同步记录。"
	case "php-security":
		title, message = "PHP 代码安全事件", "PHP 扫描有待审查结果或隔离、恢复操作，请查看应用记录；静态命中不等于已确认后门。"
	case "daily":
		title, message = "每日运维报告", "今日运维报告已生成，请登录面板查看资源、网站、任务与证书情况。"
	case "test":
		title, message = "云栈推送测试", "推送通道测试消息。"
	}
	// Source messages can include arbitrary task output, file names or credentials.
	// External notifications contain only this fixed summary and opaque event ID.
	return OutboundMessage{SchemaVersion: 1, EventID: n.ID, Kind: n.Kind, Title: title, Message: message, Severity: n.Severity, CreatedAt: n.CreatedAt}
}
func insertOutbound(tx *sql.Tx, channel string, revision int64, message OutboundMessage) error {
	var pending, total int
	if e := tx.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE state IN ('pending','running') AND channel_id=?`, channel).Scan(&pending); e != nil {
		return e
	}
	if e := tx.QueryRow(`SELECT count(*) FROM notification_deliveries`).Scan(&total); e != nil {
		return e
	}
	if pending >= 1000 || total >= 10000 {
		return errors.New("推送队列已达上限，请处理失败记录后重试")
	}
	raw, e := json.Marshal(message)
	if e != nil || len(raw) > 4096 {
		return errors.New("推送摘要无效")
	}
	_, e = tx.Exec(`INSERT OR IGNORE INTO notification_deliveries(id,channel_id,channel_revision,event_id,payload,state,created_at) VALUES(?,?,?,?,?,'pending',?)`, ID(), channel, revision, message.EventID, string(raw), time.Now().Unix())
	return e
}
func (s *Store) QueueOutboundNotifications() error {
	if e := s.syncNotifications(); e != nil {
		return e
	}
	channels, e := s.NotificationChannels()
	if e != nil {
		return e
	}
	for _, c := range channels {
		if !c.Enabled {
			continue
		}
		tx, e := s.DB.Begin()
		if e != nil {
			return e
		}
		e = queueChannelNotifications(tx, c)
		if e == nil {
			e = tx.Commit()
		} else {
			tx.Rollback()
		}
		if e != nil {
			return e
		}
	}
	return nil
}
func queueChannelNotifications(tx *sql.Tx, c NotificationChannel) error {
	var cursor, revision int64
	var enabled bool
	if e := tx.QueryRow(`SELECT watermark,revision,enabled FROM notification_channels WHERE id=?`, c.ID).Scan(&cursor, &revision, &enabled); e != nil {
		return e
	}
	if revision != c.Revision || !enabled {
		return nil
	}
	rows, e := tx.Query(`SELECT o.sequence,n.id,n.kind,n.severity,n.created_at,n.source,n.source_id FROM notification_event_order o JOIN notifications n ON n.id=o.notification_id WHERE o.sequence>? ORDER BY o.sequence LIMIT 100`, cursor)
	if e != nil {
		return e
	}
	type item struct {
		seq              int64
		n                Notification
		source, sourceID string
	}
	items := []item{}
	for rows.Next() {
		var x item
		if e = rows.Scan(&x.seq, &x.n.ID, &x.n.Kind, &x.n.Severity, &x.n.CreatedAt, &x.source, &x.sourceID); e != nil {
			rows.Close()
			return e
		}
		items = append(items, x)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, x := range items {
		if x.n.CreatedAt >= c.StartedAt && containsMenu(c.Kinds, x.n.Kind) {
			message := safeOutboundMessage(x.n)
			if x.n.Kind == "daily" && x.source == "daily-report" {
				var raw string
				if err := tx.QueryRow(`SELECT report FROM app_daily_reports WHERE day=?`, x.sourceID).Scan(&raw); err == nil {
					var report OutboundDailySummary
					if json.Unmarshal([]byte(raw), &report) != nil {
						return errors.New("日报摘要不可读取")
					}
					report.Day = x.sourceID
					message.Report = &report
				} else if !errors.Is(err, sql.ErrNoRows) {
					return err
				}
			}
			if e = insertOutbound(tx, c.ID, c.Revision, message); e != nil {
				return e
			}
		}
		cursor = x.seq
	}
	_, e = tx.Exec(`UPDATE notification_channels SET watermark=? WHERE id=? AND revision=?`, cursor, c.ID, c.Revision)
	return e
}
func (s *Store) QueueDailyNotification(day string) error {
	if _, e := time.Parse("2006-01-02", day); e != nil {
		return e
	}
	_, e := s.DB.Exec(`INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at) VALUES(?,'daily','每日运维报告','今日报告已生成','info','daily-report',?,?)`, ID(), day, time.Now().Unix())
	return e
}
func webhookSignature(secret, deliveryID, timestamp string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s.%s.", timestamp, deliveryID)
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (s *Store) NotificationDeliveryHistory(id string) ([]map[string]any, error) {
	rows, e := s.DB.Query(`SELECT id,event_id,state,attempts,http_status,error,created_at,completed_at FROM notification_deliveries WHERE channel_id=? ORDER BY rowid DESC LIMIT 100`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, event, state, message string
		var attempts, status int
		var at, completed int64
		if e = rows.Scan(&id, &event, &state, &attempts, &status, &message, &at, &completed); e != nil {
			return nil, e
		}
		out = append(out, map[string]any{"id": id, "event_id": event, "state": state, "attempts": attempts, "http_status": status, "error": message, "created_at": at, "completed_at": completed})
	}
	return out, rows.Err()
}
