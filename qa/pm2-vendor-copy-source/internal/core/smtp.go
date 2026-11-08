package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"regexp"
	"strings"
	"time"
)

type SMTPSettings struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Mode        string `json:"mode"`
	Username    string `json:"username"`
	From        string `json:"from"`
	Enabled     bool   `json:"enabled"`
	HasPassword bool   `json:"has_password"`
	UpdatedAt   string `json:"updated_at"`
}

type smtpSettingsInput struct {
	SMTPSettings
	Password string `json:"password"`
}

var smtpHostLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func validMailAddress(value string) bool {
	if value == "" || len(value) > 254 || strings.ContainsAny(value, "\r\n\t ") {
		return false
	}
	a, e := mail.ParseAddress(value)
	return e == nil && a.Address == value
}

func validSMTPHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/@ 	\r\n") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	if strings.Contains(value, ":") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !smtpHostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validateSMTPSettings(in smtpSettingsInput) (smtpSettingsInput, error) {
	in.Host = strings.TrimSpace(in.Host)
	in.Username = strings.TrimSpace(in.Username)
	in.From = strings.TrimSpace(in.From)
	if !validSMTPHost(in.Host) || in.Port < 1 || in.Port > 65535 || (in.Mode != "tls" && in.Mode != "starttls") {
		return in, errors.New("SMTP 主机、端口或加密方式无效")
	}
	if !validMailAddress(in.From) || len(in.Username) > 254 || strings.ContainsAny(in.Username, "\r\n") || len(in.Password) > 4096 || (in.Username == "" && in.Password != "") {
		return in, errors.New("发件邮箱或 SMTP 账号无效")
	}
	return in, nil
}

func (s *Store) migrateSMTP() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS smtp_settings(
		id INTEGER PRIMARY KEY CHECK(id=1),host TEXT NOT NULL,port INTEGER NOT NULL,
		mode TEXT NOT NULL,username TEXT NOT NULL,from_address TEXT NOT NULL,
		password_cipher BLOB NOT NULL,enabled INTEGER NOT NULL,updated_at TEXT NOT NULL);
		INSERT OR IGNORE INTO schema_migrations VALUES(51,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func (s *Store) SMTPSettings() (SMTPSettings, error) {
	var out SMTPSettings
	var enabled int
	var cipher []byte
	e := s.DB.QueryRow(`SELECT host,port,mode,username,from_address,password_cipher,enabled,updated_at FROM smtp_settings WHERE id=1`).Scan(
		&out.Host, &out.Port, &out.Mode, &out.Username, &out.From, &cipher, &enabled, &out.UpdatedAt)
	if e == sql.ErrNoRows {
		return SMTPSettings{Port: 587, Mode: "starttls"}, nil
	}
	out.Enabled = enabled == 1
	out.HasPassword = len(cipher) > 0
	return out, e
}

func (s *Store) saveSMTPSettings(in smtpSettingsInput, actor string) (SMTPSettings, error) {
	var e error
	if in, e = validateSMTPSettings(in); e != nil {
		return SMTPSettings{}, e
	}
	cipher := []byte{}
	if in.Password != "" {
		cipher, e = encryptCredential(s.encryptionKey, "panel-smtp", []byte(in.Password))
		if e != nil {
			return SMTPSettings{}, errors.New("SMTP 密码加密失败")
		}
	} else {
		e = s.DB.QueryRow(`SELECT password_cipher FROM smtp_settings WHERE id=1`).Scan(&cipher)
		if e != nil && e != sql.ErrNoRows {
			return SMTPSettings{}, e
		}
		if e == sql.ErrNoRows {
			cipher = []byte{}
		}
	}
	if len(cipher) == 0 {
		cipher = []byte{}
	}
	_, e = s.DB.Exec(`INSERT INTO smtp_settings(id,host,port,mode,username,from_address,password_cipher,enabled,updated_at)
		VALUES(1,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
		host=excluded.host,port=excluded.port,mode=excluded.mode,username=excluded.username,
		from_address=excluded.from_address,password_cipher=excluded.password_cipher,
		enabled=excluded.enabled,updated_at=excluded.updated_at`,
		in.Host, in.Port, in.Mode, in.Username, in.From, cipher, in.Enabled, Now())
	if e != nil {
		return SMTPSettings{}, e
	}
	_ = s.Audit(actor, "mail.smtp.save", in.Host, "success")
	return s.SMTPSettings()
}

func (s *Store) smtpPassword() (string, error) {
	var cipher []byte
	if e := s.DB.QueryRow(`SELECT password_cipher FROM smtp_settings WHERE id=1`).Scan(&cipher); e != nil {
		return "", e
	}
	if len(cipher) == 0 {
		return "", nil
	}
	plain, e := decryptCredential(s.encryptionKey, "panel-smtp", cipher)
	if e != nil {
		return "", errors.New("SMTP 密码无法解密")
	}
	return string(plain), nil
}

func smtpDeliver(ctx context.Context, settings SMTPSettings, password, recipient, subject, body string, roots *x509.CertPool) error {
	if !settings.Enabled || !validMailAddress(recipient) || !validMailAddress(settings.From) || len(body) > 8192 {
		return errors.New("邮件参数无效")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	address := net.JoinHostPort(settings.Host, fmt.Sprint(settings.Port))
	conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if e != nil {
		return e
	}
	rawConn := conn
	defer rawConn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	go func() { <-ctx.Done(); _ = rawConn.Close() }()
	tlsConfig := &tls.Config{ServerName: settings.Host, MinVersion: tls.VersionTLS12, RootCAs: roots}
	if settings.Mode == "tls" {
		secure := tls.Client(conn, tlsConfig)
		if e = secure.HandshakeContext(ctx); e != nil {
			return e
		}
		conn = secure
	}
	client, e := smtp.NewClient(conn, settings.Host)
	if e != nil {
		return e
	}
	defer client.Close()
	if settings.Mode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP 服务器不支持 STARTTLS")
		}
		if e = client.StartTLS(tlsConfig); e != nil {
			return e
		}
	}
	if settings.Username != "" {
		if e = client.Auth(smtp.PlainAuth("", settings.Username, password, settings.Host)); e != nil {
			return e
		}
	}
	if e = client.Mail(settings.From); e != nil {
		return e
	}
	if e = client.Rcpt(recipient); e != nil {
		return e
	}
	w, e := client.Data()
	if e != nil {
		return e
	}
	subject = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, subject)
	body = strings.ReplaceAll(body, "\r", "")
	message := "From: " + settings.From + "\r\nTo: " + recipient + "\r\nSubject: " + mime.QEncoding.Encode("utf-8", subject) +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + strings.ReplaceAll(body, "\n", "\r\n") + "\r\n"
	if _, e = io.WriteString(w, message); e != nil {
		_ = w.Close()
		return e
	}
	if e = w.Close(); e != nil {
		return e
	}
	_ = client.Quit()
	return nil
}

func fileSharePublicURL(access PanelAccess, token string) (string, error) {
	ip := net.ParseIP(access.HTTPIP)
	if !access.HTTPEnabled || ip == nil || ip.IsUnspecified() || access.HTTPPort < 1 || !shareTokenPattern.MatchString(token) {
		return "", errors.New("未配置可访问的面板 HTTP IP 和端口")
	}
	return "http://" + net.JoinHostPort(ip.String(), fmt.Sprint(access.HTTPPort)) + "/share/" + token, nil
}

func (a *Server) smtpRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/mail/smtp", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !a.fileSharedInfrastructureAllowed(r.Context(), u) {
			fail(w, 403, "读取全局 SMTP 配置需要当前完整管理员授权")
			return
		}
		settings, e := a.Store.SMTPSettings()
		if e != nil {
			fail(w, 500, "读取 SMTP 配置失败")
			return
		}
		send(w, 200, settings)
	}))
	m.HandleFunc("PUT /api/mail/smtp", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !a.fileSharedInfrastructureAllowed(r.Context(), u) {
			fail(w, 403, "配置全局 SMTP 需要当前完整管理员授权")
			return
		}
		var in smtpSettingsInput
		if !decode(w, r, &in) {
			return
		}
		settings, e := a.Store.saveSMTPSettings(in, u.Username)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		send(w, 200, settings)
	}))
	m.HandleFunc("POST /api/sites/{id}/files/shares/send", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !a.fileSharedInfrastructureAllowed(r.Context(), u) {
			fail(w, 403, "使用全局 SMTP 发信需要当前完整管理员授权")
			return
		}
		if !a.allowedScope(r, "file.share.mail:"+u.ID) {
			fail(w, 429, "分享邮件请求过于频繁，请稍后再试")
			return
		}
		var in struct {
			URLPath   string `json:"url_path"`
			Recipient string `json:"recipient"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF || !strings.HasPrefix(in.URLPath, "/share/") || !validMailAddress(in.Recipient) {
			fail(w, 400, "分享链接或收件邮箱无效")
			return
		}
		share, e := a.Store.fileShareByToken(strings.TrimPrefix(in.URLPath, "/share/"))
		if e != nil || share.SiteID != r.PathValue("id") {
			fail(w, 404, "分享不存在或已失效")
			return
		}
		access, e := a.Store.PanelAccess()
		if e != nil {
			fail(w, 500, "读取面板入口失败")
			return
		}
		url, e := fileSharePublicURL(access, strings.TrimPrefix(in.URLPath, "/share/"))
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		settings, e := a.Store.SMTPSettings()
		if e != nil || !settings.Enabled {
			fail(w, 409, "请先配置并启用 SMTP 邮件服务")
			return
		}
		password, e := a.Store.smtpPassword()
		if e != nil {
			fail(w, 500, "读取 SMTP 凭据失败")
			return
		}
		body := fmt.Sprintf("文件：%s\n下载地址：%s\n有效期至：%s\n\n请仅将此链接转给预期收件人。", share.Name, url, time.Unix(share.ExpiresAt, 0).Format(time.RFC3339))
		e = smtpDeliver(r.Context(), settings, password, in.Recipient, "文件分享："+share.Name, body, nil)
		if e != nil {
			_ = a.Store.Audit(u.Username, "file.share.mail", share.SiteID+":"+share.ID, "failed")
			fail(w, 502, "SMTP 发信失败，请检查配置、网络和收件地址")
			return
		}
		_ = a.Store.Audit(u.Username, "file.share.mail", share.SiteID+":"+share.ID, "success")
		send(w, 200, map[string]bool{"accepted": true})
	}))
}
