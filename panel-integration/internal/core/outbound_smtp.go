package core

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// SMTP credentials are encrypted with the channel ID as AEAD associated data.
// There is deliberately no plaintext mode, insecure flag, client key or path.
type SMTPNotificationInput struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	TLSMode    string   `json:"tls_mode"`
	ServerName string   `json:"server_name"`
	CAPEM      string   `json:"ca_pem"`
	AuthMode   string   `json:"auth_mode"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	From       string   `json:"from"`
	To         []string `json:"to"`
}

type SMTPNotificationPublic struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	TLSMode     string   `json:"tls_mode"`
	ServerName  string   `json:"server_name"`
	CAPEM       string   `json:"ca_pem"`
	AuthMode    string   `json:"auth_mode"`
	UsernameSet bool     `json:"username_set"`
	PasswordSet bool     `json:"password_set"`
	From        string   `json:"from"`
	To          []string `json:"to"`
}

func smtpPublic(v *SMTPNotificationInput) *SMTPNotificationPublic {
	if v == nil {
		return nil
	}
	return &SMTPNotificationPublic{Host: v.Host, Port: v.Port, TLSMode: v.TLSMode, ServerName: v.ServerName, CAPEM: v.CAPEM, AuthMode: v.AuthMode, UsernameSet: v.Username != "", PasswordSet: v.Password != "", From: v.From, To: append([]string(nil), v.To...)}
}

func smtpHost(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.ContainsAny(value, " \t\r\n\\%[]") {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String() == value && ((ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast()) || ip.IsLoopback())
	}
	return ValidDomain(value)
}

func smtpMailbox(value string) bool {
	if len(value) > 254 || strings.ContainsAny(value, " \t\r\n\x00\"<>()\\,;:") {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false // SMTPUTF8 and display names are intentionally not supported.
		}
	}
	a, err := mail.ParseAddress(value)
	at := strings.LastIndexByte(value, '@')
	return err == nil && a.Name == "" && a.Address == value && at > 0 && ValidDomain(strings.ToLower(value[at+1:]))
}

func validateSMTPNotification(v *SMTPNotificationInput) error {
	if v == nil || !smtpHost(v.Host) || v.Port < 1 || v.Port > 65535 || !smtpHost(v.ServerName) || (v.TLSMode != "tls" && v.TLSMode != "starttls") {
		return errors.New("SMTP 须指定规范主机、1–65535 端口、证书名称及强制 TLS 或 STARTTLS")
	}
	if _, err := LoadBalanceHealthRoots(v.CAPEM); err != nil {
		return errors.New("SMTP 专用 CA 仅接受最多 16 KiB / 4 个有效公共 CA 证书")
	}
	if v.AuthMode != "none" && v.AuthMode != "plain" && v.AuthMode != "login" {
		return errors.New("SMTP 认证只支持 PLAIN、LOGIN 或显式无认证的 TLS 中继")
	}
	if v.AuthMode == "none" {
		if v.Username != "" || v.Password != "" {
			return errors.New("无认证中继不能附带账号或密码")
		}
	} else if len(v.Username) < 1 || len(v.Username) > 254 || len(v.Password) < 1 || len(v.Password) > 512 || strings.ContainsAny(v.Username+v.Password, "\x00\r\n") {
		return errors.New("SMTP 账号或密码无效；修改时留空保留原凭据")
	}
	if !smtpMailbox(v.From) || len(v.To) < 1 || len(v.To) > 5 {
		return errors.New("请输入一个发件地址和 1–5 个 ASCII 纯收件地址，不使用显示名")
	}
	seen := map[string]bool{}
	for _, recipient := range v.To {
		if !smtpMailbox(recipient) || seen[recipient] {
			return errors.New("SMTP 收件地址无效或重复")
		}
		seen[recipient] = true
	}
	return nil
}

// Resolve once and dial the resulting address, not the hostname a second time.
// TLS still verifies the explicitly configured certificate name. Local/private
// integration is explicit; link-local/multicast targets are rejected.
func dialSMTPNotification(ctx context.Context, v *SMTPNotificationInput) (net.Conn, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, v.Host)
	if err != nil || len(ips) == 0 || len(ips) > 8 {
		return nil, errors.New("SMTP 地址解析失败或超过预算")
	}
	for _, item := range ips {
		if item.Zone != "" || ((!item.IP.IsGlobalUnicast() || item.IP.IsLinkLocalUnicast()) && !item.IP.IsLoopback()) {
			return nil, errors.New("SMTP 目标地址不可用")
		}
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	for _, item := range ips {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(item.IP.String(), strconv.Itoa(v.Port)))
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.New("SMTP 连接失败")
}

type smtpReadBudgetConn struct {
	net.Conn
	remaining int
}

func (c *smtpReadBudgetConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errors.New("SMTP 响应超过预算")
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}

type smtpLoginAuth struct {
	username, password, host string
	step                     int
}

func (a *smtpLoginAuth) Start(info *smtp.ServerInfo) (string, []byte, error) {
	if !info.TLS || info.Name != a.host {
		return "", nil, errors.New("SMTP LOGIN 需要已验证 TLS")
	}
	a.step = 0
	return "LOGIN", nil, nil
}

func (a *smtpLoginAuth) Next(challenge []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	text := strings.ToLower(strings.TrimSpace(string(challenge)))
	if a.step == 0 && (text == "username:" || text == "user name:") {
		a.step++
		return []byte(a.username), nil
	}
	if a.step == 1 && text == "password:" {
		a.step++
		return []byte(a.password), nil
	}
	return nil, errors.New("SMTP LOGIN 认证顺序无效")
}

func smtpNotificationMessage(d outboundDelivery, v *SMTPNotificationInput) ([]byte, error) {
	var source OutboundMessage
	if len(d.Payload) > 4096 || !ValidID(d.ID) || json.Unmarshal([]byte(d.Payload), &source) != nil || source.SchemaVersion != 1 || !ValidID(source.EventID) || (!containsMenu(outboundKinds, source.Kind) && source.Kind != "test") {
		return nil, errors.New("SMTP 推送摘要无效")
	}
	message := safeOutboundMessage(Notification{ID: source.EventID, Kind: source.Kind, Severity: source.Severity, CreatedAt: source.CreatedAt})
	if source.Test {
		message.Title = "测试 · " + message.Title
	}
	body := message.Message + "\n事件标识：" + source.EventID + "\n推送标识：" + d.ID + "\n"
	if source.Test {
		body = "这是手动发送的测试摘要，不是新生成的自动日报。\n" + body
	}
	if source.Kind == "daily" && source.Report != nil {
		r := source.Report
		if _, err := time.Parse("2006-01-02", r.Day); err != nil {
			return nil, errors.New("SMTP 日报日期无效")
		}
		for _, count := range []int{r.Sites, r.RunningSites, r.FailedSiteJobs, r.FailedRuntimeJobs, r.AuditEvents, r.CertificatesDue} {
			if count < 0 || count > 1000000000 {
				return nil, errors.New("SMTP 日报统计无效")
			}
		}
		body += fmt.Sprintf("日期：%s\n网站：%d（运行 %d）\n失败网站任务：%d\n失败环境任务：%d\n24 小时审计事件：%d\n14 天内到期证书：%d\n", r.Day, r.Sites, r.RunningSites, r.FailedSiteJobs, r.FailedRuntimeJobs, r.AuditEvents, r.CertificatesDue)
		for _, resource := range []struct {
			name  string
			value *float64
		}{{"CPU", r.Resources.CPU}, {"内存", r.Resources.Memory}, {"磁盘", r.Resources.Disk}} {
			if resource.value == nil {
				body += resource.name + "：未记录\n"
			} else {
				if math.IsNaN(*resource.value) || math.IsInf(*resource.value, 0) || *resource.value < 0 || *resource.value > 100 {
					return nil, errors.New("SMTP 日报资源统计无效")
				}
				body += fmt.Sprintf("%s：%.1f%%\n", resource.name, *resource.value)
			}
		}
	}
	domain := v.From[strings.LastIndexByte(v.From, '@')+1:]
	header := "From: " + v.From + "\r\nTo: " + strings.Join(v.To, ", ") + "\r\nSubject: " + mime.QEncoding.Encode("UTF-8", message.Title) + "\r\nDate: " + time.Unix(source.CreatedAt, 0).UTC().Format(time.RFC1123Z) + "\r\nMessage-ID: <yunzhan." + d.ID + "@" + domain + ">\r\nX-Yunzhan-Delivery-ID: " + d.ID + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	for len(encoded) > 76 {
		header += encoded[:76] + "\r\n"
		encoded = encoded[76:]
	}
	header += encoded + "\r\n"
	if len(header) > 16<<10 {
		return nil, errors.New("SMTP 邮件超过预算")
	}
	return []byte(header), nil
}

func smtpNotificationFailure(phase string, err error) (int, string, int64) {
	var reply *textproto.Error
	if errors.As(err, &reply) && reply.Code >= 400 && reply.Code <= 599 {
		// Never expose the server's arbitrary error text, addresses or credentials.
		return reply.Code, fmt.Sprintf("SMTP %s被拒绝（%d）", phase, reply.Code), 0
	}
	return 0, "SMTP " + phase + "失败（连接、TLS 或响应预算）", 0
}

func sendSMTPNotification(ctx context.Context, d outboundDelivery, v *SMTPNotificationInput) (int, string, int64) {
	if err := validateSMTPNotification(v); err != nil {
		return 550, "SMTP 通道配置无效", 0
	}
	data, err := smtpNotificationMessage(d, v)
	if err != nil {
		return 550, "SMTP 推送摘要无效", 0
	}
	roots, _ := LoadBalanceHealthRoots(v.CAPEM)
	configuration := &tls.Config{ServerName: v.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS12}
	raw, err := dialSMTPNotification(ctx, v)
	if err != nil {
		return smtpNotificationFailure("连接", err)
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	deadline := time.Now().Add(8 * time.Second)
	if at, ok := ctx.Deadline(); ok && at.Before(deadline) {
		deadline = at
	}
	if err = raw.SetDeadline(deadline); err != nil {
		return smtpNotificationFailure("设置期限", err)
	}
	// Bound wire input including TLS handshake certificates. Keep the concrete
	// *tls.Conn passed to net/smtp so its verified TLS state remains authoritative.
	budget := &smtpReadBudgetConn{Conn: raw, remaining: 256 << 10}
	var connection net.Conn = budget
	if v.TLSMode == "tls" {
		tlsConnection := tls.Client(budget, configuration)
		if err = tlsConnection.HandshakeContext(ctx); err != nil {
			return smtpNotificationFailure("证书验证", err)
		}
		connection = tlsConnection
	}
	client, err := smtp.NewClient(connection, v.ServerName)
	if err != nil {
		return smtpNotificationFailure("握手", err)
	}
	defer client.Close()
	if err = client.Hello("yunzhan.invalid"); err != nil {
		return smtpNotificationFailure("EHLO", err)
	}
	if v.TLSMode == "starttls" {
		if supported, _ := client.Extension("STARTTLS"); !supported {
			return 550, "SMTP 接收端未提供强制 STARTTLS；未发送认证或邮件", 0
		}
		if err = client.StartTLS(configuration); err != nil {
			return smtpNotificationFailure("STARTTLS 证书验证", err)
		}
	}
	state, secured := client.TLSConnectionState()
	if !secured || !state.HandshakeComplete || state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 {
		return 550, "SMTP TLS 未完成验证；未发送认证或邮件", 0
	}
	if v.AuthMode != "none" {
		if supported, mechanisms := client.Extension("AUTH"); !supported || !containsMenu(strings.Fields(strings.ToUpper(mechanisms)), strings.ToUpper(v.AuthMode)) {
			return 550, "SMTP 接收端不支持所选认证；未发送凭据", 0
		}
		var auth smtp.Auth = smtp.PlainAuth("", v.Username, v.Password, v.ServerName)
		if v.AuthMode == "login" {
			auth = &smtpLoginAuth{username: v.Username, password: v.Password, host: v.ServerName}
		}
		if err = client.Auth(auth); err != nil {
			return smtpNotificationFailure("认证", err)
		}
	}
	if err = client.Mail(v.From); err != nil {
		return smtpNotificationFailure("发件地址", err)
	}
	for _, address := range v.To {
		if err = client.Rcpt(address); err != nil {
			return smtpNotificationFailure("收件地址", err) // No DATA if any recipient is rejected.
		}
	}
	writer, err := client.Data()
	if err != nil {
		return smtpNotificationFailure("DATA", err)
	}
	if _, err = io.Copy(writer, strings.NewReader(string(data))); err != nil {
		return smtpNotificationFailure("发送", err)
	}
	if err = writer.Close(); err != nil {
		return smtpNotificationFailure("接收确认", err)
	}
	// A 250 response to DATA is relay acceptance, not proof of inbox delivery.
	// QUIT failure must not turn an already accepted message into another send.
	_ = client.Quit()
	return 250, "", 0
}
