package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

type ModuleAlertEvent struct {
	Sequence  int64  `json:"sequence"`
	ID        string `json:"id"`
	Time      string `json:"time"`
	Outcome   string `json:"outcome"`
	Changes   int    `json:"changes_count"`
	Conflicts int    `json:"conflicts_count"`
}
type ModuleAlertPage struct {
	Cursor int64              `json:"cursor"`
	Events []ModuleAlertEvent `json:"events"`
	Gap    bool               `json:"gap"`
}

func (a *Server) collectModuleNotifications(ctx context.Context) error {
	var firstError error
	for _, module := range []string{"file-monitor", "website-tamper-proof", "enterprise-tamper-proof", "files-sync"} {
		if err := a.collectOneModuleNotification(ctx, module); err != nil && firstError == nil {
			firstError = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return firstError
}
func (a *Server) collectOneModuleNotification(ctx context.Context, module string) error {
	cursor := int64(-1)
	e := a.Store.DB.QueryRow(`SELECT cursor FROM app_notification_cursors WHERE module_id=?`, module).Scan(&cursor)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	var page ModuleAlertPage
	if e = a.Executor.Call(ctx, "GET", "/v1/module-alert-events?module="+module+"&cursor="+strconv.FormatInt(cursor, 10), nil, &page); e != nil {
		return e
	}
	if page.Cursor < cursor {
		return errors.New("应用事件游标异常")
	}
	tx, e := a.Store.DB.Begin()
	if e != nil {
		return e
	}
	lastSequence := cursor
	for _, event := range page.Events {
		if !ValidID(event.ID) || event.Sequence <= lastSequence || event.Sequence > page.Cursor {
			tx.Rollback()
			return errors.New("应用事件摘要无效")
		}
		lastSequence = event.Sequence
		if event.Outcome == "failed" || event.Conflicts > 0 || (module != "files-sync" && event.Changes > 0) {
			at, e := time.Parse(time.RFC3339, event.Time)
			if e != nil {
				tx.Rollback()
				return e
			}
			kind, severity := "integrity", "warning"
			if module == "files-sync" {
				kind = "sync"
			}
			if event.Outcome == "failed" {
				severity = "critical"
			}
			_, e = tx.Exec(`INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at) VALUES(?,?,'应用事件','请查看应用执行记录',?,?,?,?)`, ID(), kind, severity, "app:"+module, event.ID, at.Unix())
			if e != nil {
				tx.Rollback()
				return e
			}
		}
	}
	if page.Gap {
		_, e = tx.Exec(`INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at) VALUES(?,'integrity','应用事件缺口','历史保留期或容量已跨过游标，请检查应用历史','critical','app:event-gap',?,?)`, ID(), module+":"+strconv.FormatInt(cursor, 10), time.Now().Unix())
		if e != nil {
			tx.Rollback()
			return e
		}
	}
	_, e = tx.Exec(`INSERT INTO app_notification_cursors VALUES(?,?) ON CONFLICT(module_id) DO UPDATE SET cursor=excluded.cursor`, module, page.Cursor)
	if e == nil {
		e = tx.Commit()
	} else {
		tx.Rollback()
	}
	if e != nil {
		return e
	}
	return nil
}

// Dial the resolved address directly, keeping HTTPS hostname validation intact.
// Resolve for every new connection, reject metadata/link-local/multicast targets,
// and never pass credentials through a system proxy or a redirect.
func webhookHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil {
			return nil, errors.New("推送地址解析失败")
		}
		for _, v := range ips {
			if (!v.IP.IsGlobalUnicast() && !v.IP.IsLoopback()) || v.IP.IsLinkLocalUnicast() {
				return nil, errors.New("推送目标地址不可用")
			}
		}
		for _, v := range ips {
			connection, e := dialer.DialContext(ctx, network, net.JoinHostPort(v.IP.String(), port))
			if e == nil {
				return connection, nil
			}
		}
		return nil, errors.New("推送目标连接失败")
	}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type outboundDelivery struct {
	ID, ChannelID, Payload string
	Revision               int64
	Attempts               int
	Cipher                 []byte
}

func (s *Store) claimOutbound(now int64) (outboundDelivery, error) {
	var d outboundDelivery
	tx, e := s.DB.Begin()
	if e != nil {
		return d, e
	}
	defer tx.Rollback()
	// Recover only expired leases. Multiple workers or a restart cannot steal
	// an active request. Recipients deduplicate with X-Yunzhan-Delivery-ID.
	if _, e = tx.Exec(`UPDATE notification_deliveries SET state=CASE WHEN attempts>=6 THEN 'failed' ELSE 'pending' END,lease_until=0,error='请求中断，接收端需按推送标识去重' WHERE state='running' AND lease_until<=?`, now); e != nil {
		return d, e
	}
	if _, e = tx.Exec(`UPDATE notification_deliveries SET state='cancelled',completed_at=? WHERE state IN ('pending','running') AND EXISTS(SELECT 1 FROM notification_channels c WHERE c.id=channel_id AND (c.enabled=0 OR c.revision!=channel_revision))`, now); e != nil {
		return d, e
	}
	e = tx.QueryRow(`SELECT d.id,d.channel_id,d.channel_revision,d.payload,d.attempts,c.credential FROM notification_deliveries d JOIN notification_channels c ON c.id=d.channel_id WHERE d.state='pending' AND d.next_attempt_at<=? AND c.enabled=1 AND c.revision=d.channel_revision ORDER BY d.rowid LIMIT 1`, now).Scan(&d.ID, &d.ChannelID, &d.Revision, &d.Payload, &d.Attempts, &d.Cipher)
	if errors.Is(e, sql.ErrNoRows) {
		if commitError := tx.Commit(); commitError != nil {
			return d, commitError
		}
		return d, e
	}
	if e != nil {
		return d, e
	}
	_, e = tx.Exec(`UPDATE notification_deliveries SET state='running',attempts=attempts+1,lease_until=? WHERE id=? AND state='pending'`, now+30, d.ID)
	if e != nil {
		return d, e
	}
	d.Attempts++
	return d, tx.Commit()
}
func (a *Server) sendOutbound(ctx context.Context, client *http.Client, d outboundDelivery) (int, string, int64) {
	raw, e := decryptCredential(a.accountSecretKey, "notification-channel:"+d.ChannelID, d.Cipher)
	if e != nil {
		return 0, "推送凭据无法解密", 0
	}
	var credential webhookCredential
	if json.Unmarshal(raw, &credential) != nil {
		return 0, "推送凭据损坏", 0
	}
	if _, e = validateWebhookURL(credential.URL); e != nil {
		return 0, "推送地址无效", 0
	}
	if len(d.Payload) > 4096 {
		return 0, "推送摘要超过限制", 0
	}
	req, e := http.NewRequestWithContext(ctx, "POST", credential.URL, bytes.NewBufferString(d.Payload))
	if e != nil {
		return 0, "推送请求无效", 0
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Yunzhan-Notifications/1.0")
	req.Header.Set("X-Yunzhan-Delivery-ID", d.ID)
	req.Header.Set("X-Yunzhan-Timestamp", timestamp)
	req.Header.Set("X-Yunzhan-Signature", webhookSignature(credential.Secret, d.ID, timestamp, []byte(d.Payload)))
	response, e := client.Do(req)
	if e != nil {
		return 0, "推送网络或证书验证失败", 0
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return response.StatusCode, "", 0
	}
	wait := int64(0)
	if seconds, e := strconv.ParseInt(response.Header.Get("Retry-After"), 10, 64); e == nil && seconds > 0 {
		wait = seconds
	}
	if at, e := http.ParseTime(response.Header.Get("Retry-After")); e == nil {
		wait = int64(time.Until(at).Seconds())
	}
	if wait > 3600 {
		wait = 3600
	}
	return response.StatusCode, fmt.Sprintf("接收端返回 HTTP %d", response.StatusCode), wait
}
func (s *Store) completeOutbound(d outboundDelivery, status int, message string, retryAfter, now int64) error {
	state, completed, next := "succeeded", now, int64(0)
	if message != "" {
		state = "failed"
		if d.Attempts < 6 && (status == 0 || status == 408 || status == 429 || status >= 500) {
			state = "pending"
			completed = 0
			delay := int64(15) << uint(d.Attempts-1)
			if retryAfter > delay {
				delay = retryAfter
			}
			next = now + delay
		}
	}
	_, e := s.DB.Exec(`UPDATE notification_deliveries SET state=?,http_status=?,error=?,next_attempt_at=?,lease_until=0,completed_at=? WHERE id=? AND state='running' AND channel_revision=?`, state, status, message, next, completed, d.ID, d.Revision)
	return e
}
func (a *Server) dispatchOutbound(ctx context.Context, client *http.Client) error {
	for n := 0; n < 8; n++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		d, e := a.Store.claimOutbound(time.Now().Unix())
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		status, message, retry := a.sendOutbound(ctx, client, d)
		if e = a.Store.completeOutbound(d, status, message, retry, time.Now().Unix()); e != nil {
			return e
		}
	}
	return nil
}
func (a *Server) StartOutboundNotifications(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		client := webhookHTTPClient()
		defer client.CloseIdleConnections()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !a.outboundMu.TryLock() {
					continue
				}
				bounded, cancel := context.WithTimeout(ctx, 40*time.Second)
				channels, e := a.Store.NotificationChannels()
				enabled := false
				for _, channel := range channels {
					enabled = enabled || channel.Enabled
				}
				// Initialize cursors even before external channels are enabled so a
				// first event immediately after configuration cannot be lost.
				collectErr := a.collectModuleNotifications(bounded)
				if e == nil && enabled {
					e = a.Store.QueueOutboundNotifications()
					// A damaged app ledger or a full queue must not prevent previously
					// queued notifications from being delivered and releasing capacity.
					deliveryErr := a.dispatchOutbound(bounded, client)
					if e == nil {
						e = deliveryErr
					}
					if e == nil {
						e = collectErr
					}
				}
				if e == nil {
					e = collectErr
				}
				// Keep completed records for 90 days; pending/failed records are never
				// silently removed. Capacity backpressure is visible in channel history.
				if e == nil {
					_, e = a.Store.DB.Exec(`DELETE FROM notification_deliveries WHERE state IN ('succeeded','cancelled') AND created_at<?`, time.Now().AddDate(0, 0, -90).Unix())
				}
				message := ""
				if e != nil {
					message = "推送事件收集或队列处理失败，请检查应用历史与队列容量"
				}
				_, _ = a.Store.DB.Exec(`UPDATE notification_dispatch_status SET last_error=?,last_check_at=? WHERE id=1`, message, Now())
				cancel()
				a.outboundMu.Unlock()
			}
		}
	}()
}
