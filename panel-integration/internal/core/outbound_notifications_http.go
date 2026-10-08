package core

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

func (a *Server) outboundNotificationRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/notification-channels", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		channels, e := a.Store.NotificationChannels()
		if e != nil {
			fail(w, 500, "读取推送通道失败")
			return
		}
		var message, at string
		if e = a.Store.DB.QueryRow(`SELECT last_error,last_check_at FROM notification_dispatch_status WHERE id=1`).Scan(&message, &at); e != nil {
			fail(w, 500, "读取推送状态失败")
			return
		}
		send(w, 200, map[string]any{"channels": channels, "kinds": outboundKinds, "last_error": message, "last_check_at": at})
	}))
	for _, method := range []string{"POST", "PUT"} {
		pattern := method + " /api/notification-channels"
		if method == "PUT" {
			pattern += "/{id}"
		}
		m.HandleFunc(pattern, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			var in NotificationChannelInput
			if !decode(w, r, &in) {
				return
			}
			if !a.outboundMu.TryLock() {
				fail(w, 409, "推送处理中，请稍后保存")
				return
			}
			defer a.outboundMu.Unlock()
			if in.Enabled {
				ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
				err := a.collectModuleNotifications(ctx)
				cancel()
				if err != nil {
					fail(w, 409, "应用事件源暂不可用，请稍后保存；通道尚未变更")
					return
				}
			}
			channel, e := a.Store.SaveNotificationChannel(r.PathValue("id"), in)
			if e != nil {
				fail(w, 409, e.Error())
				return
			}
			// The database has already cancelled the old revision. Interrupt its
			// active HTTP or SMTP request, without waiting for the receiver timeout.
			// A receiver may have processed bytes already sent, so dedup remains
			// necessary; cancellation cannot revoke external side effects.
			if cancel := a.outboundCancels[channel.ID]; cancel != nil {
				cancel()
			}
			_ = a.Store.Audit(u.Username, "notification.channel.save", channel.ID, "success")
			send(w, 200, channel)
		}))
	}
	m.HandleFunc("GET /api/notification-channels/{id}/deliveries", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		if !ValidID(id) {
			fail(w, 400, "通道标识无效")
			return
		}
		items, e := a.Store.NotificationDeliveryHistory(id)
		if e != nil {
			fail(w, 500, "读取推送历史失败")
			return
		}
		send(w, 200, map[string]any{"deliveries": items})
	}))
	m.HandleFunc("POST /api/notification-channels/{id}/test", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Revision int64 `json:"revision"`
			Daily    bool  `json:"daily,omitempty"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if !ValidID(id) {
			fail(w, 400, "通道标识无效")
			return
		}
		if !a.outboundMu.TryLock() {
			fail(w, 409, "推送处理中，请稍后测试")
			return
		}
		defer a.outboundMu.Unlock()
		tx, e := a.Store.DB.Begin()
		if e != nil {
			fail(w, 500, "创建测试推送失败")
			return
		}
		defer tx.Rollback()
		var revision int64
		var enabled bool
		var kindsRaw string
		if tx.QueryRow(`SELECT revision,enabled,kinds FROM notification_channels WHERE id=?`, id).Scan(&revision, &enabled, &kindsRaw) != nil || !enabled || revision != in.Revision {
			fail(w, 409, "请启用通道并读取当前配置版本")
			return
		}
		var recent int
		_ = tx.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=? AND created_at>?`, id, time.Now().Add(-time.Minute).Unix()).Scan(&recent)
		if recent >= 30 {
			fail(w, 429, "推送测试过于频繁")
			return
		}
		message := safeOutboundMessage(Notification{ID: ID(), Kind: "test", Severity: "info", CreatedAt: time.Now().Unix()})
		message.Test = true
		if in.Daily {
			var kinds []string
			if json.Unmarshal([]byte(kindsRaw), &kinds) != nil || !containsMenu(kinds, "daily") {
				fail(w, 409, "该通道未选择每日运维报告，未发送测试日报")
				return
			}
			var day, raw string
			if tx.QueryRow(`SELECT day,report FROM app_daily_reports ORDER BY day DESC LIMIT 1`).Scan(&day, &raw) != nil {
				fail(w, 409, "尚无保存的日报，请先在每日运维报告应用生成报告")
				return
			}
			var summary OutboundDailySummary
			if _, err := time.Parse("2006-01-02", day); err != nil || json.Unmarshal([]byte(raw), &summary) != nil {
				fail(w, 409, "保存的日报无法读取，未发送测试日报")
				return
			}
			summary.Day = day
			message = safeOutboundMessage(Notification{ID: message.EventID, Kind: "daily", Severity: "info", CreatedAt: message.CreatedAt})
			message.Report, message.Test = &summary, true
		}
		if e = insertOutbound(tx, id, revision, message); e != nil {
			fail(w, 409, e.Error())
			return
		}
		if e = tx.Commit(); e != nil {
			fail(w, 500, "测试推送保存失败")
			return
		}
		_ = a.Store.Audit(u.Username, "notification.channel.test", id, "queued")
		send(w, 202, map[string]any{"event_id": message.EventID, "state": "pending"})
	}))
	m.HandleFunc("POST /api/notification-channels/{id}/retry/{delivery}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Revision int64 `json:"revision"`
		}
		if !decode(w, r, &in) {
			return
		}
		id, delivery := r.PathValue("id"), r.PathValue("delivery")
		if !ValidID(id) || !ValidID(delivery) {
			fail(w, 400, "推送标识无效")
			return
		}
		if !a.outboundMu.TryLock() {
			fail(w, 409, "推送处理中，请稍后重试")
			return
		}
		defer a.outboundMu.Unlock()
		result, e := a.Store.DB.Exec(`UPDATE notification_deliveries SET state='pending',attempts=0,error='',next_attempt_at=?,completed_at=0 WHERE id=? AND channel_id=? AND state='failed' AND channel_revision=? AND EXISTS(SELECT 1 FROM notification_channels c WHERE c.id=channel_id AND c.enabled=1 AND c.revision=channel_revision)`, time.Now().Add(15*time.Second).Unix(), delivery, id, in.Revision)
		if e != nil {
			fail(w, 500, "重试保存失败")
			return
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			fail(w, 409, "记录已变化或通道配置已更新")
			return
		}
		_ = a.Store.Audit(u.Username, "notification.channel.retry", delivery, "queued")
		send(w, 202, map[string]string{"state": "pending"})
	}))
}
