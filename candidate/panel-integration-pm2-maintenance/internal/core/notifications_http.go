package core

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
)

func (a *Server) notificationRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/notification-settings", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		v, e := a.Store.NotificationSettings()
		if e != nil {
			fail(w, 500, "读取通知设置失败")
			return
		}
		send(w, 200, v)
	}))
	m.HandleFunc("PUT /api/notification-settings", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in NotificationSettings
		if !decode(w, r, &in) {
			return
		}
		v, e := a.Store.SaveNotificationSettings(in, in.Revision)
		if e != nil {
			fail(w, 409, "通知设置已变化或保留天数无效")
			return
		}
		_ = a.Store.Audit(u.Username, "notification.settings", "notifications", "success")
		send(w, 200, v)
	}))
	m.HandleFunc("GET /api/notifications", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, unread, e := a.Store.Notifications(limit)
		if e != nil {
			fail(w, 500, "读取站内通知失败")
			return
		}
		send(w, 200, map[string]any{"notifications": items, "unread": unread})
	}))
	m.HandleFunc("POST /api/notifications/{id}/read", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct{}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		if e := a.Store.ReadNotification(id); e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				fail(w, 404, "通知不存在")
			} else {
				fail(w, 500, "更新通知失败")
			}
			return
		}
		_ = a.Store.Audit(u.Username, "notification.read", id, "success")
		send(w, 200, map[string]bool{"read": true})
	}))
	m.HandleFunc("POST /api/notifications/read-all", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct{}
		if !decode(w, r, &in) {
			return
		}
		if e := a.Store.ReadAllNotifications(); e != nil {
			fail(w, 500, "更新通知失败")
			return
		}
		_ = a.Store.Audit(u.Username, "notification.read_all", "notifications", "success")
		send(w, 200, map[string]bool{"read": true})
	}))
}
