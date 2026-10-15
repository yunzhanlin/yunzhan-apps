package core

import (
	"net/http"
	"time"
)

func (a *Server) monitoringRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/monitor/history", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		rangeValue := r.URL.Query().Get("range")
		if rangeValue == "" {
			rangeValue = "1h"
		}
		points, e := a.Store.MonitorHistory(rangeValue, time.Now())
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		settings, e := a.Store.MonitoringSettings()
		if e != nil {
			fail(w, 500, "读取监控设置失败")
			return
		}
		send(w, 200, map[string]any{"range": rangeValue, "points": points, "settings": settings, "generated_at": Now()})
	}))
	m.HandleFunc("GET /api/monitor/settings", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		settings, e := a.Store.MonitoringSettings()
		if e != nil {
			fail(w, 500, "读取监控设置失败")
			return
		}
		send(w, 200, settings)
	}))
	m.HandleFunc("PUT /api/monitor/settings", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var settings MonitorSettings
		if !decode(w, r, &settings) {
			return
		}
		updated, e := a.Store.UpdateMonitoringSettings(settings, u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		if e = a.Store.CleanupMonitoring(time.Now()); e != nil {
			fail(w, 500, "设置已保存，但历史清理尚未完成")
			return
		}
		send(w, 200, updated)
	}))
	m.HandleFunc("GET /api/monitor/alerts", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		alerts, events, e := a.Store.MonitorAlerts()
		if e != nil {
			fail(w, 500, "读取监控告警失败")
			return
		}
		send(w, 200, map[string]any{"alerts": alerts, "events": events})
	}))
	m.HandleFunc("GET /api/monitor/services", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		services, e := a.Store.MonitorServices()
		if e != nil {
			fail(w, 500, "读取服务状态失败")
			return
		}
		send(w, 200, map[string]any{"services": services})
	}))
	m.HandleFunc("POST /api/monitor/alerts/{id}/acknowledge", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if e := a.Store.AcknowledgeMonitorAlert(r.PathValue("id"), time.Now(), u.Username); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, map[string]bool{"ok": true})
	}))
}
