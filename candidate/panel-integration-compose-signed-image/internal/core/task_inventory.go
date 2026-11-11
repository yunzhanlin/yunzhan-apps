package core

import (
	"local/panel/internal/appcatalog"
	"net/http"
)

const TaskInventoryAppVersion = appcatalog.TaskInventoryVersion
const TaskSysVStartupAppVersion = appcatalog.TaskSysVStartupVersion
const TaskOpenSSHInventoryAppVersion = appcatalog.TaskOpenSSHInventoryVersion

func TaskInventoryVersionSupported(version string) bool {
	return version == TaskInventoryAppVersion || TaskSysVStartupSupported(version)
}

func TaskSysVStartupSupported(version string) bool {
	return version == TaskSysVStartupAppVersion || version == TaskOpenSSHInventoryAppVersion
}

func ValidTaskInventoryView(view string) bool {
	switch view {
	case "services", "startup", "sysv-startup", "accounts", "cron", "ssh", "network":
		return true
	default:
		return false
	}
}

func (a *Server) taskInventoryRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-modules/task-manager/inventory/{view}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		view := r.PathValue("view")
		if !ValidTaskInventoryView(view) {
			fail(w, http.StatusNotFound, "未知的任务管理清单")
			return
		}
		var out map[string]any
		err := a.Executor.Call(r.Context(), http.MethodGet, "/v1/app-modules/task-manager/inventory/"+view, nil, &out)
		if err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		send(w, http.StatusOK, out)
	}))
}
