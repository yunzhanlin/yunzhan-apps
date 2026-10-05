package core

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
)

func (a *Server) hydrateScheduleDatabaseTarget(ctx context.Context, v *Schedule) error {
	if v.Kind != "database_backup" || v.DatabaseEngine != "mariadb" {
		if v.Kind == "database_backup" {
			v.DatabaseEngine = "mysql"
		} else {
			v.DatabaseEngine = ""
		}
		v.InstanceID, v.InstanceName, v.ReleaseID = "", "", ""
		return nil
	}
	var databases struct {
		Databases []MariaDBDatabase `json:"databases"`
	}
	if e := a.Executor.Call(ctx, http.MethodGet, "/v1/mariadb/databases", nil, &databases); e != nil {
		return errors.New("无法核对 MariaDB 计划目标")
	}
	var instances struct {
		Instances []MariaDBInstance `json:"instances"`
	}
	if e := a.Executor.Call(ctx, http.MethodGet, "/v1/mariadb/instances", nil, &instances); e != nil {
		return errors.New("无法核对 MariaDB 实例")
	}
	var database *MariaDBDatabase
	for i := range databases.Databases {
		if databases.Databases[i].ID == v.TargetID {
			database = &databases.Databases[i]
			break
		}
	}
	if database == nil {
		return errors.New("MariaDB 计划目标不存在")
	}
	var instance *MariaDBInstance
	for i := range instances.Instances {
		if instances.Instances[i].ID == database.InstanceID {
			instance = &instances.Instances[i]
			break
		}
	}
	if instance == nil || instance.Status != "running" {
		return errors.New("目标 MariaDB 实例未运行")
	}
	v.TargetName, v.InstanceID, v.InstanceName, v.ReleaseID = database.Name, instance.ID, instance.Name, instance.ReleaseID
	return nil
}

func (a *Server) scheduleRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/schedules", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		items, e := a.Store.Schedules()
		if e != nil {
			fail(w, 500, "读取计划任务失败")
			return
		}
		send(w, 200, map[string]any{"schedules": items})
	}))
	m.HandleFunc("POST /api/schedules", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in Schedule
		if !decode(w, r, &in) {
			return
		}
		if e := a.hydrateScheduleDatabaseTarget(r.Context(), &in); e != nil {
			fail(w, 409, e.Error())
			return
		}
		created, e := a.Store.CreateSchedule(in, u.Username, time.Now())
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 201, created)
	}))
	m.HandleFunc("PUT /api/schedules/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in Schedule
		if !decode(w, r, &in) {
			return
		}
		if e := a.hydrateScheduleDatabaseTarget(r.Context(), &in); e != nil {
			fail(w, 409, e.Error())
			return
		}
		updated, e := a.Store.UpdateSchedule(r.PathValue("id"), in, u.Username, time.Now())
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, updated)
	}))
	m.HandleFunc("DELETE /api/schedules/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Revision    int64  `json:"revision"`
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		if e := a.Store.DeleteSchedule(r.PathValue("id"), in.Revision, in.ConfirmName, u.Username, time.Now()); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, map[string]bool{"ok": true})
	}))
	m.HandleFunc("POST /api/schedules/{id}/run", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct{}
		if !decode(w, r, &in) {
			return
		}
		run, e := a.Store.QueueScheduleRun(r.PathValue("id"), "manual", u.Username, time.Now())
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, run)
	}))
	m.HandleFunc("GET /api/schedules/runs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		runs, e := a.Store.ScheduleRuns(limit)
		if e != nil {
			fail(w, 500, "读取计划运行记录失败")
			return
		}
		send(w, 200, map[string]any{"runs": runs})
	}))
}
