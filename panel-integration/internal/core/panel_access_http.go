package core

import (
	"net/http"
)

func (a *Server) panelAccessRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/panel-access", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		v, e := a.Store.PanelAccess()
		if e != nil {
			fail(w, 500, "读取面板访问设置失败")
			return
		}
		send(w, 200, v)
	}))
	m.HandleFunc("POST /api/panel-access/preview", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in PanelAccess
		if !decode(w, r, &in) {
			return
		}
		v, e := a.Store.ValidatePanelAccess(in)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		v.Revision++
		var result PanelAccessApplyResult
		e = a.Executor.Call(r.Context(), http.MethodPost, "/v1/panel-access/preview", PanelAccessApplyRequest{Config: v}, &result)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, result)
	}))
	m.HandleFunc("PUT /api/panel-access", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in PanelAccess
		if !decode(w, r, &in) {
			return
		}
		v, e := a.Store.ValidatePanelAccess(in)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		previous, _ := a.Store.PanelAccess()
		applied := v
		applied.Revision++
		if v.HTTPSEnabled {
			material, e := a.Store.CertificateMaterial(v.CertificateID)
			if e != nil {
				fail(w, 409, e.Error())
				return
			}
			var installed Certificate
			if e = a.Executor.Call(r.Context(), http.MethodPost, "/v1/certificates/install", material, &installed); e != nil {
				fail(w, 409, e.Error())
				return
			}
		}
		var result PanelAccessApplyResult
		if e = a.Executor.Call(r.Context(), http.MethodPost, "/v1/panel-access/apply", PanelAccessApplyRequest{Config: applied}, &result); e != nil {
			fail(w, 409, e.Error())
			return
		}
		updated, e := a.Store.CommitPanelAccess(v, u.Username)
		if e != nil {
			var rollback PanelAccessApplyResult
			_ = a.Executor.Call(r.Context(), http.MethodPost, "/v1/panel-access/apply", PanelAccessApplyRequest{Config: previous}, &rollback)
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, updated)
	}))
}
