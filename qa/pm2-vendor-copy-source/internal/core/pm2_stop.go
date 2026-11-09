package core

import (
	"errors"
	"net/http"

	"local/panel/internal/appcatalog"
)

// Published compat8/9 symbols keep their historical identities. Only the new
// exact revision claims the independently verified stop outcome.
const PM2EvidencePreservingStopAppVersion = appcatalog.PM2EvidencePreservingStopVersion

func ParsePM2ProjectsQuery(raw string) (AppModuleInput, error) {
	in, err := ParsePM2ConfigurationQuery(raw)
	if err != nil || in.PM2OperationID != "" || in.Limit > 64 {
		return AppModuleInput{}, errors.New("PM2 项目读取仅支持受管项目标识、最多64项分页和有界偏移")
	}
	if in.Limit == 0 {
		in.Limit = 32
	}
	return in, nil
}

func (a *Server) pm2ProjectsRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-modules/pm2-manager/projects", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, err := ParsePM2ProjectsQuery(r.URL.RawQuery); err != nil {
			fail(w, 400, err.Error())
			return
		}
		var out any
		if err := a.Executor.Call(r.Context(), "GET", "/v1/app-modules/pm2-manager/projects?"+r.URL.RawQuery, nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
}
