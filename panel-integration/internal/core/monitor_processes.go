package core

import (
	"context"
	"net/http"
	"time"
)

type MonitorProcess struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	Memory     uint64  `json:"memory"`
	ReadRate   float64 `json:"read_rate"`
	WriteRate  float64 `json:"write_rate"`
	State      string  `json:"state"`
}

func (a *Server) monitorProcessRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/monitor/processes", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var out struct {
			Processes      []MonitorProcess `json:"processes"`
			TCPConnections *int             `json:"tcp_connections"`
		}
		if err := a.Executor.Call(ctx, http.MethodGet, "/v1/monitor/processes", nil, &out); err != nil {
			fail(w, 503, "进程排行暂不可读取")
			return
		}
		if out.Processes == nil {
			out.Processes = []MonitorProcess{}
		}
		send(w, 200, out)
	}))
}
