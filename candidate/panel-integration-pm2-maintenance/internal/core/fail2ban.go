package core

import (
	"net/http"
	"net/netip"
	"regexp"
)

type Fail2banJail struct {
	Name            string   `json:"name"`
	CurrentlyBanned int      `json:"currently_banned"`
	TotalBanned     int      `json:"total_banned"`
	BannedIPs       []string `json:"banned_ips"`
}
type Fail2banStatus struct {
	Installed bool           `json:"installed"`
	Active    bool           `json:"active"`
	Jails     []Fail2banJail `json:"jails"`
	Detail    string         `json:"detail,omitempty"`
}

var fail2banJailName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (a *Server) fail2banRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/security/fail2ban", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var result Fail2banStatus
		if e := a.Executor.Call(r.Context(), "GET", "/v1/security/fail2ban", nil, &result); e != nil {
			fail(w, 503, "Fail2ban 状态不可读取")
			return
		}
		send(w, 200, result)
	}))
	m.HandleFunc("POST /api/security/fail2ban/unban", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var input struct {
			Jail string `json:"jail"`
			IP   string `json:"ip"`
		}
		if !decode(w, r, &input) {
			return
		}
		if !fail2banJailName.MatchString(input.Jail) {
			fail(w, 400, "无效 Jail 名称")
			return
		}
		ip, e := netip.ParseAddr(input.IP)
		if e != nil {
			fail(w, 400, "无效 IP 地址")
			return
		}
		input.IP = ip.Unmap().String()
		var result map[string]any
		e = a.Executor.Call(r.Context(), "POST", "/v1/security/fail2ban/unban", input, &result)
		state := "success"
		if e != nil {
			state = "failed"
		}
		_ = a.Store.Audit(u.Username, "security.fail2ban.unban", input.Jail+":"+input.IP, state)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, result)
	}))
}
