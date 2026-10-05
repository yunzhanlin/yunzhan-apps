package core

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type LoginEvent struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	IP        string `json:"ip"`
	Result    string `json:"result"`
	CreatedAt string `json:"created_at"`
}

func (s *Store) migrateLoginEvents() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS login_events(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,ip TEXT NOT NULL,result TEXT NOT NULL CHECK(result IN ('success','denied','rate_limited')),created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS login_events_recent ON login_events(id DESC);
INSERT OR IGNORE INTO schema_migrations VALUES(31,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func clientRemoteIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return "unknown"
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return "unknown"
	}
	if ip.IsLoopback() && r.Header.Get("X-Panel-Connection") == "public-http" {
		forwarded, parseErr := netip.ParseAddr(r.Header.Get("X-Real-IP"))
		if parseErr == nil && !forwarded.IsUnspecified() {
			return forwarded.Unmap().String()
		}
	}
	return ip.Unmap().String()
}

func (s *Store) RecordLoginEvent(username, ip, result string) error {
	if result != "success" && result != "denied" && result != "rate_limited" {
		return nil
	}
	username = strings.TrimSpace(username)
	if len(username) > 32 || username == "" {
		username = "unknown"
	}
	if parsed, e := netip.ParseAddr(ip); e != nil {
		ip = "unknown"
	} else {
		ip = parsed.Unmap().String()
	}
	_, e := s.DB.Exec(`INSERT INTO login_events(username,ip,result,created_at) VALUES(?,?,?,?)`, username, ip, result, Now())
	if e != nil {
		return e
	}
	_, e = s.DB.Exec(`DELETE FROM login_events WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM login_events) OR created_at < ?`, time.Now().UTC().AddDate(0, 0, -90).Format(time.RFC3339))
	return e
}

func (s *Store) LoginEvents(limit int) ([]LoginEvent, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	rows, e := s.DB.Query(`SELECT id,username,ip,result,created_at FROM login_events ORDER BY id DESC LIMIT ?`, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []LoginEvent{}
	for rows.Next() {
		var v LoginEvent
		if e = rows.Scan(&v.ID, &v.Username, &v.IP, &v.Result, &v.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (a *Server) loginEventRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/security/login-events", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		items, e := a.Store.LoginEvents(100)
		if e != nil {
			fail(w, 500, "登录记录不可读取")
			return
		}
		send(w, 200, items)
	}))
}
