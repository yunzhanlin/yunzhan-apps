package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type SiteSecurityFinding struct {
	Path        string `json:"path"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}
type SiteSecurityScan struct {
	SiteID   string                `json:"site_id"`
	Domain   string                `json:"domain"`
	Status   string                `json:"status"`
	Error    string                `json:"error,omitempty"`
	Findings []SiteSecurityFinding `json:"findings"`
}
type SiteSecurityScanReport struct {
	ScannedAt string             `json:"scanned_at"`
	Partial   bool               `json:"partial"`
	Sites     []SiteSecurityScan `json:"sites"`
}

func (s *Store) migrateSiteSecurityScan() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS site_security_scans(id INTEGER PRIMARY KEY CHECK(id=1),scanned_at TEXT NOT NULL,report_json TEXT NOT NULL);
INSERT OR IGNORE INTO schema_migrations VALUES(32,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}
func (s *Store) LastSiteSecurityScan() (SiteSecurityScanReport, error) {
	var report SiteSecurityScanReport
	var raw string
	e := s.DB.QueryRow(`SELECT report_json FROM site_security_scans WHERE id=1`).Scan(&raw)
	if e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return SiteSecurityScanReport{Sites: []SiteSecurityScan{}}, nil
		}
		return report, e
	}
	e = json.Unmarshal([]byte(raw), &report)
	return report, e
}
func (s *Store) SaveSiteSecurityScan(report SiteSecurityScanReport) error {
	raw, e := json.Marshal(report)
	if e != nil {
		return e
	}
	_, e = s.DB.Exec(`INSERT INTO site_security_scans(id,scanned_at,report_json) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET scanned_at=excluded.scanned_at,report_json=excluded.report_json`, report.ScannedAt, string(raw))
	return e
}
func (a *Server) siteSecurityScanRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/security/site-scan", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		report, e := a.Store.LastSiteSecurityScan()
		if e != nil {
			fail(w, 500, "网站扫描结果不可读取")
			return
		}
		send(w, 200, report)
	}))
	m.HandleFunc("POST /api/security/site-scan", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !a.securityScanMu.TryLock() {
			fail(w, 409, "网站安全扫描正在运行")
			return
		}
		defer a.securityScanMu.Unlock()
		sites, e := a.Store.Sites()
		if e != nil {
			fail(w, 500, "站点列表不可读取")
			return
		}
		report := SiteSecurityScanReport{ScannedAt: Now(), Sites: []SiteSecurityScan{}}
		scanContext, cancelScan := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancelScan()
		if len(sites) > 100 {
			sites = sites[:100]
			report.Partial = true
		}
		for _, site := range sites {
			if scanContext.Err() != nil {
				report.Partial = true
				break
			}
			if site.Status == "provisioning" {
				continue
			}
			var scan SiteSecurityScan
			siteContext, cancelSite := context.WithTimeout(scanContext, 3*time.Second)
			e = a.Executor.Call(siteContext, "GET", "/v1/sites/"+site.ID+"/security-scan", nil, &scan)
			cancelSite()
			if e != nil {
				scan = SiteSecurityScan{Status: "unavailable", Error: e.Error(), Findings: []SiteSecurityFinding{}}
				report.Partial = true
			}
			scan.SiteID = site.ID
			scan.Domain = site.Domain
			if scan.Status == "partial" {
				report.Partial = true
			}
			report.Sites = append(report.Sites, scan)
		}
		if e = a.Store.SaveSiteSecurityScan(report); e != nil {
			fail(w, 500, "网站扫描结果保存失败")
			return
		}
		_ = a.Store.Audit(u.Username, "security.site-scan", "sites", "success")
		send(w, 200, report)
	}))
}
