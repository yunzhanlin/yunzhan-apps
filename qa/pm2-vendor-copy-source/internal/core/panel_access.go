package core

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"regexp"
	"strings"
	"time"
)

type PanelAccess struct {
	Domain        string   `json:"domain"`
	Port          int      `json:"port"`
	CertificateID string   `json:"certificate_id,omitempty"`
	AllowedCIDRs  []string `json:"allowed_cidrs"`
	HTTPSEnabled  bool     `json:"https_enabled"`
	HTTPEnabled   bool     `json:"http_enabled"`
	HTTPIP        string   `json:"http_ip"`
	HTTPPort      int      `json:"http_port"`
	HTTPEntry     string   `json:"http_entry"`
	Revision      int64    `json:"revision"`
	UpdatedAt     string   `json:"updated_at"`
}

type PanelAccessApplyRequest struct {
	Config PanelAccess `json:"config"`
}

type PanelAccessApplyResult struct {
	Status string `json:"status"`
	Config string `json:"config,omitempty"`
	Steps  []Step `json:"steps,omitempty"`
}

func (s *Store) migratePanelAccess() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS panel_access(
id INTEGER PRIMARY KEY CHECK(id=1),domain TEXT NOT NULL,certificate_id TEXT NOT NULL DEFAULT '',allowed_cidrs TEXT NOT NULL DEFAULT '[]',https_enabled INTEGER NOT NULL CHECK(https_enabled IN (0,1)),revision INTEGER NOT NULL CHECK(revision>0),updated_at TEXT NOT NULL);
INSERT OR IGNORE INTO panel_access(id,domain,allowed_cidrs,https_enabled,revision,updated_at) VALUES(1,'panel.localhost','[]',0,1,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
INSERT OR IGNORE INTO schema_migrations VALUES(19,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	var n int
	if e = s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=34`).Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return s.migratePanelPublicHTTP()
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`ALTER TABLE panel_access ADD COLUMN port INTEGER NOT NULL DEFAULT 19443 CHECK(port BETWEEN 1024 AND 65535);
INSERT INTO schema_migrations VALUES(34,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	return s.migratePanelPublicHTTP()
}

func (s *Store) migratePanelPublicHTTP() error {
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=36`).Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return s.ensurePanelHTTPEntry()
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`ALTER TABLE panel_access ADD COLUMN http_enabled INTEGER NOT NULL DEFAULT 0 CHECK(http_enabled IN (0,1));
ALTER TABLE panel_access ADD COLUMN http_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE panel_access ADD COLUMN http_port INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_access ADD COLUMN http_entry TEXT NOT NULL DEFAULT '';
INSERT INTO schema_migrations VALUES(36,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	return s.ensurePanelHTTPEntry()
}

const panelEntryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

func GeneratePanelEntry() (string, error) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		index, e := rand.Int(rand.Reader, big.NewInt(int64(len(panelEntryAlphabet))))
		if e != nil {
			return "", e
		}
		b.WriteByte(panelEntryAlphabet[index.Int64()])
	}
	return b.String(), nil
}

func (s *Store) ensurePanelHTTPEntry() error {
	entry, e := GeneratePanelEntry()
	if e != nil {
		return e
	}
	_, e = s.DB.Exec(`UPDATE panel_access SET http_entry=? WHERE id=1 AND http_entry=''`, entry)
	return e
}

func scanPanelAccess(row interface{ Scan(...any) error }) (PanelAccess, error) {
	var v PanelAccess
	var raw string
	var enabled, httpEnabled int
	e := row.Scan(&v.Domain, &v.Port, &v.CertificateID, &raw, &enabled, &httpEnabled, &v.HTTPIP, &v.HTTPPort, &v.HTTPEntry, &v.Revision, &v.UpdatedAt)
	if e == nil {
		e = json.Unmarshal([]byte(raw), &v.AllowedCIDRs)
	}
	v.HTTPSEnabled = enabled == 1
	v.HTTPEnabled = httpEnabled == 1
	return v, e
}

func (s *Store) PanelAccess() (PanelAccess, error) {
	return scanPanelAccess(s.DB.QueryRow(`SELECT domain,port,certificate_id,allowed_cidrs,https_enabled,http_enabled,http_ip,http_port,http_entry,revision,updated_at FROM panel_access WHERE id=1`))
}

var panelHTTPEntryPattern = regexp.MustCompile(`^[A-Za-z0-9]{8,10}$`)

func normalizePanelAccess(v PanelAccess) (PanelAccess, error) {
	v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
	if v.Port == 0 {
		v.Port = 19443
	}
	if v.Port < 1024 || v.Port > 65535 || map[int]bool{19100: true, 19101: true, 19102: true, 22: true, 80: true, 443: true}[v.Port] {
		return v, errors.New("面板端口需在 1024–65535，且不能占用保留端口")
	}
	if !ValidDomain(v.Domain) {
		return v, errors.New("面板域名无效")
	}
	if len(v.AllowedCIDRs) > 20 {
		return v, errors.New("访问网段最多 20 条")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range v.AllowedCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, e := net.ParseCIDR(raw)
		if e != nil {
			return v, errors.New("访问网段必须使用 CIDR 格式")
		}
		value := network.String()
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	v.AllowedCIDRs = out
	if v.HTTPSEnabled && !ValidID(v.CertificateID) {
		return v, errors.New("启用 HTTPS 前请选择证书")
	}
	if !v.HTTPSEnabled {
		v.CertificateID = ""
	}
	if v.HTTPEnabled {
		ip := net.ParseIP(strings.TrimSpace(v.HTTPIP))
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return v, errors.New("HTTP 入口必须填写服务器 IPv4 地址")
		}
		v.HTTPIP = ip.String()
		if v.HTTPPort < 1024 || v.HTTPPort > 65535 || v.HTTPPort == v.Port || map[int]bool{19100: true, 19101: true, 19102: true, 22: true, 80: true, 443: true}[v.HTTPPort] {
			return v, errors.New("HTTP 入口端口无效或与现有入口冲突")
		}
		if !panelHTTPEntryPattern.MatchString(v.HTTPEntry) {
			return v, errors.New("HTTP 安全入口须为 8–10 位字母和数字")
		}
	} else {
		v.HTTPIP, v.HTTPPort = "", 0
		if v.HTTPEntry != "" && !panelHTTPEntryPattern.MatchString(v.HTTPEntry) {
			return v, errors.New("HTTP 安全入口须为 8–10 位字母和数字")
		}
	}
	return v, nil
}

func (s *Store) ValidatePanelAccess(v PanelAccess) (PanelAccess, error) {
	v, e := normalizePanelAccess(v)
	if e != nil {
		return v, e
	}
	if v.HTTPSEnabled {
		cert, e := s.Certificate(v.CertificateID)
		if e != nil {
			return v, errors.New("面板证书不存在或不可读取")
		}
		if e = cert.ValidateDomains(v.Domain, nil, time.Now()); e != nil {
			return v, e
		}
	}
	return v, nil
}

func (s *Store) CommitPanelAccess(v PanelAccess, actor string) (PanelAccess, error) {
	v, e := s.ValidatePanelAccess(v)
	if e != nil {
		return v, e
	}
	raw, _ := json.Marshal(v.AllowedCIDRs)
	now := Now()
	result, e := s.DB.Exec(`UPDATE panel_access SET domain=?,port=?,certificate_id=?,allowed_cidrs=?,https_enabled=?,http_enabled=?,http_ip=?,http_port=?,http_entry=?,revision=revision+1,updated_at=? WHERE id=1 AND revision=?`, v.Domain, v.Port, v.CertificateID, string(raw), v.HTTPSEnabled, v.HTTPEnabled, v.HTTPIP, v.HTTPPort, v.HTTPEntry, now, v.Revision)
	if e != nil {
		return v, e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return v, errors.New("面板访问设置已变化，请刷新后重试")
	}
	_ = s.Audit(actor, "panel.access.update", v.Domain, "success")
	return s.PanelAccess()
}
