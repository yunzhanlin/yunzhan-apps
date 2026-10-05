package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type FirewallRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
	PortFrom int    `json:"port_from"`
	PortTo   int    `json:"port_to"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
}

type FirewallConfig struct {
	Enabled       bool           `json:"enabled"`
	DefaultAction string         `json:"default_action"`
	Rules         []FirewallRule `json:"rules"`
	Revision      int64          `json:"revision"`
	UpdatedAt     string         `json:"updated_at"`
}

type FirewallStatus struct {
	Available bool   `json:"available"`
	Active    bool   `json:"active"`
	Pending   bool   `json:"pending"`
	ChangeID  string `json:"change_id,omitempty"`
	Deadline  int64  `json:"deadline,omitempty"`
	Detail    string `json:"detail"`
}

type FirewallPage struct {
	Config FirewallConfig `json:"config"`
	Status FirewallStatus `json:"status"`
}

type FirewallApplyRequest struct {
	Config   FirewallConfig `json:"config"`
	ChangeID string         `json:"change_id,omitempty"`
}

type FirewallApplyResult struct {
	Status   string `json:"status"`
	Config   string `json:"config,omitempty"`
	ChangeID string `json:"change_id,omitempty"`
	Deadline int64  `json:"deadline,omitempty"`
	Steps    []Step `json:"steps,omitempty"`
}

type FirewallConfirmRequest struct {
	ChangeID string `json:"change_id"`
}

type SSHStatus struct {
	Available              bool     `json:"available"`
	Active                 bool     `json:"active"`
	Enabled                bool     `json:"enabled"`
	Ports                  []int    `json:"ports"`
	PasswordAuthentication string   `json:"password_authentication"`
	PermitRootLogin        string   `json:"permit_root_login"`
	PubkeyAuthentication   string   `json:"pubkey_authentication"`
	MaxAuthTries           int      `json:"max_auth_tries"`
	X11Forwarding          string   `json:"x11_forwarding"`
	AllowTCPForwarding     string   `json:"allow_tcp_forwarding"`
	Warnings               []string `json:"warnings"`
	CheckedAt              string   `json:"checked_at"`
}

func (s *Store) migrateSecurity() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS security_firewall(
id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),default_action TEXT NOT NULL CHECK(default_action IN ('accept','drop')),rules_json TEXT NOT NULL DEFAULT '[]',revision INTEGER NOT NULL CHECK(revision>0),updated_at TEXT NOT NULL);
INSERT OR IGNORE INTO security_firewall(id,enabled,default_action,rules_json,revision,updated_at) VALUES(1,0,'accept','[]',1,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
CREATE TABLE IF NOT EXISTS security_firewall_pending(change_id TEXT PRIMARY KEY,config_json TEXT NOT NULL,previous_revision INTEGER NOT NULL,connection_id TEXT NOT NULL,expires_at INTEGER NOT NULL,actor TEXT NOT NULL,created_at TEXT NOT NULL);
INSERT OR IGNORE INTO schema_migrations VALUES(20,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func scanFirewall(row interface{ Scan(...any) error }) (FirewallConfig, error) {
	var v FirewallConfig
	var enabled int
	var raw string
	e := row.Scan(&enabled, &v.DefaultAction, &raw, &v.Revision, &v.UpdatedAt)
	v.Enabled = enabled == 1
	if e == nil {
		e = json.Unmarshal([]byte(raw), &v.Rules)
	}
	return v, e
}

func (s *Store) Firewall() (FirewallConfig, error) {
	return scanFirewall(s.DB.QueryRow(`SELECT enabled,default_action,rules_json,revision,updated_at FROM security_firewall WHERE id=1`))
}

func normalizeFirewall(v FirewallConfig) (FirewallConfig, error) {
	v.DefaultAction = strings.ToLower(strings.TrimSpace(v.DefaultAction))
	if v.DefaultAction != "accept" && v.DefaultAction != "drop" {
		return v, errors.New("默认策略只能是允许或拒绝")
	}
	if len(v.Rules) > 100 {
		return v, errors.New("自定义规则最多 100 条")
	}
	seen := map[string]bool{}
	for i := range v.Rules {
		r := &v.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		if r.ID == "" {
			r.ID = ID()
		}
		if !ValidID(r.ID) || seen[r.ID] {
			return v, errors.New("防火墙规则标识无效或重复")
		}
		seen[r.ID] = true
		if len([]rune(r.Name)) < 1 || len([]rune(r.Name)) > 40 {
			return v, errors.New("规则名称应为 1–40 个字符")
		}
		r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return v, errors.New("规则协议只能是 TCP 或 UDP")
		}
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		if r.Action != "accept" && r.Action != "drop" {
			return v, errors.New("规则动作只能是允许或拒绝")
		}
		r.Source = strings.TrimSpace(r.Source)
		if r.Source == "" {
			r.Source = "0.0.0.0/0"
		}
		prefix, e := netip.ParsePrefix(r.Source)
		if e != nil {
			return v, errors.New("来源地址必须使用 CIDR 格式")
		}
		r.Source = prefix.Masked().String()
		if r.PortFrom < 1 || r.PortFrom > 65535 || r.PortTo < r.PortFrom || r.PortTo > 65535 {
			return v, errors.New("端口范围必须在 1–65535 之间")
		}
	}
	return v, nil
}

func (s *Store) ValidateFirewall(v FirewallConfig) (FirewallConfig, error) {
	return normalizeFirewall(v)
}

func (s *Store) BeginFirewallChange(v FirewallConfig, changeID, connectionID, actor string, expires int64) error {
	v, e := normalizeFirewall(v)
	if e != nil {
		return e
	}
	if !ValidID(changeID) || expires <= time.Now().Unix() {
		return errors.New("防火墙确认信息无效")
	}
	raw, _ := json.Marshal(v)
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`DELETE FROM security_firewall_pending`); e != nil {
		return e
	}
	if _, e = tx.Exec(`INSERT INTO security_firewall_pending(change_id,config_json,previous_revision,connection_id,expires_at,actor,created_at) VALUES(?,?,?,?,?,?,?)`, changeID, string(raw), v.Revision, connectionID, expires, actor, Now()); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) FirewallPending() (changeID, connectionID string, expires int64, err error) {
	err = s.DB.QueryRow(`SELECT change_id,connection_id,expires_at FROM security_firewall_pending LIMIT 1`).Scan(&changeID, &connectionID, &expires)
	return
}

func (s *Store) ConfirmFirewall(changeID, connectionID, actor string) (FirewallConfig, error) {
	var raw, originalConnection, savedActor string
	var revision, expires int64
	e := s.DB.QueryRow(`SELECT config_json,previous_revision,connection_id,expires_at,actor FROM security_firewall_pending WHERE change_id=?`, changeID).Scan(&raw, &revision, &originalConnection, &expires, &savedActor)
	if e != nil {
		return FirewallConfig{}, errors.New("防火墙变更不存在或已经恢复")
	}
	if expires < time.Now().Unix() {
		return FirewallConfig{}, errors.New("确认期限已过，防火墙将自动恢复")
	}
	if connectionID == "" || connectionID == originalConnection {
		return FirewallConfig{}, errors.New("请从新的管理连接确认防火墙")
	}
	var v FirewallConfig
	if e = json.Unmarshal([]byte(raw), &v); e != nil {
		return v, e
	}
	rules, _ := json.Marshal(v.Rules)
	tx, e := s.DB.Begin()
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	result, e := tx.Exec(`UPDATE security_firewall SET enabled=?,default_action=?,rules_json=?,revision=revision+1,updated_at=? WHERE id=1 AND revision=?`, v.Enabled, v.DefaultAction, string(rules), Now(), revision)
	if e != nil {
		return v, e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return v, errors.New("防火墙配置已变化，请重新操作")
	}
	if _, e = tx.Exec(`DELETE FROM security_firewall_pending WHERE change_id=?`, changeID); e != nil {
		return v, e
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,?,?)`, actor, "security.firewall.update", fmt.Sprintf("revision:%d", revision+1), "success", Now()); e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return v, e
	}
	return s.Firewall()
}

func (s *Store) PruneExpiredFirewallPending() {
	_, _ = s.DB.Exec(`DELETE FROM security_firewall_pending WHERE expires_at<?`, time.Now().Unix())
}

func (s *Store) ClearFirewallPending(changeID string) {
	_, _ = s.DB.Exec(`DELETE FROM security_firewall_pending WHERE change_id=?`, changeID)
}

func uniqueSortedInts(values []int) []int {
	seen := map[int]bool{}
	for _, value := range values {
		if value > 0 && value <= 65535 {
			seen[value] = true
		}
	}
	out := make([]int, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}
