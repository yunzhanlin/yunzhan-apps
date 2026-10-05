package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net/mail"
	"sort"
	"strings"
	"time"
)

func (s *Store) migrateACME() error {
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=9`).Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return nil
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`CREATE TABLE acme_accounts(id TEXT PRIMARY KEY,provider TEXT NOT NULL UNIQUE,email TEXT NOT NULL,key_cipher BLOB NOT NULL,account_url TEXT NOT NULL DEFAULT '',terms_url TEXT NOT NULL,terms_accepted_at TEXT NOT NULL,created_at TEXT NOT NULL);
 CREATE TABLE acme_orders(id TEXT PRIMARY KEY,site_id TEXT NOT NULL REFERENCES sites(id),account_id TEXT NOT NULL REFERENCES acme_accounts(id),domains TEXT NOT NULL,state TEXT NOT NULL,phase TEXT NOT NULL DEFAULT 'prepare',order_url TEXT NOT NULL DEFAULT '',key_cipher BLOB NOT NULL,certificate_id TEXT NOT NULL DEFAULT '',prepare_job TEXT NOT NULL DEFAULT '',deploy_job TEXT NOT NULL DEFAULT '',baseline_tls TEXT NOT NULL,terms_url TEXT NOT NULL,auto_renew INTEGER NOT NULL,redirect INTEGER NOT NULL,attempt INTEGER NOT NULL DEFAULT 1,error TEXT NOT NULL DEFAULT '',steps TEXT NOT NULL DEFAULT '[]',idempotency_key TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
 CREATE UNIQUE INDEX one_active_acme_order ON acme_orders(site_id) WHERE state IN ('queued','running');
 CREATE TABLE acme_challenges(order_id TEXT NOT NULL REFERENCES acme_orders(id),domain TEXT NOT NULL,token TEXT NOT NULL,response TEXT NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(domain,token));
 CREATE TABLE acme_renewals(site_id TEXT PRIMARY KEY REFERENCES sites(id),account_id TEXT NOT NULL REFERENCES acme_accounts(id),certificate_id TEXT NOT NULL REFERENCES certificates(id),enabled INTEGER NOT NULL,next_attempt_at INTEGER NOT NULL,last_error TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL);
 INSERT INTO schema_migrations VALUES(9,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	return tx.Commit()
}

type ACMERequest struct {
	SiteID      string `json:"site_id"`
	Provider    string `json:"provider"`
	Email       string `json:"email"`
	Terms       string `json:"terms_url"`
	AcceptTerms bool   `json:"accept_terms"`
	AutoRenew   bool   `json:"auto_renew"`
	Redirect    bool   `json:"redirect"`
}
type ACMEOrder struct {
	Terms         string   `json:"terms_url"`
	ID            string   `json:"id"`
	SiteID        string   `json:"site_id"`
	AccountID     string   `json:"account_id"`
	Domains       []string `json:"domains"`
	State         string   `json:"state"`
	Phase         string   `json:"phase"`
	OrderURL      string   `json:"order_url"`
	CertificateID string   `json:"certificate_id"`
	PrepareJob    string   `json:"prepare_job"`
	DeployJob     string   `json:"deploy_job"`
	BaselineTLS   string   `json:"-"`
	AutoRenew     bool     `json:"auto_renew"`
	Redirect      bool     `json:"redirect"`
	Attempt       int      `json:"attempt"`
	Error         string   `json:"error"`
	Steps         []Step   `json:"steps"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

func marshalString(v any) string { b, _ := json.Marshal(v); return string(b) }
func encryptedACMEKey(master []byte, purpose string) ([]byte, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return encryptCredential(master, purpose, der)
}
func (s *Store) QueueACME(in ACMERequest, provider ACMEProvider, key, actor string) (string, error) {
	if !in.AcceptTerms || in.Terms != provider.Terms || in.Provider != provider.ID {
		return "", errors.New("请阅读并确认当前 CA 服务条款")
	}
	address, e := mail.ParseAddress(in.Email)
	if e != nil || address.Address != in.Email || len(in.Email) > 254 || strings.ContainsAny(in.Email, "\r\n") {
		return "", errors.New("请填写有效的联系邮箱")
	}
	if key == "" || len(key) > 128 {
		return "", errors.New("请求标识无效")
	}
	site, e := s.Site(in.SiteID)
	if e != nil || site.Status != "running" {
		return "", errors.New("请选择已经运行的网站")
	}
	domains := append([]string{site.Domain}, site.Settings.Domains...)
	sort.Strings(domains)
	for _, d := range domains {
		if !ValidDomain(d) {
			return "", errors.New("网站域名无效")
		}
		if provider.ID != "pebble" && (strings.HasSuffix(d, ".localhost") || strings.HasSuffix(d, ".test") || strings.HasSuffix(d, ".invalid") || strings.HasSuffix(d, ".example") || strings.HasSuffix(d, ".local")) {
			return "", errors.New("公开 CA 需要可公网验证的正式域名；当前开发域名不能申请")
		}
	}
	if provider.ID != "pebble" && !site.Settings.PublicIngress {
		return "", errors.New("请先在网站设置中启用标准网站端口，公开 CA 需要访问 HTTP 80 端口")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var oldID, oldSite, oldProvider, oldEmail, oldTerms string
	var oldAuto, oldRedirect bool
	e = tx.QueryRow(`SELECT o.id,o.site_id,a.provider,a.email,o.terms_url,o.auto_renew,o.redirect FROM acme_orders o JOIN acme_accounts a ON a.id=o.account_id WHERE o.idempotency_key=?`, key).Scan(&oldID, &oldSite, &oldProvider, &oldEmail, &oldTerms, &oldAuto, &oldRedirect)
	if e == nil {
		if oldSite != in.SiteID || oldProvider != in.Provider || oldEmail != in.Email || oldTerms != in.Terms || oldAuto != in.AutoRenew || oldRedirect != in.Redirect {
			return "", errors.New("请求标识已被不同 ACME 操作使用")
		}
		return oldID, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	var accountID, email string
	e = tx.QueryRow(`SELECT id,email FROM acme_accounts WHERE provider=?`, provider.ID).Scan(&accountID, &email)
	if errors.Is(e, sql.ErrNoRows) {
		accountID = ID()
		encrypted, e := encryptedACMEKey(s.encryptionKey, "panel-acme-account:"+accountID)
		if e != nil {
			return "", e
		}
		_, e = tx.Exec(`INSERT INTO acme_accounts(id,provider,email,key_cipher,terms_url,terms_accepted_at,created_at) VALUES(?,?,?,?,?,?,?)`, accountID, provider.ID, in.Email, encrypted, in.Terms, Now(), Now())
		if e != nil {
			return "", e
		}
	} else if e != nil {
		return "", e
	} else if email != in.Email {
		return "", errors.New("此 CA 已有账户，请使用已登记的联系邮箱")
	} else {
		if _, e = tx.Exec(`UPDATE acme_accounts SET terms_url=?,terms_accepted_at=? WHERE id=?`, in.Terms, Now(), accountID); e != nil {
			return "", e
		}
	}
	id := ID()
	encrypted, e := encryptedACMEKey(s.encryptionKey, "panel-acme-order:"+id)
	if e != nil {
		return "", e
	}
	_, e = tx.Exec(`INSERT INTO acme_orders(id,site_id,account_id,domains,state,key_cipher,baseline_tls,terms_url,auto_renew,redirect,idempotency_key,created_at,updated_at) VALUES(?,?,?,?,'queued',?,?,?,?,?,?,?,?)`, id, in.SiteID, accountID, marshalString(domains), encrypted, marshalString(site.Settings.TLS), in.Terms, in.AutoRenew, in.Redirect, key, Now(), Now())
	if e != nil {
		return "", errors.New("此网站已有进行中的证书订单")
	}
	if _, e = tx.Exec(`UPDATE acme_renewals SET next_attempt_at=? WHERE site_id=?`, time.Now().Add(6*time.Hour).Unix(), in.SiteID); e != nil {
		return "", e
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'acme.request',?,'queued',?)`, actor, id, Now()); e != nil {
		return "", e
	}
	return id, tx.Commit()
}
func (s *Store) ACMEOrder(id string) (ACMEOrder, error) {
	var o ACMEOrder
	var domains, steps string
	e := s.DB.QueryRow(`SELECT id,site_id,account_id,domains,state,phase,order_url,certificate_id,prepare_job,deploy_job,baseline_tls,terms_url,auto_renew,redirect,attempt,error,steps,created_at,updated_at FROM acme_orders WHERE id=?`, id).Scan(&o.ID, &o.SiteID, &o.AccountID, &domains, &o.State, &o.Phase, &o.OrderURL, &o.CertificateID, &o.PrepareJob, &o.DeployJob, &o.BaselineTLS, &o.Terms, &o.AutoRenew, &o.Redirect, &o.Attempt, &o.Error, &steps, &o.CreatedAt, &o.UpdatedAt)
	if e != nil {
		return o, e
	}
	if e = json.Unmarshal([]byte(domains), &o.Domains); e != nil {
		return o, e
	}
	e = json.Unmarshal([]byte(steps), &o.Steps)
	return o, e
}
