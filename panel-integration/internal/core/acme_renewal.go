package core

import (
	"errors"
	"net/http"
	"time"
)

type ACMERenewal struct {
	SiteID        string `json:"site_id"`
	SiteName      string `json:"site_name"`
	Domain        string `json:"domain"`
	Provider      string `json:"provider"`
	CertificateID string `json:"certificate_id"`
	Enabled       bool   `json:"enabled"`
	NextAttempt   int64  `json:"next_attempt_at"`
	LastError     string `json:"last_error"`
}

func (s *Store) completeACME(id string) error {
	o, e := s.ACMEOrder(id)
	if e != nil {
		return e
	}
	o.Steps = append(o.Steps, Step{Time: Now(), Message: "新证书已绑定，实际 HTTPS 和网站内容检查通过"})
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`UPDATE acme_orders SET state='succeeded',phase='complete',error='',steps=?,updated_at=? WHERE id=?`, marshalString(o.Steps), Now(), id); e != nil {
		return e
	}
	if _, e = tx.Exec(`DELETE FROM acme_challenges WHERE order_id=?`, id); e != nil {
		return e
	}
	if _, e = tx.Exec(`INSERT INTO acme_renewals(site_id,account_id,certificate_id,enabled,next_attempt_at,last_error,updated_at) VALUES(?,?,?,?,?,'',?) ON CONFLICT(site_id) DO UPDATE SET account_id=excluded.account_id,certificate_id=excluded.certificate_id,enabled=excluded.enabled,next_attempt_at=excluded.next_attempt_at,last_error='',updated_at=excluded.updated_at`, o.SiteID, o.AccountID, o.CertificateID, o.AutoRenew, time.Now().Add(24*time.Hour).Unix(), Now()); e != nil {
		return e
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('executor','acme.certificate',?,'succeeded',?)`, id, Now()); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ACMERenewals() ([]ACMERenewal, error) {
	rows, e := s.DB.Query(`SELECT r.site_id,s.name,s.domain,a.provider,r.certificate_id,r.enabled,r.next_attempt_at,r.last_error FROM acme_renewals r JOIN sites s ON s.id=r.site_id JOIN acme_accounts a ON a.id=r.account_id ORDER BY s.name,r.site_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ACMERenewal{}
	for rows.Next() {
		var r ACMERenewal
		if e = rows.Scan(&r.SiteID, &r.SiteName, &r.Domain, &r.Provider, &r.CertificateID, &r.Enabled, &r.NextAttempt, &r.LastError); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) queueDueACMERenewals(now time.Time) {
	renewals, e := s.ACMERenewals()
	if e != nil {
		return
	}
	for _, r := range renewals {
		if !r.Enabled {
			continue
		}
		site, e := s.Site(r.SiteID)
		if e != nil {
			continue
		}
		if site.Settings.TLS == nil || site.Settings.TLS.CertificateID != r.CertificateID || !site.Settings.ACME {
			_, _ = s.DB.Exec(`UPDATE acme_renewals SET enabled=0,last_error='网站证书或验证入口已变更，已暂停旧续期规则',updated_at=? WHERE site_id=?`, Now(), r.SiteID)
			continue
		}
		if r.NextAttempt > now.Unix() {
			continue
		}
		if site.Status != "running" {
			_, _ = s.DB.Exec(`UPDATE acme_renewals SET next_attempt_at=?,last_error='网站未运行，稍后重试',updated_at=? WHERE site_id=?`, now.Add(time.Hour).Unix(), Now(), r.SiteID)
			continue
		}
		cert, e := s.Certificate(r.CertificateID)
		if e != nil {
			continue
		}
		expiry, e := time.Parse(time.RFC3339, cert.NotAfter)
		if e != nil {
			continue
		}
		if expiry.Sub(now) > 30*24*time.Hour {
			_, _ = s.DB.Exec(`UPDATE acme_renewals SET next_attempt_at=?,updated_at=? WHERE site_id=?`, now.Add(24*time.Hour).Unix(), Now(), r.SiteID)
			continue
		}
		var email, terms string
		if e = s.DB.QueryRow(`SELECT a.email,a.terms_url FROM acme_accounts a JOIN acme_renewals r ON r.account_id=a.id WHERE r.site_id=?`, r.SiteID).Scan(&email, &terms); e != nil {
			continue
		}
		p, e := findACMEProvider(r.Provider)
		if e == nil {
			p.Terms = terms
			_, e = s.QueueACME(ACMERequest{SiteID: r.SiteID, Provider: r.Provider, Email: email, Terms: terms, AcceptTerms: true, AutoRenew: true, Redirect: site.Settings.TLS.Redirect}, p, ID(), "scheduler")
		}
		if e != nil {
			_, _ = s.DB.Exec(`UPDATE acme_renewals SET next_attempt_at=?,last_error=?,updated_at=? WHERE site_id=?`, now.Add(6*time.Hour).Unix(), e.Error(), Now(), r.SiteID)
		}
	}
}
func (a *Server) acmeRenewalRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/acme/accounts", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		rows, e := a.Store.DB.Query(`SELECT provider,email,terms_url,terms_accepted_at FROM acme_accounts ORDER BY provider`)
		if e != nil {
			fail(w, 500, "CA 账户不可读取")
			return
		}
		defer rows.Close()
		out := []map[string]string{}
		for rows.Next() {
			var provider, email, terms, acceptedAt string
			if e = rows.Scan(&provider, &email, &terms, &acceptedAt); e != nil {
				fail(w, 500, "CA 账户不可读取")
				return
			}
			out = append(out, map[string]string{"provider": provider, "email": email, "terms_url": terms, "terms_accepted_at": acceptedAt})
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/acme/renewals", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		out, e := a.Store.ACMERenewals()
		if e != nil {
			fail(w, 500, "续期规则不可读取")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/acme/renewals/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Enabled bool `json:"enabled"`
		}
		if !decode(w, r, &in) {
			return
		}
		e := a.Store.toggleACMERenewal(r.PathValue("id"), in.Enabled, u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, map[string]bool{"ok": true})
	}))
}
func (s *Store) toggleACMERenewal(siteID string, enabled bool, actor string) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var n int
	if e = tx.QueryRow(`SELECT count(*) FROM acme_orders WHERE site_id=? AND state IN ('queued','running')`, siteID).Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return errors.New("请等待当前证书订单完成后修改自动续期")
	}
	result, e := tx.Exec(`UPDATE acme_renewals SET enabled=?,next_attempt_at=?,last_error='',updated_at=? WHERE site_id=? AND certificate_id=(SELECT json_extract(settings_json,'$.tls.certificate_id') FROM sites WHERE id=? AND json_extract(settings_json,'$.acme')=1)`, enabled, time.Now().Add(24*time.Hour).Unix(), Now(), siteID, siteID)
	if e != nil {
		return e
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("续期规则不存在或网站已换用其他证书，请重新申请")
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'acme.renewal',?,? ,?)`, actor, siteID, marshalString(enabled), Now()); e != nil {
		return e
	}
	return tx.Commit()
}
