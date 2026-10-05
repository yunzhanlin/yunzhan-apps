package core

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var acmeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)

func (a *Server) acmeRoutes(m *http.ServeMux) {
	a.acmeRenewalRoutes(m)
	m.HandleFunc("GET /.well-known/acme-challenge/{token}", func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		host := strings.ToLower(r.Host)
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		host = strings.TrimSuffix(host, ".")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !acmeTokenPattern.MatchString(token) || !ValidDomain(host) {
			http.NotFound(w, r)
			return
		}
		var response string
		e := a.Store.DB.QueryRow(`SELECT c.response FROM acme_challenges c JOIN acme_orders o ON o.id=c.order_id JOIN sites s ON s.id=o.site_id JOIN site_domains d ON d.site_id=s.id AND d.domain=c.domain AND d.source_job='' WHERE c.domain=? AND c.token=? AND c.expires_at>? AND o.state IN ('queued','running') AND s.status='running' AND json_extract(s.settings_json,'$.acme')=1`, host, token, time.Now().Unix()).Scan(&response)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(response))
	})
	m.HandleFunc("GET /api/acme/providers", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) { send(w, 200, acmeProviders()) }))
	m.HandleFunc("GET /api/acme/providers/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		p, e := findACMEProvider(r.PathValue("id"))
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		p, e = discoverACME(ctx, p)
		if e != nil {
			fail(w, 503, "CA 目录或服务条款不可读取: "+e.Error())
			return
		}
		send(w, 200, p)
	}))
	m.HandleFunc("POST /api/acme/orders", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in ACMERequest
		if !decode(w, r, &in) {
			return
		}
		p, e := findACMEProvider(in.Provider)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		p, e = discoverACME(ctx, p)
		if e != nil {
			fail(w, 503, "CA 目录不可读取: "+e.Error())
			return
		}
		id, e := a.Store.QueueACME(in, p, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": id})
	}))
	m.HandleFunc("GET /api/acme/orders/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		o, e := a.Store.ACMEOrder(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "证书订单不存在")
			return
		}
		send(w, 200, o)
	}))
}
func (s *Store) RetryACME(id, actor string) error {
	o, e := s.ACMEOrder(id)
	if e != nil {
		return e
	}
	if o.State != "failed" {
		return errors.New("仅失败的证书订单可以重试")
	}
	site, e := s.Site(o.SiteID)
	if e != nil {
		return e
	}
	if site.Status != "running" && site.Status != "needs_attention" {
		return errors.New("请先启用站点")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// A new attempt may create a fresh preview after a failed child transaction.
	for _, pair := range [][2]string{{"prepare_job", o.PrepareJob}, {"deploy_job", o.DeployJob}} {
		if pair[1] == "" {
			continue
		}
		var state string
		if e = tx.QueryRow(`SELECT state FROM jobs WHERE id=?`, pair[1]).Scan(&state); e != nil {
			return e
		}
		if state == "failed" {
			if _, e = tx.Exec(`UPDATE acme_orders SET `+pair[0]+`='' WHERE id=?`, id); e != nil {
				return e
			}
		}
	}
	// Preserve the known remote URL so retries can recover an already issued certificate.
	orderURL := o.OrderURL
	result, e := tx.Exec(`UPDATE acme_orders SET state='queued',phase='prepare',order_url=?,error='',attempt=attempt+1,updated_at=? WHERE id=? AND state='failed'`, orderURL, Now(), id)
	if e != nil {
		return errors.New("此网站已有其他证书订单")
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	if _, e = tx.Exec(`DELETE FROM acme_challenges WHERE order_id=?`, id); e != nil {
		return e
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'acme.retry',?,'queued',?)`, actor, id, Now()); e != nil {
		return e
	}
	return tx.Commit()
}
