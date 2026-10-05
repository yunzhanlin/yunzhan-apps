package core

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/acme"
	"net/http"
	"sort"
	"strings"
	"time"
)

func RunACMEWorker(ctx context.Context, s *Store, e *ExecutorClient) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	nextRenewal := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !time.Now().Before(nextRenewal) {
				s.queueDueACMERenewals(time.Now())
				nextRenewal = time.Now().Add(30 * time.Second)
			}
			var id string
			if er := s.DB.QueryRow(`SELECT id FROM acme_orders WHERE state='queued' ORDER BY created_at,rowid LIMIT 1`).Scan(&id); er != nil {
				continue
			}
			r, er := s.DB.Exec(`UPDATE acme_orders SET state='running',updated_at=? WHERE id=? AND state='queued'`, Now(), id)
			if er != nil {
				continue
			}
			n, _ := r.RowsAffected()
			if n != 1 {
				continue
			}
			work, cancel := context.WithTimeout(ctx, 10*time.Minute)
			er = s.runACMEOrder(work, e, id)
			cancel()
			if ctx.Err() != nil {
				return
			}
			if er != nil {
				s.failACME(id, er)
			}
		}
	}
}
func (s *Store) acmeProgress(id, phase, message string) error {
	o, e := s.ACMEOrder(id)
	if e != nil {
		return e
	}
	o.Steps = append(o.Steps, Step{Time: Now(), Message: message})
	if len(o.Steps) > 100 {
		o.Steps = o.Steps[len(o.Steps)-100:]
	}
	_, e = s.DB.Exec(`UPDATE acme_orders SET phase=?,steps=?,updated_at=? WHERE id=? AND state='running'`, phase, marshalString(o.Steps), Now(), id)
	return e
}
func (s *Store) failACME(id string, reason error) {
	detail := reason.Error()
	if len(detail) > 2048 {
		detail = detail[:2048]
	}
	o, e := s.ACMEOrder(id)
	if e != nil {
		return
	}
	// A failed certificate deployment leaves the prior site configuration in
	// place. Clear the child job's attention marker only when the persisted TLS
	// binding still exactly matches the order baseline.
	restoreSite := false
	if site, siteErr := s.Site(o.SiteID); siteErr == nil {
		restoreSite = site.Status == "needs_attention" && marshalString(site.Settings.TLS) == o.BaselineTLS
	}
	o.Steps = append(o.Steps, Step{Time: Now(), Message: detail})
	tx, e := s.DB.Begin()
	if e != nil {
		return
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`UPDATE acme_orders SET state='failed',error=?,steps=?,updated_at=? WHERE id=?`, detail, marshalString(o.Steps), Now(), id); e != nil {
		return
	}
	if _, e = tx.Exec(`DELETE FROM acme_challenges WHERE order_id=?`, id); e != nil {
		return
	}
	if _, e = tx.Exec(`UPDATE acme_renewals SET last_error=?,next_attempt_at=?,updated_at=? WHERE site_id=?`, detail, time.Now().Add(6*time.Hour).Unix(), Now(), o.SiteID); e != nil {
		return
	}
	if restoreSite {
		if _, e = tx.Exec(`UPDATE sites SET status='running',updated_at=? WHERE id=? AND status='needs_attention'`, Now(), o.SiteID); e != nil {
			return
		}
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('executor','acme.certificate',?,'failed',?)`, id, Now()); e != nil {
		return
	}
	_ = tx.Commit()
}
func (s *Store) acmeCurrentSite(o ACMEOrder) (Site, error) {
	site, e := s.Site(o.SiteID)
	if e != nil {
		return site, e
	}
	if site.Status != "running" && site.Status != "needs_attention" {
		return site, errors.New("网站已停用，证书订单停止部署")
	}
	domains := append([]string{site.Domain}, site.Settings.Domains...)
	sort.Strings(domains)
	if marshalString(domains) != marshalString(o.Domains) {
		return site, errors.New("网站域名已变化，请按新域名重新申请")
	}
	targetTLS := marshalString(&SiteTLS{CertificateID: o.CertificateID, Redirect: o.Redirect})
	if marshalString(site.Settings.TLS) != o.BaselineTLS && (o.CertificateID == "" || marshalString(site.Settings.TLS) != targetTLS) {
		return site, errors.New("网站证书绑定已被其他操作修改，保留当前选择")
	}
	return site, nil
}
func (s *Store) acmeSiteJob(ctx context.Context, e *ExecutorClient, o ACMEOrder, deploy bool) error {
	column, job, phase := "prepare_job", o.PrepareJob, "prepare"
	if deploy {
		column, job, phase = "deploy_job", o.DeployJob, "deploy"
	}
	key := fmt.Sprintf("acme:%s:%s:%d", o.ID, phase, o.Attempt)
	if job == "" {
		_ = s.DB.QueryRow(`SELECT id FROM jobs WHERE idempotency_key=?`, key).Scan(&job)
	}
	if job == "" {
		site, er := s.acmeCurrentSite(o)
		if er != nil {
			return er
		}
		if !deploy && site.Settings.ACME && site.Status == "running" {
			return nil
		}
		if deploy && !site.Settings.ACME {
			return errors.New("网站验证入口已被关闭，保留当前设置")
		}
		site.Settings.ACME = true
		if deploy {
			site.Settings.TLS = &SiteTLS{CertificateID: o.CertificateID, Redirect: o.Redirect}
		}
		var preview struct {
			ConfigSHA string `json:"config_sha"`
		}
		if er = e.Call(ctx, "POST", "/v1/sites/preview", site, &preview); er != nil {
			return er
		}
		job, er = s.QueueSiteSettings(site.ID, site.Settings, site.SettingsRevision, preview.ConfigSHA, key, "acme")
		if er != nil {
			return er
		}
	}
	if _, er := s.DB.Exec(`UPDATE acme_orders SET `+column+`=?,updated_at=? WHERE id=?`, job, Now(), o.ID); er != nil {
		return er
	}
	for {
		var state, detail string
		if er := s.DB.QueryRow(`SELECT state,error FROM jobs WHERE id=?`, job).Scan(&state, &detail); er != nil {
			return er
		}
		switch state {
		case "succeeded":
			return nil
		case "failed":
			return fmt.Errorf("网站配置任务 %s 失败: %s", job, detail)
		case "needs_attention":
			if er := s.Retry(job, "acme-recovery"); er != nil {
				return fmt.Errorf("网站配置任务需要核对: %w", er)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
func decodeACMESigner(master []byte, purpose string, cipher []byte) (crypto.Signer, []byte, error) {
	der, e := decryptCredential(master, purpose, cipher)
	if e != nil {
		return nil, nil, errors.New("ACME 私钥无法解密")
	}
	key, e := x509.ParsePKCS8PrivateKey(der)
	if e != nil {
		return nil, nil, e
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("ACME 私钥格式不支持")
	}
	return signer, der, nil
}
func (s *Store) acmeClient(ctx context.Context, o ACMEOrder) (*acme.Client, *http.Client, ACMEProvider, error) {
	var providerID, email string
	var cipher []byte
	if er := s.DB.QueryRow(`SELECT provider,email,key_cipher FROM acme_accounts WHERE id=?`, o.AccountID).Scan(&providerID, &email, &cipher); er != nil {
		return nil, nil, ACMEProvider{}, er
	}
	p, er := findACMEProvider(providerID)
	if er != nil {
		return nil, nil, p, er
	}
	h, er := acmeHTTPClient(p)
	if er != nil {
		return nil, nil, p, er
	}
	signer, _, er := decodeACMESigner(s.encryptionKey, "panel-acme-account:"+o.AccountID, cipher)
	if er != nil {
		h.CloseIdleConnections()
		return nil, nil, p, er
	}
	client := &acme.Client{Key: signer, DirectoryURL: p.Directory, HTTPClient: h, UserAgent: "OwnPanel/0.1"}
	dir, er := client.Discover(ctx)
	if er != nil {
		h.CloseIdleConnections()
		return nil, nil, p, er
	}
	if dir.Terms != o.Terms {
		h.CloseIdleConnections()
		return nil, nil, p, errors.New("CA 服务条款已变更，请重新确认后申请")
	}
	account, er := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + email}}, func(terms string) bool { return terms == o.Terms })
	if errors.Is(er, acme.ErrAccountAlreadyExists) {
		account, er = client.GetReg(ctx, "")
	}
	if er != nil {
		h.CloseIdleConnections()
		return nil, nil, p, er
	}
	if _, er = s.DB.Exec(`UPDATE acme_accounts SET account_url=? WHERE id=?`, account.URI, o.AccountID); er != nil {
		h.CloseIdleConnections()
		return nil, nil, p, er
	}
	return client, h, p, nil
}
func (s *Store) runACMEOrder(ctx context.Context, e *ExecutorClient, id string) error {
	o, er := s.ACMEOrder(id)
	if er != nil {
		return er
	}
	currentSite, er := s.acmeCurrentSite(o)
	if er != nil {
		return er
	}
	if o.Phase != "prepare" && !currentSite.Settings.ACME {
		return errors.New("网站验证入口已被关闭，请确认后重试")
	}
	if er = s.acmeProgress(id, "prepare", "准备网站 HTTP-01 入口，保留业务配置和原证书"); er != nil {
		return er
	}
	if er = s.acmeSiteJob(ctx, e, o, false); er != nil {
		return er
	}
	o, er = s.ACMEOrder(id)
	if er != nil {
		return er
	}
	if o.CertificateID == "" {
		if er = s.acmeProgress(id, "account", "使用持久账户密钥连接 CA 并核对服务条款"); er != nil {
			return er
		}
		client, h, provider, er := s.acmeClient(ctx, o)
		if er != nil {
			return er
		}
		defer h.CloseIdleConnections()
		var order *acme.Order
		if o.OrderURL != "" {
			order, er = client.GetOrder(ctx, o.OrderURL)
			if er != nil {
				var problem *acme.Error
				if o.Attempt > 1 && errors.As(er, &problem) && problem.StatusCode == http.StatusNotFound {
					order = nil
				} else {
					return fmt.Errorf("远端订单无法恢复，请核对后重试: %w", er)
				}
			} else if order.Status == acme.StatusInvalid || (!order.Expires.IsZero() && time.Now().After(order.Expires) && order.Status != acme.StatusValid) {
				if o.Attempt <= 1 {
					return errors.New("远端订单无效或已过期，请重试")
				}
				order = nil
			}
		}
		if order == nil {
			ids := make([]acme.AuthzID, len(o.Domains))
			for i, domain := range o.Domains {
				ids[i] = acme.AuthzID{Type: "dns", Value: domain}
			}
			order, er = client.AuthorizeOrder(ctx, ids)
			if er != nil {
				return er
			}
			if order.URI == "" {
				return errors.New("CA 没有返回持久订单地址")
			}
			o.OrderURL = order.URI
			if _, er = s.DB.Exec(`UPDATE acme_orders SET order_url=?,updated_at=? WHERE id=?`, order.URI, Now(), id); er != nil {
				return er
			}
		}
		if er = s.acmeProgress(id, "challenge", "远端订单已保存，开始实际 HTTP-01 验证"); er != nil {
			return er
		}
		allowed := map[string]bool{}
		for _, domain := range o.Domains {
			allowed[domain] = true
		}
		for _, uri := range order.AuthzURLs {
			auth, er := client.GetAuthorization(ctx, uri)
			if er != nil {
				return er
			}
			if auth.Identifier.Type != "dns" || !allowed[auth.Identifier.Value] || auth.Wildcard {
				return errors.New("CA 返回了订单范围外的授权标识")
			}
			if auth.Status == acme.StatusValid {
				continue
			}
			if auth.Status != acme.StatusPending {
				return fmt.Errorf("域名 %s 验证状态为 %s", auth.Identifier.Value, auth.Status)
			}
			var challenge *acme.Challenge
			for _, c := range auth.Challenges {
				if c.Type == "http-01" {
					challenge = c
					break
				}
			}
			if challenge == nil {
				return errors.New("此 CA 未提供 HTTP-01 验证")
			}
			if !acmeTokenPattern.MatchString(challenge.Token) {
				return errors.New("CA 验证令牌格式无效")
			}
			response, er := client.HTTP01ChallengeResponse(challenge.Token)
			if er != nil {
				return er
			}
			if _, er = s.DB.Exec(`INSERT INTO acme_challenges(order_id,domain,token,response,expires_at) VALUES(?,?,?,?,?) ON CONFLICT(domain,token) DO UPDATE SET order_id=excluded.order_id,response=excluded.response,expires_at=excluded.expires_at`, id, auth.Identifier.Value, challenge.Token, response, time.Now().Add(15*time.Minute).Unix()); er != nil {
				return er
			}
			// Verify the actual Nginx route before telling the CA that the response is ready.
			if er = checkACMEHTTP01(ctx, auth.Identifier.Value, challenge.Token, response); er != nil {
				return er
			}
			if challenge.Status == acme.StatusPending || challenge.Status == "" {
				if _, er = client.Accept(ctx, challenge); er != nil {
					return er
				}
			} else if challenge.Status != acme.StatusProcessing && challenge.Status != acme.StatusValid {
				return errors.New("远端 HTTP-01 验证已失败，请重试新订单")
			}
			if _, er = client.WaitAuthorization(ctx, uri); er != nil {
				return er
			}
			if er = s.acmeProgress(id, "challenge", "域名 "+auth.Identifier.Value+" 已由 CA 验证"); er != nil {
				return er
			}
		}
		order, er = client.WaitOrder(ctx, o.OrderURL)
		if er != nil {
			return er
		}
		var cipher []byte
		if er = s.DB.QueryRow(`SELECT key_cipher FROM acme_orders WHERE id=?`, id).Scan(&cipher); er != nil {
			return er
		}
		signer, der, er := decodeACMESigner(s.encryptionKey, "panel-acme-order:"+id, cipher)
		if er != nil {
			return er
		}
		var chain [][]byte
		if order.Status == acme.StatusValid {
			chain, er = client.FetchCert(ctx, order.CertURL, true)
		} else if order.Status == acme.StatusReady {
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: o.Domains}, signer)
			if err != nil {
				return err
			}
			if er = s.acmeProgress(id, "finalize", "域名验证完成，提交 CSR 并核对签发结果"); er != nil {
				return er
			}
			chain, er = finalizeACMECertificate(ctx, client, o.OrderURL, order.FinalizeURL, csr)
		} else {
			return fmt.Errorf("远端订单尚不可签发: %s", order.Status)
		}
		if er != nil {
			return er
		}
		var certPEM strings.Builder
		for _, raw := range chain {
			certPEM.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		checked, er := ParseCertificate(certPEM.String(), string(keyPEM), time.Now())
		if er != nil {
			return er
		}
		actualDomains := append([]string{}, checked.Domains...)
		sort.Strings(actualDomains)
		if marshalString(actualDomains) != marshalString(o.Domains) {
			return errors.New("签发证书的域名与原订单不一致")
		}
		cert, er := s.SaveCertificate("ACME "+provider.Name+" "+id[:8], certPEM.String(), string(keyPEM), "acme-cert:"+id, "acme")
		if er != nil {
			return er
		}
		o.CertificateID = cert.ID
		if _, er = s.DB.Exec(`UPDATE acme_orders SET certificate_id=?,updated_at=? WHERE id=?`, cert.ID, Now(), id); er != nil {
			return er
		}
		if er = s.acmeProgress(id, "certificate", "新证书已检查并加密保存，准备部署"); er != nil {
			return er
		}
	}
	if _, er = s.acmeCurrentSite(o); er != nil {
		return er
	}
	if er = s.acmeSiteJob(ctx, e, o, true); er != nil {
		return er
	}
	current, er := s.acmeCurrentSite(o)
	if er != nil {
		return er
	}
	if current.Settings.TLS == nil || current.Settings.TLS.CertificateID != o.CertificateID || current.Status != "running" {
		return errors.New("部署后的网站证书绑定未完成")
	}
	return s.completeACME(id)
}

// finalizeACMECertificate reconciles an uncertain response before another CSR can be submitted.
func finalizeACMECertificate(ctx context.Context, client *acme.Client, orderURL, finalizeURL string, csr []byte) ([][]byte, error) {
	chain, _, err := client.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err == nil || ctx.Err() != nil {
		return chain, err
	}
	// Some CAs omit Location on a processing response. The pinned client then
	// loses its polling URL. Always use the durable, CA-confirmed order address.
	issued, lookupErr := client.GetOrder(ctx, orderURL)
	if lookupErr == nil && (issued.Status == acme.StatusProcessing || issued.Status == acme.StatusValid) {
		issued, lookupErr = client.WaitOrder(ctx, orderURL)
		if lookupErr == nil && issued.Status == acme.StatusValid {
			return client.FetchCert(ctx, issued.CertURL, true)
		}
	}
	return nil, err
}
