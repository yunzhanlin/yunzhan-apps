package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

func (s *Store) migrateCertificates() error {
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=8`).Scan(&n); e != nil {
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
	_, e = tx.Exec(`CREATE TABLE certificates(id TEXT PRIMARY KEY,name TEXT NOT NULL,certificate_pem TEXT NOT NULL,key_cipher BLOB NOT NULL,metadata TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL);
 INSERT INTO schema_migrations VALUES(8,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) SaveCertificate(name, certPEM, keyPEM, key, actor string) (Certificate, error) {
	var empty Certificate
	name = strings.TrimSpace(name)
	if len([]rune(name)) < 1 || len([]rune(name)) > 80 || key == "" || len(key) > 128 {
		return empty, errors.New("请填写证书名称和有效请求标识")
	}
	cert, e := ParseCertificate(certPEM, keyPEM, time.Now())
	if e != nil {
		return empty, e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	var oldMetadata string
	e = tx.QueryRow(`SELECT metadata FROM certificates WHERE idempotency_key=?`, key).Scan(&oldMetadata)
	if e == nil {
		var old Certificate
		if e = json.Unmarshal([]byte(oldMetadata), &old); e != nil {
			return empty, e
		}
		if old.ChainSHA != cert.ChainSHA || old.Name != name {
			return empty, errors.New("请求标识已用于不同证书")
		}
		return old, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return empty, e
	}
	cert.ID = ID()
	cert.Name = name
	cert.CreatedAt = Now()
	encrypted, e := encryptCredential(s.encryptionKey, "panel-tls:"+cert.ID, []byte(keyPEM))
	if e != nil {
		return empty, errors.New("证书凭据存储尚未就绪")
	}
	metadata, e := json.Marshal(cert)
	if e != nil {
		return empty, e
	}
	if _, e = tx.Exec(`INSERT INTO certificates VALUES(?,?,?,?,?,?,?)`, cert.ID, cert.Name, cert.PEM, encrypted, string(metadata), key, cert.CreatedAt); e != nil {
		return empty, e
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'certificate.upload',?,'success',?)`, actor, cert.ID, Now()); e != nil {
		return empty, e
	}
	return cert, tx.Commit()
}
func (s *Store) Certificate(id string) (Certificate, error) {
	var c Certificate
	if !ValidID(id) {
		return c, errors.New("证书标识无效")
	}
	var metadata, certificatePEM string
	if e := s.DB.QueryRow(`SELECT metadata,certificate_pem FROM certificates WHERE id=?`, id).Scan(&metadata, &certificatePEM); e != nil {
		return c, e
	}
	if e := json.Unmarshal([]byte(metadata), &c); e != nil {
		return c, e
	}
	c.PEM = certificatePEM
	now := time.Now()
	expires, e := time.Parse(time.RFC3339, c.NotAfter)
	if e != nil {
		return c, e
	}
	begins, e := time.Parse(time.RFC3339, c.NotBefore)
	if e != nil {
		return c, e
	}
	if now.Before(begins) {
		c.Status = "not_yet_valid"
	} else if !now.Before(expires) {
		c.Status = "expired"
	} else if expires.Sub(now) < 30*24*time.Hour {
		c.Status = "expiring"
	} else {
		c.Status = "valid"
	}
	if e = s.DB.QueryRow(`SELECT count(*) FROM sites WHERE json_extract(settings_json,'$.tls.certificate_id')=?`, id).Scan(&c.References); e != nil {
		return c, e
	}
	return c, nil
}
func (s *Store) Certificates() ([]Certificate, error) {
	rows, e := s.DB.Query(`SELECT id FROM certificates ORDER BY created_at DESC,rowid DESC`)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := []Certificate{}
	for _, id := range ids {
		c, e := s.Certificate(id)
		if e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, nil
}
func (s *Store) CertificateMaterial(id string) (CertificateMaterial, error) {
	var out CertificateMaterial
	if !ValidID(id) {
		return out, errors.New("证书标识无效")
	}
	var encrypted []byte
	if e := s.DB.QueryRow(`SELECT certificate_pem,key_cipher FROM certificates WHERE id=?`, id).Scan(&out.CertificatePEM, &encrypted); e != nil {
		return out, e
	}
	key, e := decryptCredential(s.encryptionKey, "panel-tls:"+id, encrypted)
	if e != nil {
		return out, errors.New("证书私钥无法解密，请核对私有主密钥")
	}
	out.ID = id
	out.PrivateKeyPEM = string(key)
	return out, nil
}
func (s *Store) validateSiteCertificate(primary string, settings SiteSettings) error {
	if settings.TLS == nil {
		return nil
	}
	cert, e := s.Certificate(settings.TLS.CertificateID)
	if e != nil {
		return errors.New("所选证书不存在或不可读取")
	}
	return cert.ValidateDomains(primary, settings.Domains, time.Now())
}
func (a *Server) certificateRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/certificates", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		out, e := a.Store.Certificates()
		if e != nil {
			fail(w, 500, "证书列表不可读取")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/certificates", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Name           string `json:"name"`
			CertificatePEM string `json:"certificate_pem"`
			PrivateKeyPEM  string `json:"private_key_pem"`
		}
		if !decode(w, r, &in) {
			return
		}
		out, e := a.Store.SaveCertificate(in.Name, in.CertificatePEM, in.PrivateKeyPEM, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		send(w, 201, out)
	}))
}
