package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"time"
)

type FileShare struct {
	ID        string `json:"id"`
	SiteID    string `json:"site_id"`
	Path      string `json:"path"`
	Name      string `json:"name"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt string `json:"created_at"`
	RevokedAt int64  `json:"revoked_at"`
	PurgedAt  int64  `json:"-"`
	Downloads int64  `json:"downloads"`
}

var shareTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func (s *Store) migrateFileShares() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS file_shares(
		id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
		site_id TEXT NOT NULL REFERENCES sites(id), path TEXT NOT NULL, name TEXT NOT NULL,
		bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, expires_at INTEGER NOT NULL,
		created_at TEXT NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0,
		purged_at INTEGER NOT NULL DEFAULT 0,
		downloads INTEGER NOT NULL DEFAULT 0);
		CREATE INDEX IF NOT EXISTS file_shares_site ON file_shares(site_id,created_at);
		INSERT OR IGNORE INTO schema_migrations VALUES(50,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func (s *Store) createFileShare(v FileShare) (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(token))
	r, e := s.DB.Exec(`INSERT INTO file_shares(id,token_hash,site_id,path,name,bytes,sha256,expires_at,created_at)
		SELECT ?,?,?,?,?,?,?,?,? WHERE (SELECT count(*) FROM file_shares WHERE site_id=? AND revoked_at=0 AND expires_at>?)<20`,
		v.ID, hex.EncodeToString(hash[:]), v.SiteID, v.Path, v.Name, v.Bytes, v.SHA256, v.ExpiresAt, v.CreatedAt, v.SiteID, time.Now().Unix())
	if e != nil {
		return "", e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return "", e
	}
	if n == 0 {
		return "", errors.New("每个站点最多保留 20 个有效分享")
	}
	return token, e
}

func (s *Store) listFileShares(siteID string) ([]FileShare, error) {
	rows, e := s.DB.Query(`SELECT id,site_id,path,name,bytes,sha256,expires_at,created_at,revoked_at,downloads FROM file_shares WHERE site_id=? ORDER BY created_at DESC LIMIT 100`, siteID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []FileShare{}
	for rows.Next() {
		var v FileShare
		if e = rows.Scan(&v.ID, &v.SiteID, &v.Path, &v.Name, &v.Bytes, &v.SHA256, &v.ExpiresAt, &v.CreatedAt, &v.RevokedAt, &v.Downloads); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) fileShareByToken(token string) (FileShare, error) {
	var v FileShare
	if !shareTokenPattern.MatchString(token) {
		return v, sql.ErrNoRows
	}
	hash := sha256.Sum256([]byte(token))
	e := s.DB.QueryRow(`SELECT id,site_id,path,name,bytes,sha256,expires_at,created_at,revoked_at,downloads FROM file_shares WHERE token_hash=? AND revoked_at=0 AND expires_at>?`, hex.EncodeToString(hash[:]), time.Now().Unix()).Scan(
		&v.ID, &v.SiteID, &v.Path, &v.Name, &v.Bytes, &v.SHA256, &v.ExpiresAt, &v.CreatedAt, &v.RevokedAt, &v.Downloads)
	return v, e
}

func (s *Store) revokeFileShare(siteID, id string) (bool, error) {
	r, e := s.DB.Exec(`UPDATE file_shares SET revoked_at=CASE WHEN revoked_at=0 THEN ? ELSE revoked_at END WHERE id=? AND site_id=?`, time.Now().Unix(), id, siteID)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}

// Expired and revoked snapshots are removed independently of browser visits.
// A failed purge is retried later; the token is already invalid in the DB.
func (a *Server) cleanupFileShares(ctx context.Context) error {
	rows, e := a.Store.DB.QueryContext(ctx, `SELECT site_id,id FROM file_shares WHERE purged_at=0 AND (revoked_at>0 OR expires_at<=?) LIMIT 100`, time.Now().Unix())
	if e != nil {
		return e
	}
	var pending [][2]string
	for rows.Next() {
		var siteID, id string
		if e = rows.Scan(&siteID, &id); e != nil {
			rows.Close()
			return e
		}
		pending = append(pending, [2]string{siteID, id})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, item := range pending {
		var ack map[string]bool
		if e = a.Executor.Call(ctx, "POST", "/v1/sites/"+item[0]+"/files/action", FileAction{Action: "share_purge", ShareID: item[1]}, &ack); e != nil {
			continue
		}
		_, _ = a.Store.DB.ExecContext(ctx, `UPDATE file_shares SET purged_at=? WHERE id=?`, time.Now().Unix(), item[1])
	}
	return nil
}

func (a *Server) StartFileShareMaintenance(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			callCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			_ = a.cleanupFileShares(callCtx)
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (a *Server) fileShareRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/sites/{id}/files/shares", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, e := a.Store.Site(r.PathValue("id")); e != nil {
			fail(w, 404, "站点不存在")
			return
		}
		shares, e := a.Store.listFileShares(r.PathValue("id"))
		if e != nil {
			fail(w, 500, "读取分享列表失败")
			return
		}
		send(w, 200, shares)
	}))
	m.HandleFunc("POST /api/sites/{id}/files/shares", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		siteID := r.PathValue("id")
		access, accessErr := a.Store.PanelAccess()
		if accessErr != nil || !access.HTTPEnabled {
			fail(w, 409, "请先开启面板公网 HTTP 入口，再创建文件分享")
			return
		}
		if _, e := fileSharePublicURL(access, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); e != nil {
			fail(w, 409, e.Error())
			return
		}
		if _, e := a.Store.Site(siteID); e != nil {
			fail(w, 404, "站点不存在")
			return
		}
		var in struct {
			Path         string `json:"path"`
			ExpiresHours int    `json:"expires_hours"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF || !ValidFilePath(in.Path, false) || in.ExpiresHours < 1 || in.ExpiresHours > 168 {
			fail(w, 400, "分享文件路径或到期时间无效（1–168 小时）")
			return
		}
		id := ID()
		var snapshot struct {
			Name   string `json:"name"`
			Bytes  int64  `json:"bytes"`
			SHA256 string `json:"sha256"`
		}
		if e := a.Executor.Call(r.Context(), "POST", "/v1/sites/"+siteID+"/files/action", FileAction{Action: "share_prepare", Path: in.Path, ShareID: id}, &snapshot); e != nil {
			fail(w, 409, e.Error())
			return
		}
		share := FileShare{ID: id, SiteID: siteID, Path: in.Path, Name: snapshot.Name, Bytes: snapshot.Bytes, SHA256: snapshot.SHA256, ExpiresAt: time.Now().Add(time.Duration(in.ExpiresHours) * time.Hour).Unix(), CreatedAt: Now()}
		token, e := a.Store.createFileShare(share)
		if e != nil {
			var ack map[string]bool
			_ = a.Executor.Call(r.Context(), "POST", "/v1/sites/"+siteID+"/files/action", FileAction{Action: "share_purge", ShareID: id}, &ack)
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "file.share.create", siteID+":"+in.Path, "success")
		publicURL, e := fileSharePublicURL(access, token)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 201, map[string]any{"share": share, "url_path": "/share/" + token, "public_url": publicURL})
	}))
	m.HandleFunc("DELETE /api/sites/{id}/files/shares/{shareID}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		siteID, id := r.PathValue("id"), r.PathValue("shareID")
		if !ValidID(id) {
			fail(w, 404, "分享不存在")
			return
		}
		changed, e := a.Store.revokeFileShare(siteID, id)
		if e != nil {
			fail(w, 500, "撤销分享失败")
			return
		}
		if !changed {
			fail(w, 404, "分享不存在")
			return
		}
		_ = a.Store.Audit(u.Username, "file.share.revoke", siteID+":"+id, "success")
		var ack map[string]bool
		if e = a.Executor.Call(r.Context(), "POST", "/v1/sites/"+siteID+"/files/action", FileAction{Action: "share_purge", ShareID: id}, &ack); e != nil {
			fail(w, 409, "分享已撤销，快照清理失败，请稍后重试")
			return
		}
		_, _ = a.Store.DB.Exec(`UPDATE file_shares SET purged_at=? WHERE id=?`, time.Now().Unix(), id)
		send(w, 200, map[string]bool{"ok": true})
	}))
	m.HandleFunc("GET /share/{token}", func(w http.ResponseWriter, r *http.Request) {
		share, e := a.Store.fileShareByToken(r.PathValue("token"))
		if e != nil {
			http.NotFound(w, r)
			return
		}
		if _, e = a.Store.Site(share.SiteID); e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": share.Name}))
		sent, e := a.proxyFile(w, r, "/v1/sites/"+share.SiteID+"/files/shares/"+share.ID)
		if e != nil {
			if !sent {
				http.NotFound(w, r)
			}
			_ = a.Store.Audit("share", "file.share.download", share.SiteID+":"+share.ID, "failed")
			return
		}
		_, _ = a.Store.DB.Exec(`UPDATE file_shares SET downloads=downloads+1 WHERE id=?`, share.ID)
		_ = a.Store.Audit("share", "file.share.download", share.SiteID+":"+share.ID, "success")
	})
}
