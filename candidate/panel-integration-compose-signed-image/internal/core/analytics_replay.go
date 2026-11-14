package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"local/panel/internal/appcatalog"
)

const (
	analyticsReplayDays         = 7
	analyticsReplayFrameLimit   = 180
	analyticsReplaySiteLimit    = 10000
	analyticsReplayTotalLimit   = 30000
	analyticsReplayTileLimit    = 60
	analyticsReplayFrameBytes   = 3900
	analyticsReplayAnchorWindow = 30 * time.Minute
)

var errReplayNotActive = errors.New("会话画面采集已关闭或不在抽样范围")
var errReplayPageAbsent = errors.New("会话画面找不到对应的页面事件")
var errReplayCapacity = errors.New("会话画面达到保存上限")

type analyticsReplayPolicy struct {
	SiteID   string `json:"site_id"`
	Enabled  bool   `json:"enabled"`
	Sample   int    `json:"sample_percent"`
	Revision int64  `json:"revision"`
}

// Each rectangle is [left, top, width, height, 24-bit RGB, element kind] in
// thousandths of the viewport. The wire format contains no text, markup,
// resource URLs, CSS expressions, input values, or serialized DOM nodes.
type analyticsReplayFrame struct {
	Width   int     `json:"width"`
	Height  int     `json:"height"`
	Scroll  int     `json:"scroll"`
	Pointer []int   `json:"pointer,omitempty"`
	Tiles   [][]int `json:"tiles"`
}

func (f *analyticsReplayFrame) valid() bool {
	if f == nil || f.Width < 1 || f.Width > 8192 || f.Height < 1 || f.Height > 8192 ||
		f.Scroll < 0 || f.Scroll > 1000 || f.Tiles == nil || len(f.Tiles) > analyticsReplayTileLimit {
		return false
	}
	if len(f.Pointer) != 0 && (len(f.Pointer) != 3 || f.Pointer[0] < 0 || f.Pointer[0] > 1000 || f.Pointer[1] < 0 || f.Pointer[1] > 1000 || f.Pointer[2] < 0 || f.Pointer[2] > 1) {
		return false
	}
	for _, tile := range f.Tiles {
		if len(tile) != 6 || tile[0] < 0 || tile[0] >= 1000 || tile[1] < 0 || tile[1] >= 1000 ||
			tile[2] < 1 || tile[2] > 1000-tile[0] || tile[3] < 1 || tile[3] > 1000-tile[1] ||
			tile[4] < 0 || tile[4] > 0xffffff || tile[5] < 0 || tile[5] > 4 {
			return false
		}
	}
	return true
}

func (s *Store) migrateAnalyticsReplay() error {
	_, err := s.DB.Exec(`
CREATE TABLE IF NOT EXISTS analytics_replay_policy(
    site_id TEXT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    sample INTEGER NOT NULL CHECK(sample BETWEEN 1 AND 100),
    revision INTEGER NOT NULL CHECK(revision > 0)
);
CREATE TABLE IF NOT EXISTS analytics_replay_frames(
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    session TEXT NOT NULL,
    visitor TEXT NOT NULL,
    path TEXT NOT NULL,
    received_ms INTEGER NOT NULL,
    frame BLOB NOT NULL,
    PRIMARY KEY(site_id,id)
);
CREATE INDEX IF NOT EXISTS analytics_replay_session ON analytics_replay_frames(site_id,session,visitor,received_ms);
CREATE INDEX IF NOT EXISTS analytics_replay_expiry ON analytics_replay_frames(received_ms);`)
	return err
}

func (s *Store) analyticsReplayPolicy(ctx context.Context, site string) (analyticsReplayPolicy, error) {
	out := analyticsReplayPolicy{SiteID: site, Sample: 10}
	err := s.DB.QueryRowContext(ctx, "SELECT enabled,sample,revision FROM analytics_replay_policy WHERE site_id=?", site).
		Scan(&out.Enabled, &out.Sample, &out.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	return out, err
}

func (a *Server) analyticsReplayRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/analytics/sites/{id}/replay-policy", a.authorize(a.readAnalyticsReplayPolicy))
	m.HandleFunc("POST /api/analytics/sites/{id}/replay-policy", a.authorize(a.setAnalyticsReplayPolicy))
	m.HandleFunc("GET /api/analytics/sites/{id}/sessions/{session}/replay", a.authorize(a.readAnalyticsReplay))
}

func (a *Server) readAnalyticsReplayPolicy(w http.ResponseWriter, r *http.Request, _ identity) {
	site := r.PathValue("id")
	if !ValidID(site) {
		fail(w, 400, "网站标识无效")
		return
	}
	if _, err := a.Store.Site(site); err != nil {
		fail(w, 404, "网站不存在")
		return
	}
	policy, err := a.Store.analyticsReplayPolicy(r.Context(), site)
	if err != nil {
		fail(w, 503, "暂时无法读取会话回看设置")
		return
	}
	send(w, 200, policy)
}

func (a *Server) setAnalyticsReplayPolicy(w http.ResponseWriter, r *http.Request, u identity) {
	site := r.PathValue("id")
	var in analyticsReplayPolicy
	if !decode(w, r, &in) {
		return
	}
	if !ValidID(site) || in.SiteID != site || in.Revision < 0 || in.Sample < 1 || in.Sample > 100 {
		fail(w, 400, "网站范围、设置版本或抽样比例无效")
		return
	}
	if in.Enabled && !a.Store.analyticsHasReceipt(r.Context(), appcatalog.AnalyticsSessionActivityVersion) {
		fail(w, 409, "请先从签名应用商店安装支持会话回看的网站分析版本")
		return
	}
	result, err := a.Store.DB.ExecContext(r.Context(), `INSERT INTO analytics_replay_policy(site_id,enabled,sample,revision)
SELECT ?,?,?,1 FROM sites WHERE id=? AND (?=0 OR EXISTS(SELECT 1 FROM analytics_config WHERE site_id=? AND enabled=1))
  AND (?=0 OR EXISTS(SELECT 1 FROM analytics_replay_policy WHERE site_id=? AND revision=?))
ON CONFLICT(site_id) DO UPDATE SET enabled=excluded.enabled,sample=excluded.sample,revision=analytics_replay_policy.revision+1
WHERE analytics_replay_policy.revision=?`,
		site, in.Enabled, in.Sample, site, in.Enabled, site, in.Revision, site, in.Revision, in.Revision)
	if err != nil {
		fail(w, 503, "暂时无法保存会话回看设置")
		return
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		fail(w, 409, "请核对网站已开启浏览器采集，或刷新后使用最新设置版本")
		return
	}
	in.Revision++
	_ = a.Store.Audit(u.Username, "analytics.replay-policy", site, "succeeded")
	send(w, 200, in)
}

func (a *Server) analyticsReplaySample(ctx context.Context, site string) int {
	p, err := a.Store.analyticsReplayPolicy(ctx, site)
	if err != nil || !p.Enabled || !a.Store.analyticsHasReceipt(ctx, appcatalog.AnalyticsSessionActivityVersion) {
		return 0
	}
	return p.Sample
}

func (s *Store) storeAnalyticsReplay(ctx context.Context, site string, v AnalyticsEvent, selection uint64, now time.Time) error {
	raw, err := json.Marshal(v.Replay)
	if err != nil || len(raw) > analyticsReplayFrameBytes {
		return errors.New("会话画面编码无效")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if !analyticsReceiptVerified(ctx, tx, appcatalog.AnalyticsSessionActivityVersion) {
		return errReplayNotActive
	}
	var enabled bool
	var sample int
	err = tx.QueryRowContext(ctx, `SELECT p.enabled,p.sample FROM analytics_replay_policy p JOIN analytics_config c ON c.site_id=p.site_id
WHERE p.site_id=? AND c.enabled=1`, site).Scan(&enabled, &sample)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (!enabled || selection*100 >= uint64(sample)*(1<<32)) {
		return errReplayNotActive
	}
	if err != nil {
		return err
	}
	// An accepted frame belongs to an observed page of the same pseudonymous
	// visitor and session. The display path comes from that page event.
	var path string
	err = tx.QueryRowContext(ctx, `SELECT path FROM analytics_events
WHERE site_id=? AND session=? AND visitor=? AND received>=? AND kind='pageview'
AND json_extract(data,'$.page_id')=? ORDER BY received DESC LIMIT 1`,
		site, v.Session, v.Visitor, now.Add(-analyticsReplayAnchorWindow).Unix(), v.PageID).Scan(&path)
	if errors.Is(err, sql.ErrNoRows) {
		return errReplayPageAbsent
	}
	if err != nil {
		return err
	}
	var duplicate, siteFrames, sessionFrames, totalFrames int
	err = tx.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM analytics_replay_frames WHERE site_id=? AND id=?),
(SELECT count(*) FROM analytics_replay_frames WHERE site_id=?),
(SELECT count(*) FROM analytics_replay_frames WHERE site_id=? AND session=? AND visitor=?),
(SELECT count(*) FROM analytics_replay_frames)`,
		site, v.ID, site, site, v.Session, v.Visitor).Scan(&duplicate, &siteFrames, &sessionFrames, &totalFrames)
	if err != nil {
		return err
	}
	if duplicate != 0 {
		return nil
	}
	if sessionFrames >= analyticsReplayFrameLimit || siteFrames >= analyticsReplaySiteLimit || totalFrames >= analyticsReplayTotalLimit {
		return errReplayCapacity
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO analytics_replay_frames(site_id,id,session,visitor,path,received_ms,frame)
VALUES(?,?,?,?,?,?,?)`, site, v.ID, v.Session, v.Visitor, path, now.UnixMilli(), raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}

type analyticsReplayDisplayFrame struct {
	Path       string               `json:"path"`
	ReceivedMS int64                `json:"received_ms"`
	Viewport   analyticsReplayFrame `json:"viewport"`
}

func (a *Server) readAnalyticsReplay(w http.ResponseWriter, r *http.Request, _ identity) {
	w.Header().Set("Cache-Control", "private, no-store")
	site, session := r.PathValue("id"), r.PathValue("session")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !ValidID(site) || !validAnalyticsActivityHash(session) || !validAnalyticsActivityHash(q.Get("visitor")) {
		fail(w, 400, "会话或访客标识无效")
		return
	}
	for key, values := range q {
		if len(values) != 1 || key != "visitor" && key != "from" && key != "to" {
			fail(w, 400, "回看查询参数无效")
			return
		}
	}
	now := time.Now()
	from, to, err := analyticsWindow(q.Get("from"), q.Get("to"), now)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if !a.Store.analyticsHasReceipt(r.Context(), appcatalog.AnalyticsSessionActivityVersion) {
		fail(w, 409, "请先从签名应用商店安装支持会话回看的网站分析版本")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rows, err := a.Store.DB.QueryContext(ctx, `SELECT f.path,f.received_ms,f.frame FROM analytics_replay_frames f
JOIN analytics_config c ON c.site_id=f.site_id
WHERE f.site_id=? AND f.session=? AND f.visitor=? AND f.received_ms>=? AND f.received_ms<?
AND f.received_ms>=? - min(?,c.retention)*86400000
ORDER BY f.received_ms,f.rowid LIMIT ?`, site, session, q.Get("visitor"), from.UnixMilli(), to.UnixMilli(),
		now.UnixMilli(), analyticsReplayDays, analyticsReplayFrameLimit)
	if err != nil {
		fail(w, 503, "暂时无法读取会话画面")
		return
	}
	defer rows.Close()
	frames := []analyticsReplayDisplayFrame{}
	for rows.Next() {
		var f analyticsReplayDisplayFrame
		var raw []byte
		if err := rows.Scan(&f.Path, &f.ReceivedMS, &raw); err != nil || len(raw) > analyticsReplayFrameBytes ||
			json.Unmarshal(raw, &f.Viewport) != nil || !f.Viewport.valid() {
			fail(w, 503, "会话画面记录无法核对")
			return
		}
		frames = append(frames, f)
	}
	if rows.Err() != nil {
		fail(w, 503, "暂时无法完成会话画面读取")
		return
	}
	send(w, 200, map[string]any{"site_id": site, "session_id": session, "from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "frames": frames})
}
