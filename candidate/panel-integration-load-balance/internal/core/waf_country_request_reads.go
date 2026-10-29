package core

import (
	"context"
	"encoding/json"
	"errors"
)

func decodeWAFCountryActorBody(raw []byte, actor string) (WAFCountryDataSelection, error) {
	var empty WAFCountryDataSelection
	bad := errors.New("国家数据请求账户或完整字段无法核对；未提交")
	if !ValidID(actor) || len(raw) > 4096 || !wafInventoryJSONShape(raw, []string{"actor_id", "selection"}) {
		return empty, bad
	}
	var in struct {
		Actor     string          `json:"actor_id"`
		Selection json.RawMessage `json:"selection"`
	}
	if json.Unmarshal(raw, &in) != nil || in.Actor != actor {
		return empty, bad
	}
	selection, err := DecodeWAFCountryDataSelection(in.Selection)
	if err != nil {
		return empty, bad
	}
	return selection, nil
}

type wafCountryRequestSummary struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
	PayloadSHA string `json:"payload_sha256"`
}
type wafCountryRequestPage struct {
	ActorID    string                     `json:"actor_id"`
	Entries    []wafCountryRequestSummary `json:"entries"`
	NextCursor string                     `json:"next_cursor"`
	ReadOnly   bool                       `json:"read_only"`
}
type wafCountryRequestDetail struct {
	ActorID                 string                   `json:"actor_id"`
	Request                 wafCountryRequestSummary `json:"request"`
	Selection               WAFCountryDataSelection  `json:"selection"`
	ReadOnly                bool                     `json:"read_only"`
	Error                   string                   `json:"error"`
	Result                  *WAFCountryDataOperation `json:"result,omitempty"`
	ResultSHA               string                   `json:"result_sha256,omitempty"`
	CanCancelBeforeDispatch bool                     `json:"can_cancel_before_dispatch"`
	Cancellation            *wafCountryCancellation  `json:"cancellation,omitempty"`
}

func (s *Store) readWAFCountryRequest(ctx context.Context, actor, id string) (wafCountryRequestDetail, error) {
	var empty wafCountryRequestDetail
	if ctx == nil || !ValidID(actor) || !ValidID(id) {
		return empty, errors.New("国家数据原请求身份无效")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := wafCountryCurrentAccess(ctx, tx, actor); err != nil {
		return empty, err
	}
	original, err := readWAFCountryOriginal(ctx, tx, id)
	if err != nil || original.Actor != actor {
		return empty, errors.New("当前账户原国家数据请求不存在或无法完整核对")
	}
	out, err := countryRequestDetail(ctx, tx, original)
	if err != nil {
		return empty, err
	}
	return out, tx.Commit()
}

func (s *Store) readWAFCountryRequests(ctx context.Context, actor, cursor string) (wafCountryRequestPage, error) {
	var empty wafCountryRequestPage
	if ctx == nil || !ValidID(actor) || cursor != "" && !ValidID(cursor) {
		return empty, errors.New("国家数据原请求目录身份无效")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := wafCountryCurrentAccess(ctx, tx, actor); err != nil {
		return empty, err
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM waf_country_requests`).Scan(&count) != nil || count > wafCountryRequestMax {
		return empty, errors.New("国家数据目录无法完整读取或超出逻辑容量")
	}
	rows, err := tx.QueryContext(ctx, `SELECT job_id FROM waf_country_requests WHERE actor_id=? AND job_id>? ORDER BY job_id LIMIT 21`, actor, cursor)
	if err != nil {
		return empty, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return empty, errors.New("国家数据原请求目录损坏")
		}
		ids = append(ids, id)
	}
	rowErr := rows.Err()
	closeErr := rows.Close()
	if rowErr != nil {
		return empty, rowErr
	}
	if closeErr != nil {
		return empty, closeErr
	}
	out := wafCountryRequestPage{ActorID: actor, Entries: []wafCountryRequestSummary{}, ReadOnly: true}
	previous := cursor
	for _, id := range ids {
		if !ValidID(id) || id <= previous {
			return empty, errors.New("国家数据原请求目录顺序或身份损坏")
		}
		original, err := readWAFCountryOriginal(ctx, tx, id)
		if err != nil || original.Actor != actor {
			return empty, errors.New("国家数据原请求目录不能完整核对，未返回部分结果")
		}
		if _, err := countryRequestDetail(ctx, tx, original); err != nil {
			return empty, err
		}
		if len(out.Entries) == 20 {
			out.NextCursor = previous
			break
		}
		out.Entries = append(out.Entries, wafCountryRequestSummary{id, original.Job.State, original.Created, original.PayloadSHA})
		previous = id
	}
	return out, tx.Commit()
}
