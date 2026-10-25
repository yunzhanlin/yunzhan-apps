package core

import (
	"database/sql"
	"errors"
	"net/http"
)

type registryRequestCloseInput struct {
	Action          string `json:"action"`
	ExpectedVersion string `json:"expected_version"`
	ExpectedSHA256  string `json:"expected_sha256"`
}
type registryQueryRow interface{ QueryRow(string, ...any) *sql.Row }

// Checked inside every queue/reservation transaction as well as before replay.
// Closing an unsubmitted request fences a late request still fetching metadata;
// it is not cancellation of an actual job and must never remove a job binding.
func ensureRegistryRequestOpen(q registryQueryRow, key string) error {
	var n int
	if err := q.QueryRow(`SELECT count(*) FROM app_registry_request_closures WHERE idempotency_key=?`, key).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return errors.New("原应用请求已安全关闭且未入队；未重新提交，请使用新的请求标识")
	}
	return nil
}

func registryClosedOutcome(q registryQueryRow, app, actor, key string) (registryRequestOutcome, bool, error) {
	var out registryRequestOutcome
	var storedActor string
	err := q.QueryRow(`SELECT actor_id,app_id,action,version,sha256 FROM app_registry_request_closures WHERE idempotency_key=?`, key).Scan(&storedActor, &out.AppID, &out.Action, &out.Version, &out.SHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	var jobs int
	if err := q.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&jobs); err != nil || jobs != 0 {
		return out, false, errors.New("关闭记录与保留的任务不一致")
	}
	if storedActor != actor || out.AppID != app || (out.Action != "install" && out.Action != "update") || validateRegistryUpdateRequest(app, actor, key, registryUpdateInput{out.Version, out.SHA256}) != nil {
		return out, false, errors.New("原关闭记录身份不一致")
	}
	out.State, out.StateKnown = "closed_without_submission", true
	return out, true, nil
}

func (s *Store) closeRegistryRequest(app, actor, key string, in registryRequestCloseInput) (registryRequestOutcome, error) {
	var out registryRequestOutcome
	if (in.Action != "install" && in.Action != "update") || validateRegistryUpdateRequest(app, actor, key, registryUpdateInput{in.ExpectedVersion, in.ExpectedSHA256}) != nil {
		return out, errors.New("关闭请求标识、版本或摘要无效")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow(`SELECT (SELECT count(*) FROM app_registry_install_requests WHERE idempotency_key=?)+(SELECT count(*) FROM app_registry_update_requests WHERE idempotency_key=?)+(SELECT count(*) FROM runtime_jobs WHERE idempotency_key=?)`, key, key, key).Scan(&n); err != nil {
		return out, err
	}
	if n != 0 {
		return out, errors.New("原请求已有任务或保留的身份；不能关闭，请核对原任务")
	}
	if prior, found, e := registryClosedOutcome(tx, app, actor, key); e != nil {
		return out, e
	} else if found {
		if prior.Action != in.Action || prior.Version != in.ExpectedVersion || prior.SHA256 != in.ExpectedSHA256 {
			return out, errors.New("原关闭记录已绑定不同请求")
		}
		return prior, tx.Commit()
	}
	if err = tx.QueryRow(`SELECT count(*) FROM app_registry_request_closures`).Scan(&n); err != nil {
		return out, err
	}
	if n >= 100000 {
		return out, errors.New("关闭记录达到容量上限；保留原请求，未关闭")
	}
	if _, err = tx.Exec(`INSERT INTO app_registry_request_closures(idempotency_key,actor_id,app_id,action,version,sha256,created_at) VALUES(?,?,?,?,?,?,?)`, key, actor, app, in.Action, in.ExpectedVersion, in.ExpectedSHA256, Now()); err != nil {
		return out, err
	}
	out = registryRequestOutcome{AppID: app, Action: in.Action, State: "closed_without_submission", StateKnown: true, Version: in.ExpectedVersion, SHA256: in.ExpectedSHA256}
	return out, tx.Commit()
}

func (a *Server) closeRegistryRequest(w http.ResponseWriter, r *http.Request, u identity) {
	var in registryRequestCloseInput
	if !decode(w, r, &in) {
		return
	}
	out, err := a.Store.closeRegistryRequest(r.PathValue("id"), u.ID, r.PathValue("key"), in)
	if err != nil {
		fail(w, 409, "不能安全关闭原请求；请核对原任务，未取消、删除或重发任务")
		return
	}
	send(w, 200, out)
}
