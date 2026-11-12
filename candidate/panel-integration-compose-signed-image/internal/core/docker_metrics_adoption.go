package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
)

const dockerMetricsReviewJob = "docker_metrics_review"

func dockerMetricsPackage(app appcatalog.CatalogItem) bool {
	return app.ID == "docker-manager" && app.Provider == "runtime" && app.Target == "docker-auto" &&
		app.ManageRoute == "docker" && app.Version == appcatalog.DockerMetricsVersion
}

// The dashboard package can advance after observing the existing Engine.
// It never submits a runtime install, even if Docker disappears during review.
func (a *Server) reviewDockerMetricsPackage(ctx context.Context, item appcatalog.CatalogItem, key string, user identity) (string, error) {
	spec, ok := runtimecatalog.DockerSpecOn(runtimecatalog.HostPlatform())
	release, known := runtimecatalog.Find(spec.ReleaseID)
	if !ok || !known || release.Family != "docker" || !dockerMetricsPackage(item) {
		return "", errors.New("无法核对当前系统的 Docker 应用包")
	}
	var runtimes struct {
		Installed []registryInstalledRuntime `json:"installed"`
	}
	if err := a.Executor.Call(ctx, http.MethodGet, "/v1/runtimes", nil, &runtimes); err != nil {
		return "", errors.New("无法读取已安装的 Docker 运行时")
	}
	count := 0
	for _, row := range runtimes.Installed {
		if row.ID != release.ID {
			continue
		}
		if row.Status != "installed" || row.Family != release.Family || row.Version != release.Version {
			return "", errors.New("当前 Docker 运行时身份或版本待核对")
		}
		count++
	}
	var engine struct {
		Available bool   `json:"available"`
		Active    bool   `json:"active"`
		Version   string `json:"version"`
	}
	if count != 1 || a.Executor.Call(ctx, http.MethodGet, "/v1/docker", nil, &engine) != nil ||
		!engine.Active || !engine.Available || engine.Version != spec.EngineVersion {
		return "", errors.New("当前 Docker Engine 的运行状态或固定版本无法核对")
	}

	tx, err := a.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var previous string
	err = tx.QueryRowContext(ctx, "SELECT version FROM app_registry_receipts WHERE app_id=? AND scope=?", item.ID, release.ID).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if err == nil {
		cmp, valid := appcatalog.CompareVersions(previous, item.Version)
		if !valid || cmp >= 0 {
			return "", errors.New("Docker 应用包已达到此版本，请刷新商店")
		}
	}
	var pending int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM app_registry_pending WHERE app_id=? AND scope=?", item.ID, release.ID).Scan(&pending); err != nil {
		return "", err
	}
	if pending != 0 {
		return "", errors.New("已有 Docker 应用包回执待核对，请刷新商店")
	}
	job, stamp := ID(), Now()
	steps, err := json.Marshal([]Step{{Time: stamp, Message: "已核对正在运行的 Docker Engine 和原安装版本，刷新商店可查看应用包回执"}})
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO runtime_jobs
		(id,target_id,kind,state,steps,idempotency_key,created_at,updated_at)
		VALUES(?,?,?,'succeeded',?,?,?,?)`, job, release.ID, dockerMetricsReviewJob, string(steps), key, stamp, stamp); err != nil {
		return "", err
	}
	if err := a.Store.bindRegistryUpdate(item, release.ID, key, user.ID)(tx, job, false); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at)
		VALUES(?,'docker.metrics.package.review',?,'verified',?)`, user.Username, release.ID, stamp); err != nil {
		return "", err
	}
	return job, tx.Commit()
}
