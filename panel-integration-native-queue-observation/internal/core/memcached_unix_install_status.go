package core

import (
	"context"

	"local/panel/internal/appcatalog"
)

func registryComposeInstallJobPath(app, version, job string) string {
	if app == "memcached" && version == appcatalog.MemcachedUnixVersion {
		return "/v1/docker/memcached-unix/installs/" + job
	}
	return "/v1/docker/jobs/" + job
}

// The replay response did not carry a package revision in its old ABI. Read
// the original immutable binding; never query a mutating legacy observer for
// a new socket-only job merely because delivery was uncertain.
func (s *Store) registryComposeReplayJobPath(ctx context.Context, prior registryInstallReplay) (string, error) {
	if prior.Target != "memcached-cache" {
		return "/v1/docker/jobs/" + prior.JobID, nil
	}
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil {
		return "", errMemcachedUnixAuthority
	}
	var app, version, provider, scope, target string
	if s.DB.QueryRowContext(ctx, `SELECT app_id,version,provider,scope,target FROM app_registry_install_requests WHERE job_id=?`, prior.JobID).Scan(&app, &version, &provider, &scope, &target) != nil ||
		app != "memcached" || !appcatalog.ValidVersion(version) || provider != prior.Provider || provider != "compose" || scope != prior.Scope || target != prior.Target {
		return "", errMemcachedUnixAuthority
	}
	return registryComposeInstallJobPath(app, version, prior.JobID), nil
}

// Projection only: callers must first independently authenticate the complete
// original Root chain and official envelope. This is historical JOB state,
// never a live container-health claim or authority to enqueue another worker.
func MemcachedUnixInstallResult(record MemcachedUnixInstallRecord) (DockerJobResult, error) {
	if ValidateMemcachedUnixInstallRecord(record) != nil {
		return DockerJobResult{}, errMemcachedUnixInstallRecord
	}
	out := DockerJobResult{JobID: record.Operation.JobID, Kind: "compose", ProjectID: record.Operation.ProjectID}
	switch record.Phase {
	case "prepared":
		out.State, out.Message = "queued", "原安装身份已保留；尚不能确认账户、镜像或容器已安装"
	case "account-intent", "account-verified", "pull-intent", "image-verified", "project-intent", "project-written", "start-intent", "runtime-verified":
		out.State, out.Message = "running", "原 Socket 安装事务执行中；不重发、不推断成功"
	case "committed":
		out.State, out.Message, out.ContainerID = "succeeded", "原安装已完成真实运行核验并提交；当前服务健康需另行实时检查", record.ContainerID
	case "refused":
		out.State, out.Error = "failed", "原安装在副作用前拒绝；未启动或重发工作进程"
	case "needs-attention":
		out.State, out.Error = "needs_attention", "原安装存在未核对结果；保留账户、配置和容器证据，不自动重放、回滚或删除"
	default:
		return DockerJobResult{}, errMemcachedUnixInstallRecord
	}
	return out, nil
}
