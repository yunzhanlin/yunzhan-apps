//go:build linux

package executor

import (
	"context"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

var memcachedUnixAdmission sync.Mutex

// Separate canonical bounded IPC, never the generic Compose ABI/body limit.
// Root independently verifies its compiled official key, exact fresh original
// Core reservation and native host before retaining any new job. A duplicate
// only observes its original chain; it never launches/restarts another worker.
func (s *Service) memcachedUnixInstallAdmissionRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/docker/memcached-unix/installs/{job}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		job := r.PathValue("job")
		if !core.ValidID(job) || r.URL.RawQuery != "" {
			respond(w, 404, map[string]string{"error": "原 Socket 安装任务无效"})
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(r.Body, core.MaxMemcachedUnixInstallSubmissionBytes+1))
		in, decodeErr := core.DecodeMemcachedUnixInstallSubmission(raw)
		if readErr != nil || decodeErr != nil || in.Operation.JobID != job {
			respond(w, 400, map[string]string{"error": "Socket 原安装传输、容量或身份不匹配"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		authority, err := appcatalog.VerifyMemcachedUnixReleaseEnvelope(ctx, in.Envelope, in.Binding.Version, in.Binding.ManifestSHA256)
		if err != nil || !authority.Matches(in.Binding.Version, in.Binding.ManifestSHA256) {
			respond(w, 409, map[string]string{"error": "执行器独立官方验签或完整能力尚未通过；未保留任务或安装容器"})
			return
		}
		first, err := core.NewMemcachedUnixInstallRecord(in)
		if err != nil || first.CatalogSHA256 != authority.CatalogSHA256() {
			respond(w, 409, map[string]string{"error": "原 Socket 签名交付绑定变化"})
			return
		}
		if !memcachedUnixAdmission.TryLock() {
			respond(w, 409, map[string]string{"error": "另一个 Socket 原安装正在核对；未重发"})
			return
		}
		defer memcachedUnixAdmission.Unlock()
		store := memcachedUnixJournalStore{base: memcachedUnixInstallJobsRoot}
		original, openErr := store.open(job)
		if openErr == nil {
			defer original.Close()
			chain, err := original.readChain()
			if err != nil || len(chain) == 0 || chain[0] != first {
				respond(w, 409, map[string]string{"error": "原任务存在不同或不完整证据；未覆盖或重发"})
				return
			}
			result, err := original.status(ctx)
			if err != nil {
				respond(w, 409, map[string]string{"error": "原任务结果暂不能核对；未重新启动"})
				return
			}
			respond(w, 200, result)
			return
		}
		if !os.IsNotExist(openErr) || upgradeguard.Blocked() || memcachedUnixHostAvailable() != nil || dockerAvailable(ctx) != nil {
			respond(w, 409, map[string]string{"error": "Socket 原任务、程序升级状态、Docker 或隔离前提不可核对；未安装"})
			return
		}
		leaseContext, leaseCancel := context.WithTimeout(ctx, 3*time.Second)
		lifetime, err := acquireMemcachedUnixRuntime(leaseContext)
		leaseCancel()
		if err != nil {
			respond(w, 409, map[string]string{"error": "原运行时生命周期租约不可核对；未安装"})
			return
		}
		defer lifetime.Close()
		reader, err := openMemcachedUpdateCoreAuthority(ctx)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原账户和保留请求不可核对"})
			return
		}
		defer reader.Close()
		if reader.unixInstall(ctx, in.Operation, in.Binding) != nil || (&core.Store{DB: reader.db}).CheckMemcachedUnixOtherInstalls(ctx, in.Operation, in.Binding) != nil {
			respond(w, 403, map[string]string{"error": "原安装请求或当前完整管理员授权无效"})
			return
		}
		if checkMemcachedRootTransactions(ctx) != nil || !lifetime.current() || reader.unixInstall(ctx, in.Operation, in.Binding) != nil || upgradeguard.Blocked() || ctx.Err() != nil {
			respond(w, 409, map[string]string{"error": "原生事务或授权在保留前变化；未安装或重发"})
			return
		}
		retained, fresh, err := store.prepare(raw)
		if err != nil || retained != first {
			respond(w, 409, map[string]string{"error": "原安装事务持久化结果不能核对；保留原证据，不重发"})
			return
		}
		if fresh {
			go runMemcachedUnixInstall(job)
		}
		result, err := core.MemcachedUnixInstallResult(retained)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原安装结果不能核对，未重发"})
			return
		}
		respond(w, 202, result)
	})
}
