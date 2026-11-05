//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"time"

	"local/panel/internal/core"
)

const integrityKernelScope = "Linux 原生不可变标记保护实际受管网站：阻止受保护文件写入及保护目录内的新增、改名和删除。按 inode 核对，不跟随符号链接、硬链接或其他挂载。原有标记和数字所有者保留。排除项仅为现存目录，目录内部可写，其名称仍受父目录保护。不是进程白名单或对抗具备相同内核权限的 Root；执行器需要 CAP_LINUX_IMMUTABLE。启停逐项执行，未完成或中断不会宣称整体成功；不会自动重跑、清理旧记录或删除用户数据。"

func (s *Service) integrityKernelAppReceipt(ctx context.Context, applications ...string) (string, error) {
	application, err := integrityKernelApplicationArgument(applications)
	if err != nil {
		return "", err
	}
	unknown := errors.New("当前签名应用收据不能核对；未授权内核控制，监控、原保护和数据保留")
	if s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" || s.Config.SitesDir != "/srv/panel/sites" {
		return "", unknown
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return "", unknown
	}
	defer reader.db.Close()
	if !reader.current() {
		return "", unknown
	}
	var version, sha, target string
	if reader.db.QueryRowContext(ctx, "SELECT version,sha256,target FROM app_registry_receipts WHERE app_id=? AND scope=?", application, application).Scan(&version, &sha, &target) != nil || version != core.IntegrityKernelAppVersion || target != application || !phpValidSHA(sha) || !reader.current() {
		return "", unknown
	}
	return sha, nil
}

func (s *Service) integrityKernelStatus(ctx context.Context, site string, applications ...string) (core.IntegrityKernelStatus, error) {
	out := core.IntegrityKernelStatus{SiteID: site, State: "needs-baseline", Operations: []core.IntegrityKernelOperation{}, Capability: integrityKernelHasCapability(), Scope: integrityKernelScope}
	application, err := integrityKernelApplicationArgument(applications)
	if err != nil {
		return out, err
	}
	if application == core.IntegrityKernelEnterpriseApplication {
		out.AppID = application
	}
	if !core.ValidID(site) {
		return out, errors.New("内核保护网站标识无效")
	}
	installed, err := s.moduleInstalledRecord(application)
	var receiptErr error
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if err == nil && installed["version"] == core.IntegrityKernelAppVersion {
		out.AppVersion = core.IntegrityKernelAppVersion
		out.AppSHA, receiptErr = s.integrityKernelAppReceipt(ctx, application)
	}
	baseline, baselineErr := s.readIntegrityBaseline(application, site)
	if baselineErr == nil {
		out.BaselineSHA = baseline.Signature
		out.BaselineFiles = len(baseline.Files)
		out.State = "ready"
	} else if !errors.Is(baselineErr, os.ErrNotExist) {
		out.Error = integrityKernelBoundedError(baselineErr)
	}
	rows, err := s.integrityKernelOperations()
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		if row.Request.Input.SiteID == site {
			out.Operations = append(out.Operations, row)
		}
	}
	latest := integrityKernelLatest(rows, site)
	baselineState := out.State
	if latest != nil {
		out.Latest = latest
		out.Revision = latest.Revision
		switch latest.State {
		case "queued", "running":
			out.State = latest.State
		case "needs-attention":
			out.State = "needs-attention"
			out.Error = latest.Error
		case "declined":
			out.Error = latest.Error
		case "cancelled":
			out.Error = latest.Error
			if latest.Request.Action == "release" {
				out.State = "needs-attention"
			}
		case "succeeded":
			if latest.Request.Action == "release" {
				out.State = "released"
			} else {
				plan, e := s.integrityKernelSourcePlan(rows, *latest)
				if e == nil {
					e = s.integrityKernelVerify(ctx, plan, false)
				}
				if e != nil {
					out.State = "needs-attention"
					out.Error = integrityKernelBoundedError(e)
				} else {
					out.State = "enabled"
				}
			}
		}
		if core.IntegrityKernelRequestApplication(latest.Request) != application {
			// Keep the common revision and all original evidence visible, but
			// never offer another application's protected inode for release.
			out.State = baselineState
			if !core.IntegrityKernelOperationReleased(*latest) {
				out.State = "other-application"
				out.Error = "该网站仍由另一防篡改应用保护或核对原结果；请从原应用处理，不能在这里重复启用或解除"
			}
		}
	}
	if out.AppVersion == "" {
		out.State = "upgrade-required"
		if latest != nil && core.IntegrityKernelRequestApplication(latest.Request) == application {
			out.Error = "原内核保护记录仍保留；当前应用身份不支持控制，请先恢复对应签名版本"
		}
	}
	if !out.Capability && out.State == "ready" {
		out.State = "unsupported"
		out.Error = "当前执行器没有 CAP_LINUX_IMMUTABLE；未启用内核写保护"
	}
	if out.State == "enabled" && baselineErr != nil {
		out.State = "needs-attention"
		out.Error = "原内核标记仍需核对，当前签名基线无法读取或验证；不会自动解除或覆盖"
	}
	if receiptErr != nil {
		out.Error = receiptErr.Error()
		if latest != nil && !core.IntegrityKernelOperationReleased(*latest) && core.IntegrityKernelRequestApplication(latest.Request) == application {
			out.State = "needs-attention"
		} else {
			out.State = "upgrade-required"
		}
	}
	if latest != nil && core.IntegrityKernelRequestApplication(latest.Request) != application && !core.IntegrityKernelOperationReleased(*latest) {
		out.State = "other-application"
		out.Error = "该网站仍由另一防篡改应用保护或核对原结果；请从原应用处理，不能在这里重复启用或解除"
	}
	out.VerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return out, nil
}

// The same read-only reference fence protects manual baseline replacement,
// website archive, uninstall and version changes. Corrupt/unknown inventory
// is not empty inventory. A failed release retains the original reference.
func (s *Service) integrityKernelReference(site string) error {
	rows, err := s.integrityKernelOperations()
	if err != nil {
		return err
	}
	latest := map[string]core.IntegrityKernelOperation{}
	for _, row := range rows {
		if site == "" || row.Request.Input.SiteID == site {
			latest[row.Request.Input.SiteID] = row
		}
	}
	for _, row := range latest {
		if (row.State == "declined" || row.State == "cancelled") && row.Request.Action == "enable" || row.State == "succeeded" && row.Request.Action == "release" {
			continue
		}
		return errors.New("网站仍有内核保护、排队或待核对原任务；先从原任务明确解除，数据、基线和执行记录保留")
	}
	return nil
}
