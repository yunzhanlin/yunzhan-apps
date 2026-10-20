package executor

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

const apacheBodyJobs = "/var/lib/panel-executor/apache-body-builds"
const apacheBodyRequests = "/var/lib/panel-executor/apache-body-requests"
const apacheBodyCancellations = "/var/lib/panel-executor/apache-body-cancellations"
const apacheBodyEngines = "/opt/panel/app-modules/apache-waf/engines"
const apacheBodyCache = "/var/cache/panel-apache-body-build"
const apacheBodyCompilerCollectionContract = nativeCompilerCollectionContract

// Ready is a sealed, independently probed program, not website activation.
// Keep this authority separate from the v3/Nginx engine record and namespaces.
type apacheBodyBuildRecord struct {
	Format              int               `json:"format"`
	JobID               string            `json:"job_id"`
	State               string            `json:"state"`
	Error               string            `json:"error,omitempty"`
	Architecture        string            `json:"architecture"`
	Engine              string            `json:"engine_version"`
	YAJL                string            `json:"yajl_version"`
	CRS                 string            `json:"crs_version"`
	ApacheVersion       string            `json:"apache_version"`
	ApacheBinary        string            `json:"apache_binary"`
	ApacheSHA           string            `json:"apache_sha256"`
	Prefix              string            `json:"prefix"`
	ModuleSHA           string            `json:"module_sha256,omitempty"`
	TreeSHA             string            `json:"tree_sha256,omitempty"`
	SourceSHA           map[string]string `json:"source_sha256"`
	AssetSHA            map[string]string `json:"asset_sha256"`
	StartedAt           string            `json:"started_at"`
	FinishedAt          string            `json:"finished_at,omitempty"`
	CompletedBuildSteps []string          `json:"completed_build_steps"`
	Steps               []core.Step       `json:"steps"`
	ABIValidated        bool              `json:"module_abi_validated"`
	HardeningValidated  bool              `json:"elf_hardening_validated"`
	CompilerCollected   bool              `json:"compiler_groups_collected"`
	CompilerCollection  string            `json:"compiler_collection_contract,omitempty"`
	ProductionUsed      bool              `json:"production_loaded"`
}

func apacheBodyReleaseSources() []wafEngineSource {
	// CRS has its own reviewed source authority. Adding it here neither admits
	// arbitrary URLs nor imports the Nginx connector or v3 engine sources.
	return append(apacheBodySources(), wafEngineSources()[2])
}

func apacheBodyReleaseAssetPins() map[string]string {
	pins := apacheBodyAssetPins()
	pins["modsecurity-crs-LICENSE"] = wafEngineAssetPins()["modsecurity-crs-LICENSE"]
	return pins
}

func verifiedApacheBodyReleaseAsset(name string) ([]byte, error) {
	if name == "modsecurity-crs-LICENSE" {
		return verifiedWAFEngineAsset(name)
	}
	return verifiedApacheBodyAsset(name)
}

func apacheBodyPaths(id string) apacheBodyBuildPaths {
	return apacheBodyBuildPaths{filepath.Join(apacheBodyCache, id, "work"), filepath.Join(apacheBodyCache, id, "compiler-prefix"), filepath.Join(apacheBodyCache, id, "assets"), "/opt/panel/runtimes/apache/2.4.68"}
}

func apacheBodyRecordContract(record apacheBodyBuildRecord) error {
	if record.CompilerCollection != apacheBodyCompilerCollectionContract {
		return errors.New("Apache 程序缺少当前专用 cgroup 与稳定进程回收证据，旧进程组标记不能授权启用")
	}
	return apacheBodyRecordAuthorityContract(record, apacheBodyEngineVersion, apacheBodyReleaseAssetPins())
}

// Exact previous YZ4, group-only YZ5 and pre-reap-witness YZ5 bytes may be
// inspected, never activated. v1 had an exit/adoption race and is not upgraded.
// No migration invents the stronger collection witness or rewrites old records.
func apacheBodyRetainedRecordContract(record apacheBodyBuildRecord) error {
	if record.CompilerCollection != "" && record.CompilerCollection != "dedicated_cgroup_v2_pidfd_reaped_v1" {
		return errors.New("保留程序含未知或当前回收契约，不属于闭合历史查阅范围")
	}
	pins := apacheBodyReleaseAssetPins()
	if record.Engine == "2.9.15-yz4" {
		if record.CompilerCollection != "" {
			return errors.New("历史 YZ4 不存在该回收契约，未混合版本证据")
		}
		pins["apache-body-metadata-only.patch"] = "f5d505b5e281a42f23ad49c32c5c9e2c778a84b041308d06b286a6cb927623f1"
		return apacheBodyRecordAuthorityContract(record, "2.9.15-yz4", pins)
	}
	if record.Engine != apacheBodyEngineVersion {
		return errors.New("保留程序不是精确审核的历史版本")
	}
	return apacheBodyRecordAuthorityContract(record, apacheBodyEngineVersion, pins)
}

func apacheBodyRecordAuthorityContract(record apacheBodyBuildRecord, engine string, assets map[string]string) error {
	r, ok := runtimecatalog.Find("apache-2.4.68")
	if !ok || record.Format != 1 || !core.ValidID(record.JobID) || record.State != "ready" || record.Error != "" || record.ProductionUsed || !record.ABIValidated || !record.HardeningValidated || !record.CompilerCollected || record.Architecture != runtime.GOARCH || record.Engine != engine || record.YAJL != apacheBodyYAJLVersion || record.CRS != wafBodyCRSVersion || record.ApacheVersion != r.Version || record.ApacheBinary != r.CLI() || record.Prefix != filepath.Join(apacheBodyEngines, record.JobID) {
		return errors.New("Apache 请求体程序未完成、架构不匹配或发布身份异常")
	}
	for _, digest := range []string{record.ApacheSHA, record.ModuleSHA, record.TreeSHA} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || digest != strings.ToLower(digest) {
			return errors.New("Apache 程序完整摘要缺失或格式异常")
		}
	}
	if len(record.SourceSHA) != len(apacheBodyReleaseSources()) || len(record.AssetSHA) != len(assets) {
		return errors.New("Apache 原始源码、补丁或完整许可清单不完整")
	}
	for _, source := range apacheBodyReleaseSources() {
		if record.SourceSHA[source.Name] != source.SHA256 {
			return errors.New("Apache 原始源码摘要不是本发布审核版本")
		}
	}
	for name, sha := range assets {
		if record.AssetSHA[name] != sha {
			return errors.New("Apache 补丁、许可或变更通知摘要不匹配")
		}
	}
	plan, err := apacheBodyNativeBuildPlan(apacheBodyPaths(record.JobID))
	if err != nil {
		return err
	}
	labels := []string{}
	for _, command := range plan {
		labels = append(labels, command.Label)
	}
	if !reflect.DeepEqual(record.CompletedBuildSteps, labels) {
		return errors.New("Apache 固定编译步骤没有按顺序全部完成")
	}
	start, err := time.Parse(time.RFC3339, record.StartedAt)
	if err != nil {
		return errors.New("Apache 构建开始时间无效")
	}
	finish, err := time.Parse(time.RFC3339, record.FinishedAt)
	if err != nil || finish.Before(start) || finish.Sub(start) > 4*time.Hour || len(record.Steps) < len(plan) || len(record.Steps) > 48 {
		return errors.New("Apache 构建结束时间或审计步骤无效")
	}
	previous := start
	for _, step := range record.Steps {
		at, err := time.Parse(time.RFC3339, step.Time)
		if err != nil || at.Before(previous) || at.After(finish) || step.Message == "" || len(step.Message) > 512 || strings.ContainsRune(step.Message, '\x00') {
			return errors.New("Apache 构建审计步骤时间、顺序或内容异常")
		}
		previous = at
	}
	return nil
}
