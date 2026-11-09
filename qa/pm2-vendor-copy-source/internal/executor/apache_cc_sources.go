package executor

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
)

const apacheCCEngineVersion = "1.0.0"
const apacheCCRotationEngineVersion = "1.1.0"

func apacheCCFormatHasModule(format int) bool { return format == 2 || format == 3 }

func apacheCCEngineForFormat(format int) string {
	switch format {
	case 2:
		return apacheCCEngineVersion
	case 3:
		return apacheCCRotationEngineVersion
	default:
		return ""
	}
}

//go:embed assets/apache-cc-*
var apacheCCAssets embed.FS

func apacheCCAssetPins() map[string]string {
	return map[string]string{
		"apache-cc-log.h":    "01b5a69506068367e695e5e018adaf313362531887d174e2e311c3c36e2302e9",
		"apache-cc-core.h":   "7eedc366e2415b1d4b2da5f559bd6fb853f2d03114ee288db680dcf22d08256d",
		"apache-cc-module.c": "46788c6ff7bdbdd9f4504ac446da18eaabd076cca95ba08d84fae956636c6954",
		"apache-cc-LICENSE":  "b52f92aef98bd7d509e5abb037984bb3bcd64bc6f59798a8fd8a8d4f5323795d",
	}
}

func verifiedApacheCCAsset(name string) ([]byte, error) {
	want, ok := apacheCCAssetPins()[name]
	if !ok {
		want, ok = apacheCCRotationAssetPins()[name]
	}
	if !ok {
		return nil, errors.New("Apache CC 资源未在固定审核清单内")
	}
	b, err := apacheCCAssets.ReadFile("assets/" + name)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(b)
	if hex.EncodeToString(digest[:]) != want {
		return nil, errors.New("Apache CC 原生源码或许可固定摘要异常")
	}
	return b, nil
}

// Format2 keeps the original four exact resources. Format3 alone permits the
// independently pinned writer which refuses stale open descriptions after a
// locked name exchange. Old records are neither rewritten nor relabelled.
func apacheCCRotationAssetPins() map[string]string {
	old := apacheCCAssetPins()
	return map[string]string{
		"apache-cc-log-v2.h":    "55e1e7bb561d80a901a18f50b0168236caf3a3d0cce89e1e5efe0d4d52140074",
		"apache-cc-module-v2.c": "04fbbbe8d36c468cd9fb59cf63d13083d9f8456a737f6fbe46c7872ad68cd13b",
		"apache-cc-core.h":      old["apache-cc-core.h"],
		"apache-cc-LICENSE":     old["apache-cc-LICENSE"],
	}
}

// Format1 remains the exact accepted body-only build plan and asset set.
// Format2 adds one independently authored DSO; neither format adopts the
// other's record by relabeling its version or manufacturing missing proof.
func apacheBodyReleaseAssetPinsForFormat(format int) map[string]string {
	pins := apacheBodyReleaseAssetPins()
	if apacheCCFormatHasModule(format) {
		cc := apacheCCAssetPins()
		if format == 3 {
			cc = apacheCCRotationAssetPins()
		}
		for name, digest := range cc {
			pins[name] = digest
		}
	}
	return pins
}

func apacheBodyBuildPlanForFormat(paths apacheBodyBuildPaths, format int) ([]wafBuildCommand, error) {
	plan, err := apacheBodyNativeBuildPlan(paths)
	if err != nil {
		return nil, err
	}
	if format == 1 {
		return plan, nil
	}
	if !apacheCCFormatHasModule(format) {
		return nil, errors.New("Apache 引擎构建格式未实现")
	}
	module, label := "apache-cc-module.c", "非特权编译固定 Apache 原生共享 CC 模块"
	if format == 3 {
		module, label = "apache-cc-module-v2.c", "非特权编译固定 Apache 可轮转日志的原生共享 CC 模块"
	}
	plan = append(plan, wafBuildCommand{
		Label:     label,
		Directory: paths.Work,
		Program:   "/usr/bin/cc",
		Arguments: []string{"-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-g0", "-fPIC", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-shared", "-Wl,-z,relro,-z,now", "-I" + filepath.Join(paths.Apache, "include"), "-I/usr/include/apr-1.0", "-I" + paths.Assets, filepath.Join(paths.Assets, module), "-o", filepath.Join(paths.Work, "mod_yunzhan_cc.so"), "-lcrypto", "-pthread"},
	})
	return plan, nil
}

func validateApacheBodyCCBuildCommand(paths apacheBodyBuildPaths, index int, command wafBuildCommand) error {
	return validateApacheBodyCCBuildCommandForFormat(paths, 2, index, command)
}

func validateApacheBodyCCBuildCommandForFormat(paths apacheBodyBuildPaths, format, index int, command wafBuildCommand) error {
	plan, err := apacheBodyBuildPlanForFormat(paths, format)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(plan) || !reflect.DeepEqual(plan[index], command) {
		return errors.New("Apache CC 构建命令不属于对应的固定审核步骤")
	}
	return nil
}
