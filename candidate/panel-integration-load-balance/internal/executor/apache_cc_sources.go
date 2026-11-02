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

// Format1 remains the exact accepted body-only build plan and asset set.
// Format2 adds one independently authored DSO; neither format adopts the
// other's record by relabeling its version or manufacturing missing proof.
func apacheBodyReleaseAssetPinsForFormat(format int) map[string]string {
	pins := apacheBodyReleaseAssetPins()
	if format == 2 {
		for name, digest := range apacheCCAssetPins() {
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
	if format != 2 {
		return nil, errors.New("Apache 引擎构建格式未实现")
	}
	plan = append(plan, wafBuildCommand{
		Label:     "非特权编译固定 Apache 原生共享 CC 模块",
		Directory: paths.Work,
		Program:   "/usr/bin/cc",
		Arguments: []string{"-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-g0", "-fPIC", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-shared", "-Wl,-z,relro,-z,now", "-I" + filepath.Join(paths.Apache, "include"), "-I/usr/include/apr-1.0", "-I" + paths.Assets, filepath.Join(paths.Assets, "apache-cc-module.c"), "-o", filepath.Join(paths.Work, "mod_yunzhan_cc.so"), "-lcrypto", "-pthread"},
	})
	return plan, nil
}

func validateApacheBodyCCBuildCommand(paths apacheBodyBuildPaths, index int, command wafBuildCommand) error {
	plan, err := apacheBodyBuildPlanForFormat(paths, 2)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(plan) || !reflect.DeepEqual(plan[index], command) {
		return errors.New("Apache CC 构建命令不属于对应的固定审核步骤")
	}
	return nil
}
