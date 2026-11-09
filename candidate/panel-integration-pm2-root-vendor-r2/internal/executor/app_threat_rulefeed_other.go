//go:build !linux

package executor

import "errors"

func RunNetworkIDSRuleFeedInstall(string) error {
	return errors.New("IDS 规则安装仅支持已审核 Linux")
}
