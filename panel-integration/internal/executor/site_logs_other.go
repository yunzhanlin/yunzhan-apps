//go:build !linux

package executor

import "errors"

func readSiteLog(id, kind string) (string, error) { return "", errors.New("站点日志需要 Linux") }
