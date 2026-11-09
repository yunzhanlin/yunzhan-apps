//go:build !linux

package executor

import "errors"

func RunComposeJob(string) error { return errors.New("Docker Compose 管理仅支持 Linux") }
func RecoverComposeJobs() error  { return errors.New("Docker Compose 管理仅支持 Linux") }
