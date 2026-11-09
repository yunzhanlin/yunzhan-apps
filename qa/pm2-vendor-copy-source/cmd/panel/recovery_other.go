//go:build !linux

package main

import "errors"

func recoverLocalAccount(data, name string) error {
	return errors.New("请在安装面板的 Linux 主机以 root 执行本机救援")
}
