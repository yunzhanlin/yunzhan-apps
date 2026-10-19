//go:build linux

package executor

import (
	"errors"
	"strconv"
	"strings"
)

// A oneshot unit can remain active after an out-of-band unmount. Conversely,
// systemctl stop may return successfully even when ExecStop could not unmount
// a busy directory. Always inspect the kernel before claiming or forgetting it.
func nfsKernelMount(data, target string, expected nfsMount) (bool, error) {
	found := false
	for _, line := range strings.Split(data, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		fields, filesystem := strings.Fields(left), strings.Fields(right)
		if len(fields) < 6 || fields[4] != target {
			continue
		}
		if found {
			return true, errors.New("NFS 目录存在叠加挂载，拒绝操作")
		}
		found = true
		if !ok || len(filesystem) < 3 || (filesystem[0] != "nfs" && filesystem[0] != "nfs4") || filesystem[1] != expected.Source {
			return true, errors.New("NFS 挂载来源或文件系统与受管清单不符，保留外部挂载")
		}
		options := map[string]bool{}
		for _, option := range strings.Split(fields[5]+","+filesystem[2], ",") {
			options[option] = true
		}
		for _, required := range []string{"nosuid", "nodev", "noexec"} {
			if !options[required] {
				return true, errors.New("NFS 实际挂载缺少安全选项，保留记录以供检查")
			}
		}
		if expected.ReadOnly && !options["ro"] || !expected.ReadOnly && !options["rw"] {
			return true, errors.New("NFS 实际只读状态与受管清单不符")
		}
		port := expected.Port
		if port == 0 {
			port = 2049
		}
		actualPort := 2049
		for option := range options {
			if strings.HasPrefix(option, "port=") {
				var err error
				actualPort, err = strconv.Atoi(strings.TrimPrefix(option, "port="))
				if err != nil {
					return true, errors.New("NFS 实际端口不可验证")
				}
			}
		}
		if actualPort != port {
			return true, errors.New("NFS 实际远程端口与受管清单不符")
		}
	}
	return found, nil
}

func (s *Service) nfsMountStatus(m nfsMount) (bool, error) {
	data, err := readModuleProcFile(s.systemPath("/proc/self/mountinfo"), 1<<20)
	if err != nil {
		return false, err
	}
	return nfsKernelMount(string(data), "/srv/panel/nfs/"+m.ID, m)
}
