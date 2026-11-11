//go:build linux

package executor

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const sysvInitDirectory = "/etc/init.d"

func openTaskStartupDirectory(path string) (*os.File, error) {
	directory, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	info, err := directory.Stat()
	if err == nil {
		stat, valid := info.Sys().(*syscall.Stat_t)
		if valid && stat.Uid == 0 && info.Mode().Perm()&0o022 == 0 {
			return directory, nil
		}
		err = errors.New("启动目录的权限无法核对")
	}
	directory.Close()
	return nil, err
}

func (out *taskInventory) taskStartupNames(directory *os.File) ([]string, error) {
	names, err := directory.Readdirnames(taskInventoryLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > taskInventoryLimit {
		out.Partial = true
		names = names[:taskInventoryLimit]
	}
	sort.Strings(names)
	return names, nil
}

func validSysVName(name string) bool {
	const lettersAndNumbers = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return name != "" && len(name) <= 120 && strings.ContainsRune(lettersAndNumbers, rune(name[0])) &&
		strings.Trim(name, lettersAndNumbers+"_.-") == ""
}

func (s *Service) taskSysVStartup(out *taskInventory) error {
	directory, err := openTaskStartupDirectory(s.systemPath(sysvInitDirectory))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("无法核对 SysV 初始化目录")
	}
	defer directory.Close()
	names, err := out.taskStartupNames(directory)
	if err != nil {
		return errors.New("无法读取 SysV 初始化目录")
	}
	scripts := map[string][]string{}
	for _, name := range names {
		if !validSysVName(name) {
			continue
		}
		var stat unix.Stat_t
		if unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil {
			out.Partial = true
			continue
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == 0 && stat.Mode&0o022 == 0 && stat.Mode&0o111 != 0 {
			scripts[name] = nil
		}
	}
	for _, level := range []string{"S", "1", "2", "3", "4", "5"} {
		if err := s.taskSysVRunlevel(out, level, scripts); err != nil {
			out.Partial = true
		}
	}
	for _, name := range names {
		levels, present := scripts[name]
		if !present {
			continue
		}
		state := "未发现启动链接"
		if len(levels) > 0 {
			state = "已登记启动链接"
		}
		out.add(map[string]string{
			"name": name, "startup_state": state, "preset": "", "source": "SysV",
			"runlevels": strings.Join(levels, "、"),
		})
	}
	return nil
}

func (s *Service) taskSysVRunlevel(out *taskInventory, level string, scripts map[string][]string) error {
	path := "/etc/rc" + level + ".d"
	directory, err := openTaskStartupDirectory(s.systemPath(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
	names, err := out.taskStartupNames(directory)
	if err != nil {
		return err
	}
	buffer := make([]byte, 512)
	for _, entry := range names {
		if len(entry) < 4 || entry[0] != 'S' || entry[1] < '0' || entry[1] > '9' || entry[2] < '0' || entry[2] > '9' {
			continue
		}
		name := entry[3:]
		levels, tracked := scripts[name]
		if !tracked || len(levels) > 0 && levels[len(levels)-1] == level {
			continue
		}
		n, err := unix.Readlinkat(int(directory.Fd()), entry, buffer)
		if err != nil || n == len(buffer) {
			out.Partial = true
			continue
		}
		target := string(buffer[:n])
		if target == filepath.Join(sysvInitDirectory, name) || target == "../init.d/"+name {
			scripts[name] = append(levels, level)
		} else {
			out.Partial = true
		}
	}
	return nil
}
