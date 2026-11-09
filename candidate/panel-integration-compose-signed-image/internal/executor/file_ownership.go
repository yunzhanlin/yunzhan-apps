package executor

import (
	"errors"
	"os"
)

type fileOwner struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

func existingFileOwner(path string) (*fileOwner, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("原子写入目标不是普通文件；未替换异常路径")
	}
	return fileOwnerForInfo(info)
}
