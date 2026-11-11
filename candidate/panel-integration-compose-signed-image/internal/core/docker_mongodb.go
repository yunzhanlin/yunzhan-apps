package core

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MongoDBKernelCompatibility checks the startup requirements of the pinned
// MongoDB 8.0 image against the running Linux kernel.
func MongoDBKernelCompatibility() error {
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return errors.New("无法读取当前 Linux 内核版本，不能确认 MongoDB 8.0 兼容性")
	}
	return mongoDBKernelCompatibility(string(release))
}

func mongoDBKernelCompatibility(release string) error {
	release = strings.TrimSpace(release)
	number := release
	if end := strings.IndexAny(number, "-+"); end >= 0 {
		number = number[:end]
	}
	parts := strings.Split(number, ".")
	var version [3]int
	for i := range version {
		if i >= len(parts) {
			return errors.New("无法识别当前 Linux 内核版本，不能确认 MongoDB 8.0 兼容性")
		}
		value, err := strconv.Atoi(parts[i])
		if err != nil || value < 0 {
			return errors.New("无法识别当前 Linux 内核版本，不能确认 MongoDB 8.0 兼容性")
		}
		version[i] = value
	}
	major, minor, patch := version[0], version[1], version[2]
	// Match the actual release reported to the container. Ubuntu may have a
	// backport without reporting the upstream patch number (SERVER-136848).
	if (major == 6 && minor >= 19) || (major == 7 && minor == 0 && patch < 14) {
		return fmt.Errorf("MongoDB 8.0 与 Linux 内核 %s 不兼容。此镜像需要 Linux 6.19 以前或 7.0.14 及以上的内核", release)
	}
	return nil
}
