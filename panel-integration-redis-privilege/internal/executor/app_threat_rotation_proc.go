package executor

import (
	"errors"
	"strconv"
	"strings"
)

// /proc directory ownership can be root for non-dumpable nonroot processes.
// Read the kernel's four real/effective/saved/filesystem UIDs instead; matching
// any one of them conservatively includes the account's retained descriptors.
func threatIDSProcAccount(status []byte, uid uint32) (bool, error) {
	if len(status) > 64<<10 || uid == 0 || uid >= 1000 {
		return false, errors.New("IDS 进程账户观察范围无效")
	}
	seen, matching := false, false
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "Uid" {
			continue
		}
		if seen {
			return false, errors.New("IDS 内核 UID 字段重复")
		}
		seen = true
		values := strings.Fields(value)
		if len(values) != 4 {
			return false, errors.New("IDS 内核 UID 集合不完整")
		}
		for _, value := range values {
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil || strconv.FormatUint(n, 10) != value {
				return false, errors.New("IDS 内核 UID 数值不可核对")
			}
			matching = matching || uint32(n) == uid
		}
	}
	if !seen {
		return false, errors.New("IDS 内核 UID 字段缺失")
	}
	return matching, nil
}
