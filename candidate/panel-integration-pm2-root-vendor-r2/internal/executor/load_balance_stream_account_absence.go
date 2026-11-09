package executor

import (
	"strings"

	"local/panel/internal/loadbalancestream"
)

// Creation absence is stricter than a missing passwd row: a pre-existing
// shadow/group/gshadow identity or delegated membership could give a newly
// created same-name account foreign privileges. This pure parser grants no
// creation authority and returns no secret or unrelated account information.
func validateLoadBalanceStreamAccountAbsence(passwd, group, shadow, gshadow []byte) error {
	name := loadbalancestream.ServiceAccount
	for index, source := range [][]byte{passwd, group, shadow, gshadow} {
		fields := []int{7, 4, 9, 4}[index]
		rows, err := memcachedUnixNSSRows(source, fields)
		if err != nil || len(rows) == 0 {
			return errLoadBalanceStreamAccount
		}
		seen := map[string]bool{}
		for _, row := range rows {
			if seen[row[0]] || row[0] == name {
				return errLoadBalanceStreamAccount
			}
			seen[row[0]] = true
			switch index {
			case 0:
				if _, ok := memcachedUnixNSSNumber(row[2]); !ok {
					return errLoadBalanceStreamAccount
				}
				if _, ok := memcachedUnixNSSNumber(row[3]); !ok {
					return errLoadBalanceStreamAccount
				}
			case 1:
				if _, ok := memcachedUnixNSSNumber(row[2]); !ok {
					return errLoadBalanceStreamAccount
				}
				for _, member := range strings.Split(row[3], ",") {
					if strings.TrimSpace(member) == name {
						return errLoadBalanceStreamAccount
					}
				}
			case 3:
				for _, membership := range row[2:] {
					for _, member := range strings.Split(membership, ",") {
						if strings.TrimSpace(member) == name {
							return errLoadBalanceStreamAccount
						}
					}
				}
			}
		}
	}
	return nil
}
