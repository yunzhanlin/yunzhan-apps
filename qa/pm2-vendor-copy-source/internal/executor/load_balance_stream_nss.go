package executor

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

var errLoadBalanceStreamIdentity = errors.New("TCP/UDP 服务专用的本地锁定账户、独占 UID/GID 或完整 NSS 身份无法核对；未创建、接管或修改账户")

// Private Root facts only. Neither a label nor this digest grants account,
// listener, command, installation, service-start or recovery authority.
type loadBalanceStreamIdentity struct {
	UID    uint32
	GID    uint32
	SHA256 string
}

func validateLoadBalanceStreamNSS(passwd, group, shadow, gshadow []byte) (loadBalanceStreamIdentity, error) {
	var empty loadBalanceStreamIdentity
	name := loadbalancestream.ServiceAccount
	users, err := memcachedUnixNSSRows(passwd, 7)
	if err != nil {
		return empty, errLoadBalanceStreamIdentity
	}
	var selected []string
	for _, row := range users {
		if row[0] == name {
			if selected != nil {
				return empty, errLoadBalanceStreamIdentity
			}
			selected = row
		}
	}
	if selected == nil {
		return empty, errLoadBalanceStreamIdentity
	}
	uid, ok1 := memcachedUnixNSSNumber(selected[2])
	gid, ok2 := memcachedUnixNSSNumber(selected[3])
	if !ok1 || !ok2 || uid < 100 || uid >= 1000 || gid < 100 || gid >= 1000 || selected[1] != "x" || selected[4] != name || selected[5] != "/nonexistent" || (selected[6] != "/usr/sbin/nologin" && selected[6] != "/sbin/nologin") {
		return empty, errLoadBalanceStreamIdentity
	}
	for _, row := range users {
		u, ok1 := memcachedUnixNSSNumber(row[2])
		g, ok2 := memcachedUnixNSSNumber(row[3])
		if !ok1 || !ok2 || row[0] != name && (u == uid || g == gid) {
			return empty, errLoadBalanceStreamIdentity
		}
	}
	groups, err := memcachedUnixNSSRows(group, 4)
	if err != nil {
		return empty, errLoadBalanceStreamIdentity
	}
	var selectedGroup []string
	for _, row := range groups {
		g, ok := memcachedUnixNSSNumber(row[2])
		if !ok {
			return empty, errLoadBalanceStreamIdentity
		}
		if row[0] == name || g == gid {
			if selectedGroup != nil || row[0] != name || g != gid || row[1] != "x" || row[3] != "" {
				return empty, errLoadBalanceStreamIdentity
			}
			selectedGroup = row
		} else {
			for _, member := range strings.Split(row[3], ",") {
				if strings.TrimSpace(member) == name {
					return empty, errLoadBalanceStreamIdentity
				}
			}
		}
	}
	if selectedGroup == nil {
		return empty, errLoadBalanceStreamIdentity
	}
	secrets, err := memcachedUnixNSSRows(shadow, 9)
	if err != nil {
		return empty, errLoadBalanceStreamIdentity
	}
	var selectedShadow []string
	for _, row := range secrets {
		if row[0] == name {
			if selectedShadow != nil || row[1] == "" || (!strings.HasPrefix(row[1], "!") && !strings.HasPrefix(row[1], "*")) {
				return empty, errLoadBalanceStreamIdentity
			}
			selectedShadow = row
		}
	}
	if selectedShadow == nil {
		return empty, errLoadBalanceStreamIdentity
	}
	privateGroups, err := memcachedUnixNSSRows(gshadow, 4)
	if err != nil {
		return empty, errLoadBalanceStreamIdentity
	}
	var selectedPrivateGroup []string
	for _, row := range privateGroups {
		if row[0] == name {
			if selectedPrivateGroup != nil || row[1] == "" || (!strings.HasPrefix(row[1], "!") && !strings.HasPrefix(row[1], "*")) || row[2] != "" || row[3] != "" {
				return empty, errLoadBalanceStreamIdentity
			}
			selectedPrivateGroup = row
		} else {
			for _, list := range row[2:4] {
				for _, member := range strings.Split(list, ",") {
					if strings.TrimSpace(member) == name {
						return empty, errLoadBalanceStreamIdentity
					}
				}
			}
		}
	}
	if selectedPrivateGroup == nil {
		return empty, errLoadBalanceStreamIdentity
	}
	// Do not retain or return password fields, even locked ones. Bind only
	// digests of this account's four selected records, not unrelated secrets.
	binding := struct {
		Format  int    `json:"format"`
		Name    string `json:"name"`
		UID     string `json:"uid"`
		GID     string `json:"gid"`
		Passwd  string `json:"passwd_sha256"`
		Group   string `json:"group_sha256"`
		Shadow  string `json:"shadow_sha256"`
		Gshadow string `json:"gshadow_sha256"`
	}{1, name, strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10), core.Hash(strings.Join(selected, ":")), core.Hash(strings.Join(selectedGroup, ":")), core.Hash(strings.Join(selectedShadow, ":")), core.Hash(strings.Join(selectedPrivateGroup, ":"))}
	raw, err := json.Marshal(binding)
	if err != nil {
		return empty, errLoadBalanceStreamIdentity
	}
	return loadBalanceStreamIdentity{UID: uid, GID: gid, SHA256: core.Hash(string(raw))}, nil
}
