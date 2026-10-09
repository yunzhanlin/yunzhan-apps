package core

// RemoteSyncTarget is public connection policy, never authentication material.
// Fixed IP and an exact public host key are required: no TOFU, DNS changes,
// arbitrary SSH command, proxy command, agent, or automatic shell fallback.
type RemoteSyncTarget struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	HostKey    string `json:"host_key"`
	Root       string `json:"root"`
	BackupRoot string `json:"backup_root"`
}
