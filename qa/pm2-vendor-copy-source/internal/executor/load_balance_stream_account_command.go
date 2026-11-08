package executor

import "local/panel/internal/loadbalancestream"

// Fixed shadow-utils argv only: no password, chosen UID/GID, extra groups,
// home, subuid allocation, account adoption, shell source or caller path.
func loadBalanceStreamAccountCreationArgs() []string {
	return []string{
		"--system", "--user-group", "--no-create-home", "--no-log-init",
		"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
		"--comment", loadbalancestream.ServiceAccount, "--groups", "",
		"--key", "SYS_UID_MIN=100", "--key", "SYS_UID_MAX=999",
		"--key", "SYS_GID_MIN=100", "--key", "SYS_GID_MAX=999",
		"--", loadbalancestream.ServiceAccount,
	}
}
