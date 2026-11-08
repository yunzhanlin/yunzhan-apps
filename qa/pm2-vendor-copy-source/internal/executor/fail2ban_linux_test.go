//go:build linux

package executor

import "testing"

func TestFail2banStatusParser(t *testing.T) {
	if names := parseFail2banJails("Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nginx-http-auth\n"); len(names) != 2 || names[0] != "sshd" || names[1] != "nginx-http-auth" {
		t.Fatalf("jails: %+v", names)
	}
	jail := parseFail2banJail("sshd", "|- Currently banned:\t2\n|- Total banned:\t5\n`- Banned IP list:\t192.0.2.15 2001:db8::3\n")
	if jail.CurrentlyBanned != 2 || jail.TotalBanned != 5 || len(jail.BannedIPs) != 2 {
		t.Fatalf("jail: %+v", jail)
	}
}
