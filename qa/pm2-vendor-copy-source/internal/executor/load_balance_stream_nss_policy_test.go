package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamNSSPolicyClosedLocalAndSystemdSources(t *testing.T) {
	for _, value := range []string{
		"passwd: files\ngroup: files\nshadow: files\ngshadow: files\n",
		"# Normal local identity sources\npasswd: files systemd\ngroup: files systemd\nshadow: files systemd\ngshadow: files systemd\nhosts: resolve [!UNAVAIL=return] files dns\n",
		"passwd: files systemd\ngroup: files [SUCCESS=merge] systemd\nshadow: files systemd\ngshadow: files systemd\ninitgroups: files [SUCCESS=merge] systemd\n",
	} {
		if validateLoadBalanceStreamNSSPolicy([]byte(value)) != nil {
			t.Fatal("documented local/systemd policy refused")
		}
	}
}

func TestLoadBalanceStreamNSSPolicyRejectsUnavailableOrAmbiguousIdentitySources(t *testing.T) {
	good := "passwd: files systemd\ngroup: files systemd\nshadow: files systemd\ngshadow: files systemd\n"
	for _, database := range []string{"passwd", "group", "shadow", "gshadow"} {
		for _, value := range []string{"files ldap", "sss files", "files winbind", "compat", "files db", "systemd files", "files systemd systemd", "files [UNAVAIL=return] systemd", "files [NOTFOUND=return] systemd", "files [SUCCESS=return] systemd", "files [SUCCESS=merge] ldap", "files\n" + database + ": files", "", "files: systemd"} {
			t.Run(database+"/"+strings.ReplaceAll(value, "\n", "-"), func(t *testing.T) {
				changed := strings.Replace(good, database+": files systemd\n", database+": "+value+"\n", 1)
				if validateLoadBalanceStreamNSSPolicy([]byte(changed)) != errLoadBalanceStreamNSSPolicy {
					t.Fatal("unsupported/ambiguous identity source admitted")
				}
			})
		}
		for _, changed := range []string{strings.Replace(good, database+": files systemd\n", "", 1), good + database + ": files\n", good + database + " files\n"} {
			if validateLoadBalanceStreamNSSPolicy([]byte(changed)) != errLoadBalanceStreamNSSPolicy {
				t.Fatal("missing/duplicate/malformed critical source admitted")
			}
		}
	}
	for _, value := range []string{"", strings.TrimSuffix(good, "\n"), good + "\x00", strings.ReplaceAll(good, "\n", "\r\n"), good + "initgroups: files ldap\n", good + strings.Repeat("#", 65536)} {
		if validateLoadBalanceStreamNSSPolicy([]byte(value)) != errLoadBalanceStreamNSSPolicy {
			t.Fatal("unbounded/noncanonical or remote initgroups configuration admitted")
		}
	}
}
