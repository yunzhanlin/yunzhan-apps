package runtimecatalog

import "runtime"

// MariaDB Foundation currently publishes generic systemd binary archives for
// x86_64 only. Digests are pinned from its official Downloads REST API.
func MariaDBForArch(arch string) []Release {
	if arch != "amd64" {
		return nil
	}
	return []Release{
		{"mariadb-11.4.13", "mariadb", "11.4.13", "11.4", "lts", "https://archive.mariadb.org/mariadb-11.4.13/bintar-linux-systemd-x86_64/mariadb-11.4.13-linux-systemd-x86_64.tar.gz", "3cebf63914df3154b7cb6d548337eb2be42c773aeb641110446b72e2746cfed7", "MariaDB Foundation 官方二进制 · 官方 SHA-256 清单"},
		{"mariadb-11.8.9", "mariadb", "11.8.9", "11.8", "lts", "https://archive.mariadb.org/mariadb-11.8.9/bintar-linux-systemd-x86_64/mariadb-11.8.9-linux-systemd-x86_64.tar.gz", "32f8871a2aa38b36aa418b7f4abc6fc0c6ef1ba5a45798cacb2afa52c8a6113b", "MariaDB Foundation 官方二进制 · 官方 SHA-256 清单"},
	}
}

func MariaDB() []Release { return MariaDBForArch(runtime.GOARCH) }
