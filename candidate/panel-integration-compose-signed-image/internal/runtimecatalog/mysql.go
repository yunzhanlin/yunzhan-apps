package runtimecatalog

import "runtime"

// The official MySQL archives were verified against detached signatures from
// MySQL Release Engineering, fingerprint BCA43417C3B485DD128EC6D4B7B3B788A8D3785C.
func MySQLForArch(arch string) []Release {
	switch arch {
	case "arm64":
		return []Release{
			{"mysql-8.4.13", "mysql", "8.4.13", "8.4", "lts", "https://dev.mysql.com/get/Downloads/MySQL-8.4/mysql-8.4.13-linux-glibc2.28-aarch64.tar.xz", "6531bb50f64c986a2abdab6b647cbd553e8740b3e5d3867f5415e33568879fc9", "MySQL 官方二进制 · PGP 签名核对"},
			{"mysql-8.4.11", "mysql", "8.4.11", "8.4", "lts", "https://dev.mysql.com/get/Downloads/MySQL-8.4/mysql-8.4.11-linux-glibc2.28-aarch64.tar.xz", "04b2f9791d314167a9eb83abcb476f45a7cd9e4aa88fa7a638cba40d1bc2a109", "MySQL 官方二进制 · PGP 签名核对"},
			{"mysql-8.0.46", "mysql", "8.0.46", "8.0", "eol", "https://dev.mysql.com/get/Downloads/MySQL-8.0/mysql-8.0.46-linux-glibc2.28-aarch64.tar.xz", "49cda0de886b021df1c2e3e382164ca3c61e93e7e5c4ee90849e13862e30dd7f", "MySQL 官方二进制 · PGP 签名核对"},
		}
	case "amd64":
		return []Release{
			{"mysql-8.4.13", "mysql", "8.4.13", "8.4", "lts", "https://dev.mysql.com/get/Downloads/MySQL-8.4/mysql-8.4.13-linux-glibc2.28-x86_64-minimal.tar.xz", "5dfbb764f731df40ef9e4f5d69aed32bdac8ba1af20bd96b7d40a942d83d4ed2", "MySQL 官方二进制 · PGP 签名核对"},
			{"mysql-8.4.11", "mysql", "8.4.11", "8.4", "lts", "https://dev.mysql.com/get/Downloads/MySQL-8.4/mysql-8.4.11-linux-glibc2.28-x86_64-minimal.tar.xz", "383f54e124d5f325d67f0c6912a8f96814eedc761a17ea30112e52fa4cc6b143", "MySQL 官方二进制 · PGP 签名核对"},
			{"mysql-8.0.46", "mysql", "8.0.46", "8.0", "eol", "https://dev.mysql.com/get/Downloads/MySQL-8.0/mysql-8.0.46-linux-glibc2.28-x86_64.tar.xz", "0fcdb2e88b5bb151118420745070a34621463dd85a50e1eacd7c3aa1b9d1f4a2", "MySQL 官方二进制 · PGP 签名核对"},
		}
	}
	return nil
}
func MySQL() []Release { return MySQLForArch(runtime.GOARCH) }

func IsMySQL84MigrationTarget(id string) bool {
	r, found := Find(id)
	return found && r.Family == "mysql" && r.Series == "8.4"
}
