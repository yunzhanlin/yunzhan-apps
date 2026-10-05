// Package runtimecatalog contains the reviewed, immutable source allowlist.
// Updating it is a code release; clients cannot supply URLs, commands or digests.
package runtimecatalog

import "path/filepath"

type Release struct {
	ID      string `json:"id"`
	Family  string `json:"family"`
	Version string `json:"version"`
	Series  string `json:"series"`
	Channel string `json:"channel"`
	URL     string `json:"source_url"`
	SHA256  string `json:"sha256,omitempty"`
	Source  string `json:"source"`
}

var PHP = []Release{
	{"php-8.2.33", "php", "8.2.33", "8.2", "security", "https://www.php.net/distributions/php-8.2.33.tar.gz", "9a525d4db1237ede408e454b46f5a93b9e45d83d71753592e3f921903d917e07", "PHP 官方源码 · 2026-09-08 固定清单"},
	{"php-8.3.33", "php", "8.3.33", "8.3", "security", "https://www.php.net/distributions/php-8.3.33.tar.gz", "f43566da482abeb1614a512dabeda74967847ce8e176a977390d7a115e7812fd", "PHP 官方源码 · 2026-09-08 固定清单"},
	{"php-8.4.25", "php", "8.4.25", "8.4", "active", "https://www.php.net/distributions/php-8.4.25.tar.gz", "5cde1da976b728fa09e6b549a4c8afcd0c180337028dacf34f73b11be50253db", "PHP 官方源码 · 2026-09-08 固定清单"},
	{"php-8.5.10", "php", "8.5.10", "8.5", "active", "https://www.php.net/distributions/php-8.5.10.tar.gz", "f5c0ac99b85b3d677de475c2e4f509f9b4f54663f3ee5a84d6d9481a521d4100", "PHP 官方源码 · 2026-09-08 固定清单"},
}

// These hashes were verified against the official detached PGP signatures.
// Signer: 43387825DDB1BB97EC36BA5D007C8D7C15D87369 (nginx.org/keys/arut.key).
var Nginx = []Release{
	{"nginx-1.30.4", "nginx", "1.30.4", "1.30", "stable", "https://nginx.org/download/nginx-1.30.4.tar.gz", "4261dc90e9e47c1c4041276e9aaa3d48ebe2e664f728e14fa95ae6c67d57a08b", "Nginx 官方源码 · PGP 签名核对"},
	{"nginx-1.31.5", "nginx", "1.31.5", "1.31", "mainline", "https://nginx.org/download/nginx-1.31.5.tar.gz", "e951607d534836624bd36b6b45a71dbfb055237deae3738da6bbf3270dada279", "Nginx 官方源码 · PGP 签名核对"},
}

// Apache HTTP Server is built side by side and does not replace the global
// Nginx ingress. The digest is pinned from the official Apache SHA-256 file.
var Apache = []Release{
	{"apache-2.4.68", "apache", "2.4.68", "2.4", "stable", "https://downloads.apache.org/httpd/httpd-2.4.68.tar.gz", "ed9a9d4500fb48bb28eaffb3ba71d06ccf86d498fa13ab9f781da010cc488498", "Apache HTTP Server 官方源码 · 官方 SHA-256 清单"},
}

// Docker is installed from Debian's signed repository at an exact reviewed
// package version. It is host software rather than a side-by-side runtime.
var Docker = []Release{
	{"docker-debian-26.1.5", "docker", "26.1.5", "26", "debian", "https://packages.debian.org/trixie/docker.io", "", "Debian 13 官方仓库软件包 · 固定包版本"},
	{"docker-ce-29.8.2-bookworm", "docker", "29.8.2", "29", "official", "https://docs.docker.com/engine/install/debian/", "", "Docker 官方签名仓库 · Debian 12 固定包版本"},
}

const DockerEnginePackage = "docker.io"
const DockerEnginePackageVersion = "26.1.5+dfsg1-9+deb13u1"
const DockerCLIPackage = "docker-cli"
const DockerCLIPackageVersion = "26.1.5+dfsg1-9+deb13u1"
const DockerComposePackage = "docker-compose"
const DockerComposePackageVersion = "2.26.1-4"

type DockerInstallSpec struct {
	ReleaseID      string
	Packages       []string
	EngineVersion  string
	ComposeVersion string
	ExternalRepo   bool
}

func DockerSpecOn(major string) (DockerInstallSpec, bool) {
	switch major {
	case "12":
		return DockerInstallSpec{
			ReleaseID: "docker-ce-29.8.2-bookworm", EngineVersion: "29.8.2", ComposeVersion: "5.6.0", ExternalRepo: true,
			Packages: []string{
				"docker-ce=5:29.8.2-1~debian.12~bookworm",
				"docker-ce-cli=5:29.8.2-1~debian.12~bookworm",
				"containerd.io=2.3.6-1~debian.12~bookworm",
				"docker-buildx-plugin=0.37.1-1~debian.12~bookworm",
				"docker-compose-plugin=5.6.0-1~debian.12~bookworm",
			},
		}, true
	case "13":
		return DockerInstallSpec{
			ReleaseID: "docker-debian-26.1.5", EngineVersion: "26.1.5+dfsg1", ComposeVersion: "2.26.1-4",
			Packages: []string{
				DockerEnginePackage + "=" + DockerEnginePackageVersion,
				DockerCLIPackage + "=" + DockerCLIPackageVersion,
				DockerComposePackage + "=" + DockerComposePackageVersion,
			},
		}, true
	default:
		return DockerInstallSpec{}, false
	}
}

func All() []Release {
	all := append([]Release{}, PHP...)
	all = append(all, Nginx...)
	all = append(all, Apache...)
	all = append(all, Redis...)
	all = append(all, Node()...)
	all = append(all, MariaDB()...)
	all = append(all, Docker...)
	return append(all, MySQL()...)
}
func Find(id string) (Release, bool) {
	for _, r := range All() {
		if r.ID == id {
			return r, true
		}
	}
	return Release{}, false
}
func (r Release) Prefix() string { return filepath.Join("/opt/panel/runtimes", r.Family, r.Version) }
func (r Release) CLI() string {
	if r.Family == "nginx" {
		return filepath.Join(r.Prefix(), "sbin/nginx")
	}
	if r.Family == "apache" {
		return filepath.Join(r.Prefix(), "bin/httpd")
	}
	if r.Family == "mysql" {
		return filepath.Join(r.Prefix(), "bin/mysql")
	}
	if r.Family == "mariadb" {
		return filepath.Join(r.Prefix(), "bin/mariadb")
	}
	if r.Family == "docker" {
		return "/usr/bin/docker"
	}
	if r.Family == "redis" {
		return filepath.Join(r.Prefix(), "bin/redis-server")
	}
	if r.Family == "node" {
		return filepath.Join(r.Prefix(), "bin/node")
	}
	return filepath.Join(r.Prefix(), "bin/php")
}
func (r Release) FPM() string { return filepath.Join(r.Prefix(), "sbin/php-fpm") }
