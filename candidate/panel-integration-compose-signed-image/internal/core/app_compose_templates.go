package core

import (
	"fmt"
	"strconv"
	"strings"
)

const legacyNginxImage = "nginx:1.30.6-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5"

const LegacyPHP81BookwormTemplate = "php-legacy-81-bookworm"
const legacyPHP81BookwormCompat2Template = "php-legacy-81-bookworm-compat2"
const legacyPHP80BullseyeTemplate = "php-legacy-80-bullseye"
const legacyPHP80BullseyeCompat2Template = "php-legacy-80-bullseye-compat2"
const legacyPHP74BullseyeTemplate = "php-legacy-74-bullseye"
const legacyPHP74BullseyeCompat3Template = "php-legacy-74-bullseye-compat3"
const legacyPHP52BookwormTemplate = "php-legacy-52-bookworm"

const legacyPHP81BookwormImage = "ghcr.io/yunzhanlin/yunzhan-apps-php81:8.1.34-compat1@sha256:5afb2145c6441b3a3f524fd7542b35f252d06d81525064ac16d67ae7568a3f2d"

const LegacyPHPPlaceholder = `<?php header("Content-Type: application/json"); echo json_encode(array("version"=>PHP_VERSION,"sapi"=>php_sapi_name(),"mysql"=>extension_loaded("mysql"),"mysqli"=>extension_loaded("mysqli"),"pdo_mysql"=>extension_loaded("pdo_mysql"))); ?>` + "\n"

var LegacyPHPImages = map[string]string{
	"php-legacy-52": "devilbox/php-fpm:5.2-mods@sha256:828b23fa58707af737868450ce54322f663dfdbac659142eb89f20d04a347804",
	"php-legacy-53": "devilbox/php-fpm:5.3-mods@sha256:0970426b4057797c199c0fbc20644c68cdd1b2d536d6444bbc7b428680c5353d",
	"php-legacy-54": "devilbox/php-fpm:5.4-mods@sha256:8ef285267bd5474f66bab025db05b61099e3b49d3f4ce2114354f6d96b94f226",
	"php-legacy-55": "devilbox/php-fpm:5.5-mods@sha256:35adf2d78687d90eeac58e486d38fa6a4dd370fd930bbf237fa277e90dd45fbc",
	"php-legacy-56": "devilbox/php-fpm:5.6-mods@sha256:29b317b07fe5473f774cbdc05c6ee7f31b1af647b72785107bbfe31aa0d80426",
	"php-legacy-70": "devilbox/php-fpm:7.0-mods@sha256:b2ded3e0a1ee36da20c79ec8f3461026559b85c27126015dd46bf04e4793c961",
	"php-legacy-71": "devilbox/php-fpm:7.1-mods@sha256:09fa041ccf308ca9f694e4812a7e2a315ddba988901f96f646f2923a29ba88aa",
	"php-legacy-72": "devilbox/php-fpm:7.2-mods@sha256:f0d61ef2490243a4ab25a5d620567995449a5318683e8eb277e2cd9c232bced6",
	"php-legacy-73": "devilbox/php-fpm:7.3-mods@sha256:f4a7983a8f0da0f883038d8e7414532608ee80e0da11be17567caf539e22194d",
	"php-legacy-74": "devilbox/php-fpm:7.4-mods@sha256:f672e26b354d5c50271f01aaa1cb646e5769aca340be193a6faafa43b0501896",
	"php-legacy-80": "devilbox/php-fpm:8.0-mods@sha256:95cdcafdc30064ff49a7456c8fccf65ff2fd39301ff2244a93e3c9f0ac2a3c10",
	"php-legacy-81": "devilbox/php-fpm:8.1-mods@sha256:30ed5320f8003e5dde008dfdffa5d3647f0cc41a7004cea6cb40dda005583320",
}

type finalLegacyPHPRelease struct {
	template, previous, appID, version, appVersion, image string
}

var finalLegacyPHPReleases = []finalLegacyPHPRelease{
	{legacyPHP81BookwormCompat2Template, LegacyPHP81BookwormTemplate, "php-81", "8.1.34", "8.1.34-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php81:8.1.34-compat2@sha256:afda4abcf8755a50879d77643533d1af624236711c6cdf4e40653b09cbfc0830"},
	{LegacyPHP81BookwormTemplate, "php-legacy-81", "php-81", "8.1.34", "8.1.34-compat1", legacyPHP81BookwormImage},
	{legacyPHP80BullseyeCompat2Template, legacyPHP80BullseyeTemplate, "php-80", "8.0.30", "8.0.30-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php80:8.0.30-compat2@sha256:6f1ded5a5e08fc7f31efc5416cc0b877d75f94f576ed0d44bbb8d78319da3eed"},
	{legacyPHP80BullseyeTemplate, "php-legacy-80", "php-80", "8.0.30", "8.0.30-compat1", "ghcr.io/yunzhanlin/yunzhan-apps-php80:8.0.30-compat1@sha256:984e0174e4cfb31348ddc7dbe762de771e16961b20fa23a89779e2e27b3670a3"},
	{legacyPHP74BullseyeCompat3Template, legacyPHP74BullseyeTemplate, "php-74", "7.4.33", "7.4.33-compat3", "ghcr.io/yunzhanlin/yunzhan-apps-php74:7.4.33-compat3@sha256:cce1df42ef6874ea19eab10615822a4677e44004bfc0b2c3e4ee23db475c3b9d"},
	{legacyPHP74BullseyeTemplate, "php-legacy-74", "php-74", "7.4.33", "7.4.33-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php74:7.4.33-compat2@sha256:e186cbfc73ab5f3bb305b5be0db073f52e42855dcf8ff959993d4490edcef609"},
	{"php-legacy-73-buster", "php-legacy-73", "php-73", "7.3.33", "7.3.33-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php73:7.3.33-compat2@sha256:1eb9e3a0a3e87ed62ed6753d0163434e2f5ac4e25160410636ef8d79522b811e"},
	{"php-legacy-72-buster", "php-legacy-72", "php-72", "7.2.34", "7.2.34-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php72:7.2.34-compat2@sha256:f0912cb90007593fd8eae5ea842c03f536b8d89b770a4f85db75a906b5571625"},
	{"php-legacy-71-stretch", "php-legacy-71", "php-71", "7.1.33", "7.1.33-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php71:7.1.33-compat2@sha256:71ba20833894aabe0ed1089ec94fdc098f7fc8979750c84d99cef1ff88f047c9"},
	{"php-legacy-70-stretch", "php-legacy-70", "php-70", "7.0.33", "7.0.33-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php70:7.0.33-compat2@sha256:d5fd374b5226e21940d2517ca0b3d8ecf24a7026a413a7a672b502a092f5b83e"},
	{"php-legacy-56-stretch", "php-legacy-56", "php-56", "5.6.40", "5.6.40-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php56:5.6.40-compat2@sha256:6899f1a035633574ca09573da446be76a7fcd303566049fa60293ad442c8b9f8"},
	{"php-legacy-55-bookworm", "php-legacy-55", "php-55", "5.5.38", "5.5.38-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php55:5.5.38-compat2@sha256:cec48405f9adb85e86a5aee8f5f4eb3da3396ab57d94a1544bb774b6832cf18d"},
	{"php-legacy-54-bookworm", "php-legacy-54", "php-54", "5.4.45", "5.4.45-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php54:5.4.45-compat2@sha256:25745de343faf6dd3c2fde3bb8729dd5475f42ae1064c178d56d07b9a2d0dd0d"},
	{"php-legacy-53-bookworm", "php-legacy-53", "php-53", "5.3.29", "5.3.29-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php53:5.3.29-compat2@sha256:e55568758bc9d63603ba4ede0bedb88e87b173685806fa73c3e795be2350dff1"},
	{legacyPHP52BookwormTemplate, "php-legacy-52", "php-52", "5.2.17", "5.2.17-compat2", "ghcr.io/yunzhanlin/yunzhan-apps-php52:5.2.17-compat2@sha256:0134be0181025424e737318227409208f4be3cc405641e443d839bc46ed7c604"},
}

func findFinalLegacyPHPRelease(id string) (finalLegacyPHPRelease, bool) {
	for _, release := range finalLegacyPHPReleases {
		if release.template == id {
			return release, true
		}
	}
	return finalLegacyPHPRelease{}, false
}

func previousLegacyPHPTemplates(release finalLegacyPHPRelease) []string {
	var templates []string
	for previous := release.previous; previous != "" && len(templates) < len(finalLegacyPHPReleases); {
		templates = append(templates, previous)
		prior, ok := findFinalLegacyPHPRelease(previous)
		if !ok {
			break
		}
		previous = prior.previous
	}
	return templates
}

func LegacyPHPImage(id string) (string, bool) {
	if release, ok := findFinalLegacyPHPRelease(id); ok {
		return release.image, true
	}
	image, ok := LegacyPHPImages[id]
	return image, ok
}

func LegacyPHPArchitectureSupported(id, architecture string) bool {
	if _, ok := findFinalLegacyPHPRelease(id); ok {
		return architecture == "amd64" || architecture == "arm64"
	}
	_, known := LegacyPHPImages[id]
	return known && architecture == "amd64"
}

func IsDockerTemplate(id string) bool {
	if _, ok := LegacyPHPImage(id); ok {
		return true
	}
	switch id {
	case "nginx-static", "redis-cache", "memcached-cache", PhpMyAdminLegacyTemplate, PhpMyAdmin523Template, "mongodb", "elasticsearch", "node-service", "wordpress-blog", "rabbitmq", OpenLiteSpeedLegacyTemplate, OpenLiteSpeed194Template:
		return true
	}
	return false
}

// LegacyPHPTemplate exposes only the compiled-host validated legacy factory to
// the native sync reader. It cannot render a foreign architecture via input.
func LegacyPHPTemplate(id string, port int) (string, error) {
	if _, ok := LegacyPHPImage(id); !ok {
		return "", fmt.Errorf("不是隔离 PHP 模板")
	}
	return dockerTemplate(id, port)
}

// LegacyPHPBootstrap is the exact fixed startup command, shared by the template
// renderer and the native sync authority. It is not request-supplied PHP code.
const LegacyPHPBootstrap = `set -eu
mkdir -p /tmp/cloudstack-ini
cp /usr/local/etc/php/conf.d/*.ini /tmp/cloudstack-ini/
printf '%s\n' 'expose_php=Off' 'allow_url_include=Off' 'disable_functions=exec,passthru,shell_exec,system,proc_open,popen' 'memory_limit=128M' 'max_execution_time=30' > /tmp/cloudstack-ini/zz-cloudstack.ini
printf '%s\n' '<?php header("Content-Type: application/json"); echo json_encode(array("ok"=>true,"version"=>PHP_VERSION)); ?>' > /tmp/cloudstack-probe.php
if [ ! -e /var/www/html/index.php ]; then
printf '%s\n' '<?php header("Content-Type: application/json"); echo json_encode(array("version"=>PHP_VERSION,"sapi"=>php_sapi_name(),"mysql"=>extension_loaded("mysql"),"mysqli"=>extension_loaded("mysqli"),"pdo_mysql"=>extension_loaded("pdo_mysql"))); ?>' > /var/www/html/index.php
chown 1000:1000 /var/www/html /var/www/html/index.php
chmod 755 /var/www/html
chmod 644 /var/www/html/index.php
fi
exec /usr/local/sbin/php-fpm
`

// PHP 5.2 predates FPM. Its reviewed image runs the fixed FastCGI worker.
func LegacyPHPBootstrapForTemplate(id string) string {
	if id == legacyPHP52BookwormTemplate {
		return strings.Replace(LegacyPHPBootstrap, "exec /usr/local/sbin/php-fpm\n", "exec /usr/local/bin/yunzhan-start-php-cgi\n", 1)
	}
	return LegacyPHPBootstrap
}

func isolatedPHPTemplate(id string, port int) string {
	image, _ := LegacyPHPImage(id)
	phpInit := LegacyPHPBootstrapForTemplate(id)
	// Regex locations stop at the first match. Hidden-path denial must precede
	// PHP dispatch, including hidden files that themselves end in .php.
	// https://nginx.org/en/docs/http/ngx_http_core_module.html#location
	nginxInit := `set -eu
cat > /tmp/cloudstack-nginx.conf <<'CLOUDSTACK_CONFIG'
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 256; }
http {
 include /etc/nginx/mime.types;
 default_type application/octet-stream;
 access_log /dev/stdout;
 client_body_temp_path /tmp/client;
 fastcgi_temp_path /tmp/fastcgi;
 proxy_temp_path /tmp/proxy;
 uwsgi_temp_path /tmp/uwsgi;
 scgi_temp_path /tmp/scgi;
 server {
  listen 8080;
  server_name _;
  root /var/www/html;
  index index.php index.html;
  location = /.__cloudstack_health { include /etc/nginx/fastcgi_params; fastcgi_pass php:9000; fastcgi_param SCRIPT_FILENAME /tmp/cloudstack-probe.php; }
  location / { try_files $uri $uri/ /index.php?$query_string; }
  location ~ /\. { deny all; }
  location ~ \.php$ { try_files $uri =404; include /etc/nginx/fastcgi_params; fastcgi_pass php:9000; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }
 }
}
CLOUDSTACK_CONFIG
exec nginx -c /tmp/cloudstack-nginx.conf -g 'daemon off;'
`
	return fmt.Sprintf(`services:
  php:
    image: %s
    restart: unless-stopped
    entrypoint: ["/bin/sh", "-c"]
    command: [%s]
    environment:
      PHP_INI_SCAN_DIR: /tmp/cloudstack-ini
    read_only: true
    tmpfs: [/tmp, /var/run]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 256m
    pids_limit: 96
    volumes:
      - site-data:/var/www/html
    healthcheck:
      test: ["CMD-SHELL", "php -r '$$s=@fsockopen(\"127.0.0.1\",9000);exit($$s?0:1);'"]
      interval: 10s
      timeout: 5s
      retries: 24
      start_period: 30s
  web:
    image: %s
    restart: unless-stopped
    user: "101:101"
    networks: [default, edge]
    entrypoint: ["/bin/sh", "-c"]
    command: [%s]
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 64m
    pids_limit: 32
    depends_on:
      php:
        condition: service_healthy
    ports:
      - "127.0.0.1:%d:8080"
    volumes:
      - site-data:/var/www/html:ro
    healthcheck:
      test: ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:8080/.__cloudstack_health"]
      interval: 10s
      timeout: 5s
      retries: 18
volumes:
  site-data: {}
networks:
  default:
    internal: true
  edge: {}
`, image, strconv.Quote(strings.ReplaceAll(phpInit, "$", "$$")), legacyNginxImage, strconv.Quote(strings.ReplaceAll(nginxInit, "$", "$$")), port)
}
