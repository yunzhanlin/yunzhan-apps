package core

import (
	"fmt"
	"strconv"
	"strings"
)

const legacyNginxImage = "nginx:1.30-alpine@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94"

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

func IsDockerTemplate(id string) bool {
	if _, ok := LegacyPHPImages[id]; ok {
		return true
	}
	switch id {
	case "nginx-static", "redis-cache", "memcached-cache", "phpmyadmin", "mongodb", "elasticsearch", "node-service", "wordpress-blog", "rabbitmq", "openlitespeed":
		return true
	}
	return false
}
func isolatedPHPTemplate(id string, port int) string {
	phpInit := `set -eu
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
  location ~ \.php$ { try_files $uri =404; include /etc/nginx/fastcgi_params; fastcgi_pass php:9000; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; }
  location ~ /\. { deny all; }
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
`, LegacyPHPImages[id], strconv.Quote(strings.ReplaceAll(phpInit, "$", "$$")), legacyNginxImage, strconv.Quote(strings.ReplaceAll(nginxInit, "$", "$$")), port)
}
