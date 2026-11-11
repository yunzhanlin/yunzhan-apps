package core

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	OpenLiteSpeedLegacyTemplate = "openlitespeed"
	OpenLiteSpeed194Template    = "openlitespeed-194"
	openLiteSpeed194AppVersion  = "1.9.4-compat2"
)

func IsOpenLiteSpeedTemplate(template string) bool {
	return template == OpenLiteSpeedLegacyTemplate || template == OpenLiteSpeed194Template
}

// Docker must leave a new admin volume empty so the image's default password
// is replaced before the first start. Existing volumes keep their accounts.
const openLiteSpeedBootstrap = `set -eu
if [ -z "$(ls -A /usr/local/lsws/conf)" ]; then cp -R /usr/local/lsws/.conf/. /usr/local/lsws/conf/; fi
admin_dir=/usr/local/lsws/admin/conf
pending="$admin_dir/.yunzhan-admin-initializing"
if [ -z "$(ls -A "$admin_dir")" ]; then
  (umask 077; mkdir "$pending")
fi
if [ -d "$pending" ] && [ ! -L "$pending" ]; then
  [ ! -L "$admin_dir/htpasswd" ] && [ ! -L "$pending/htpasswd" ] || exit 1
  cp -R /usr/local/lsws/admin/.conf/. "$admin_dir/"
  HASH=$(/usr/local/lsws/admin/fcgi-bin/admin_php -q /usr/local/lsws/admin/misc/htpasswd.php "$CLOUDSTACK_ADMIN_PASSWORD")
  [ -n "$HASH" ]
  (umask 077; printf 'admin:%s\n' "$HASH" > "$pending/htpasswd")
  mv -f "$pending/htpasswd" "$admin_dir/htpasswd"
  rmdir "$pending"
fi
if [ ! -s "$admin_dir/htpasswd" ] || [ -L "$admin_dir/htpasswd" ]; then
  echo 'OpenLiteSpeed WebAdmin credential file is missing or invalid' >&2
  exit 1
fi
if [ ! -d /var/www/vhosts/cloudstack/html ]; then
  mkdir -p /var/www/vhosts/cloudstack
  cp -R /usr/local/lsws/Example/. /var/www/vhosts/cloudstack/
fi
sed -i 's#vhRoot[[:space:]]*Example/#vhRoot /var/www/vhosts/cloudstack/#' /usr/local/lsws/conf/httpd_config.conf
exec /entrypoint.sh
`

// This exact command identifies older projects produced by the panel. Keep
// arbitrary Compose files and projects with a different image out of migration.
const previousOpenLiteSpeedBootstrap = `set -eu
if [ -z "$(ls -A /usr/local/lsws/conf)" ]; then cp -R /usr/local/lsws/.conf/. /usr/local/lsws/conf/; fi
if [ -z "$(ls -A /usr/local/lsws/admin/conf)" ]; then cp -R /usr/local/lsws/admin/.conf/. /usr/local/lsws/admin/conf/; fi
if [ ! -d /var/www/vhosts/cloudstack/html ]; then
  mkdir -p /var/www/vhosts/cloudstack
  cp -R /usr/local/lsws/Example/. /var/www/vhosts/cloudstack/
fi
sed -i 's#vhRoot[[:space:]]*Example/#vhRoot /var/www/vhosts/cloudstack/#' /usr/local/lsws/conf/httpd_config.conf
HASH=$(/usr/local/lsws/admin/fcgi-bin/admin_php -q /usr/local/lsws/admin/misc/htpasswd.php "$CLOUDSTACK_ADMIN_PASSWORD")
printf 'admin:%s\n' "$HASH" > /usr/local/lsws/admin/conf/htpasswd
chmod 600 /usr/local/lsws/admin/conf/htpasswd
exec /entrypoint.sh
`

const previousOpenLiteSpeedAdminVolume = "      - admin-conf:/usr/local/lsws/admin/conf\n"
const openLiteSpeedAdminVolume = `      - type: volume
        source: admin-conf
        target: /usr/local/lsws/admin/conf
        volume:
          nocopy: true
`

// A new managed project publishes WebAdmin only on the host's loopback.
// Initialize the vendor marker with its credential, then respect its volume
// state on subsequent boots.
const openLiteSpeed194AdminMarker = `  marker="$admin_dir/enable_webadmin"
  [ ! -L "$marker" ] || exit 1
  if [ ! -e "$marker" ]; then
    (umask 077; set -C; : > "$marker")
  fi
`

var openLiteSpeed194Bootstrap = strings.Replace(openLiteSpeedBootstrap,
	"  rmdir \"$pending\"\n", openLiteSpeed194AdminMarker+"  rmdir \"$pending\"\n", 1)

func openLiteSpeedComposeCommand(bootstrap string) string {
	return "    command: [" + strconv.Quote(strings.ReplaceAll(bootstrap, "$", "$$")) + "]\n"
}

func openLiteSpeedCompose(template string, port int, password string) string {
	image, bootstrap := dockerOpenLiteSpeedImage, openLiteSpeedBootstrap
	if template == OpenLiteSpeed194Template {
		image, bootstrap = dockerOpenLiteSpeed194Image, openLiteSpeed194Bootstrap
	}
	return fmt.Sprintf(`services:
  openlitespeed:
    image: %s
    restart: unless-stopped
    entrypoint: ["/bin/sh", "-c"]
%s    environment:
      CLOUDSTACK_ADMIN_PASSWORD: "%s"
    mem_limit: 512m
    ports:
      - "127.0.0.1:%d:8088"
      - "127.0.0.1:%d:7080"
    volumes:
      - server-conf:/usr/local/lsws/conf
%s      - site-data:/var/www/vhosts
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:8088/ >/dev/null"]
      interval: 15s
      timeout: 10s
      retries: 18
      start_period: 60s
volumes:
  server-conf: {}
  admin-conf: {}
  site-data: {}
`, image, openLiteSpeedComposeCommand(bootstrap), password, port, port+1, openLiteSpeedAdminVolume)
}

// The executor uses the reviewed file, including the two loopback bindings,
// before giving a new project access to the WebAdmin provisioning command.
func OpenLiteSpeed194ComposeMatches(source string, port int, password string) bool {
	return port >= 1024 && port < 65535 && len(password) == 64 && ValidID(password[:32]) &&
		ValidID(password[32:]) && source == openLiteSpeedCompose(OpenLiteSpeed194Template, port, password)
}

// UpgradeOpenLiteSpeedAdminCompose changes only the known older bootstrap and
// admin mount in a generated, digest-pinned project.
func UpgradeOpenLiteSpeedAdminCompose(source string) (string, bool) {
	oldCommand := openLiteSpeedComposeCommand(previousOpenLiteSpeedBootstrap)
	if strings.Count(source, oldCommand) != 1 ||
		strings.Count(source, previousOpenLiteSpeedAdminVolume) != 1 ||
		strings.Count(source, "    image: "+dockerOpenLiteSpeedImage+"\n") != 1 {
		return source, false
	}
	source = strings.Replace(source, oldCommand, openLiteSpeedComposeCommand(openLiteSpeedBootstrap), 1)
	return strings.Replace(source, previousOpenLiteSpeedAdminVolume, openLiteSpeedAdminVolume, 1), true
}

// OpenLiteSpeedAdminCommandVersion identifies the exact managed container
// command. An unfamiliar command cannot be adopted into a credential migration.
func OpenLiteSpeedAdminCommandVersion(image string, command []string) int {
	if image != dockerOpenLiteSpeedImage || len(command) != 1 {
		return 0
	}
	switch command[0] {
	case previousOpenLiteSpeedBootstrap:
		return 1
	case openLiteSpeedBootstrap:
		return 2
	default:
		return 0
	}
}
