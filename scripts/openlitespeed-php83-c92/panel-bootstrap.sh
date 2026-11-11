set -eu
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
