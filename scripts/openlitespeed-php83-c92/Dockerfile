FROM litespeedtech/openlitespeed:1.9.4-lsphp83@sha256:e240c9af427fe36e373382384a8eaabd7224412fbb3257a4288525adbd67d19c

# The vendor image keeps a separate legacy PHP executable for WebAdmin.
# Use its already packaged, patched LSAPI executable for both processes.
RUN set -eux; \
    test -f /usr/local/lsws/admin/fcgi-bin/admin_php; \
    test ! -L /usr/local/lsws/admin/fcgi-bin/admin_php; \
    test -x /usr/local/lsws/lsphp83/bin/lsphp; \
    /usr/local/lsws/lsphp83/bin/lsphp -v | grep -q '^PHP 8\.3\.36 '; \
    rm /usr/local/lsws/admin/fcgi-bin/admin_php; \
    ln -s /usr/local/lsws/lsphp83/bin/lsphp /usr/local/lsws/admin/fcgi-bin/admin_php; \
    /usr/local/lsws/admin/fcgi-bin/admin_php -v | grep -q '^PHP 8\.3\.36 '
