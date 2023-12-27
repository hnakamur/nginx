#!/bin/sh
set -eu
set -x
if [ $# -eq 1 ]; then
  if [ $1 = "-c" ]; then
    export CFLAGS="-g -O2 -ffile-prefix-map=/src/nginx=. -flto=auto -ffat-lto-objects -specs=/usr/share/dpkg/no-pie-compile.specs -fstack-protector-strong -fstack-protector-strong -Wall -Wformat=2 -Werror=unused-variable -Wno-error=conversion -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC -Wno-missing-field-initializers -Wno-implicit-fallthrough -I/usr/include/luajit-2.1"
    export LDFLAGS="-Wl,-Bsymbolic-functions -flto=auto -ffat-lto-objects -flto=auto -specs=/usr/share/dpkg/no-pie-link.specs -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie -lm -lluajit-5.1 -ldl"
    ./auto/configure \
		--prefix=/etc/nginx \
		--sbin-path=/usr/sbin/nginx \
		--modules-path=/usr/lib/nginx/modules \
		--conf-path=/etc/nginx/nginx.conf \
		--error-log-path=/var/log/nginx/error.log \
		--http-log-path=/var/log/nginx/access.log \
		--pid-path=/var/run/nginx.pid \
		--lock-path=/var/run/nginx.lock \
		--http-client-body-temp-path=/var/cache/nginx/client_temp \
		--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
		--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
		--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
		--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
		--user=nginx \
		--group=nginx \
		--with-compat \
		--with-file-aio \
		--with-threads \
		--with-http_addition_module \
		--with-http_auth_request_module \
		--with-http_dav_module \
		--with-http_flv_module \
		--with-http_geoip_module=dynamic \
		--with-http_gunzip_module \
		--with-http_gzip_static_module \
		--with-http_image_filter_module=dynamic \
		--with-http_mp4_module \
		--with-http_random_index_module \
		--with-http_realip_module \
		--with-http_secure_link_module \
		--with-http_slice_module \
		--with-http_ssl_module \
		--with-http_stub_status_module \
		--with-http_sub_module \
		--with-http_v2_module \
		--with-http_xslt_module=dynamic \
		--with-mail=dynamic \
		--with-mail_ssl_module \
		--with-stream \
		--with-stream_realip_module \
		--with-stream_ssl_module \
		--with-stream_ssl_preread_module \
		--add-module=./ngx_devel_kit \
		--add-dynamic-module=./lua-nginx-module \
		--add-dynamic-module=./echo-nginx-module \
		--add-dynamic-module=./headers-more-nginx-module \
		--add-dynamic-module=./lua-upstream-nginx-module \
		--add-dynamic-module=./memc-nginx-module \
		--add-dynamic-module=./nginx-dav-ext-module \
		--add-dynamic-module=./nginx-http-shibboleth \
		--add-dynamic-module=./nginx-rtmp-module \
		--add-dynamic-module=./nginx-sorted-querystring-module \
		--add-dynamic-module=./ngx_cache_purge \
		--add-dynamic-module=./ngx_http_enhanced_memcached_module \
		--add-dynamic-module=./ngx_http_pipelog_module \
		--add-dynamic-module=./ngx_http_secure_download \
		--add-dynamic-module=./redis2-nginx-module \
		--add-dynamic-module=./set-misc-nginx-module \
		--add-dynamic-module=./srcache-nginx-module \
		--add-dynamic-module=./njs/nginx \
		--add-dynamic-module=./nginx-var-limit-conn-module \
		--add-dynamic-module=./nginx-var-limit-req-module \
		--with-cc-opt="${CFLAGS}" \
		--with-ld-opt="${LDFLAGS}" \
		--without-pcre2
  fi
fi
make -j
sudo make install
sudo rsync -av ./my-config/ /etc/nginx/
sudo nginx -t
sudo systemctl stop nginx
logtime=$(date +%Y%m%dT%H%M%S)
sudo mv /var/log/nginx/access.log /var/log/nginx/access.log-$(logtime)
sudo mv /var/log/nginx/error.log /var/log/nginx/error.log-$(logtime)
sudo systemctl start nginx
systemctl status nginx

if [ ! -f /tmp/random-1m.dat ]; then
  dd if=/dev/random of=/tmp/random-1m.dat bs=1048576 count=1
fi
if [ ! -f /tmp/random-1g.dat ]; then
  dd if=/dev/random of=/tmp/random-1g.dat bs=1048576 count=1024
fi
hey -host www1.example.com -c 3 -z 3s -m POST -D /tmp/random-1m.dat -req-body-rate 262144 -req-body-burst 262144 http://localhost/limit-conn &
hey -host www1.example.com -c 3 -z 3s http://localhost/limit-conn &
hey -host www2.example.com -c 9 -z 3s http://localhost/limit-conn &
hey -host www3.example.com -c 2 -z 3s http://localhost/limit-conn &
hey -host www4.example.com -c 3 -z 3s http://localhost/limit-conn &
for i in $(seq 6); do
  curl -sSD - http://localhost/top-limit-conn || :
  sleep 0.5
done
wait
