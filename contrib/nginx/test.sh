#!/usr/bin/env bash
# test.sh: builds nginx (pinned release, SHA-256 checked) with the module and checks every route end to end.
#   Needs: build/libcursedjwt_nginx.a (`make`), libcrypto headers, curl, python3 with `cryptography`.
#   HS256 / RS256 / ES256 x small and OIDC-style claims, each inline, batched (cursed_jwt_batch 16), and batched
#   with an error_page internal redirect:  valid -> 200; tampered signature, expired, missing token, another key's
#   algorithm -> 401 (403 through the redirect).  Then 400 concurrent valid requests through the batch route.
#   PORT (default 18080), NGINX_SRC (an unpacked nginx tree to use instead of the download).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
B=$HERE/build
PORT=${PORT:-18080}
V=1.30.6
SHA=3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8
[ -f "$B/libcursedjwt_nginx.a" ] || { echo "test.sh: run make first" >&2 && exit 2; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

src=${NGINX_SRC:-$B/nginx-$V}
if [ -z "${NGINX_SRC:-}" ] && [ ! -d "$src" ]; then
  t=$B/nginx-$V.tar.gz
  [ -f "$t" ] && [ "$(sha "$t")" = $SHA ] || curl -fsSL "https://nginx.org/download/nginx-$V.tar.gz" -o "$t"
  [ "$(sha "$t")" = $SHA ] || { echo "nginx-$V.tar.gz: SHA-256 mismatch" >&2 && rm -f "$t" && exit 1; }
  tar -xzf "$t" -C "$B"
fi

P=$B/nginx
ssl=$(brew --prefix openssl@3 2>/dev/null || true)
if [ ! -f "$P/modules/ngx_http_cursed_jwt_module.so" ] || [ "$B/libcursedjwt_nginx.a" -nt "$P/modules/ngx_http_cursed_jwt_module.so" ] ||
  [ "$HERE/ngx_http_cursed_jwt_module.c" -nt "$P/modules/ngx_http_cursed_jwt_module.so" ]; then
  # no rewrite / PCRE / gzip: nothing here needs them, and the build then needs only libcrypto
  (cd "$src" && ./configure --prefix="$P" --with-compat --without-http_rewrite_module --without-pcre \
    --without-http_gzip_module --add-dynamic-module="$HERE" \
    ${ssl:+--with-cc-opt="-I$ssl/include" --with-ld-opt="-L$ssl/lib"} >"$B/configure.log" &&
    make -j"${JOBS:-4}" >"$B/make.log" 2>&1 && make install >/dev/null) ||
    { echo "test.sh: nginx build failed, see $B/configure.log and $B/make.log" >&2 && exit 1; }
fi

if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then echo "test.sh: port $PORT is in use" >&2 && exit 1; fi
T=$B/t
rm -rf "$T" && mkdir -p "$T/logs" # logs/: nginx opens its default error log before it reads the config
python3 "$HERE/gen_tokens.py" "$T" 20 >/dev/null
{
  cat <<CONF
worker_processes 1;
pid $T/nginx.pid;
error_log $T/error.log warn;
load_module $P/modules/ngx_http_cursed_jwt_module.so;
events { worker_connections 1024; }
http {
  access_log off;
  client_body_temp_path $T; proxy_temp_path $T; fastcgi_temp_path $T; uwsgi_temp_path $T; scgi_temp_path $T;
  server {
    listen 127.0.0.1:$PORT;
    location @denied { empty_gif; }
CONF
  for a in hs256 rs256 es256; do
    cat <<CONF
    location = /i/$a { cursed_jwt "api"; cursed_jwt_key_file $T/$a.jwks; empty_gif; }
    location = /b/$a { cursed_jwt "api"; cursed_jwt_key_file $T/$a.jwks; cursed_jwt_batch 16; empty_gif; }
    location = /r/$a { cursed_jwt "api"; cursed_jwt_key_file $T/$a.jwks; cursed_jwt_batch 16; error_page 401 =403 @denied; empty_gif; }
CONF
  done
  echo "  }"
  echo "}"
} >"$T/nginx.conf"

"$P/sbin/nginx" -p "$T" -c "$T/nginx.conf"
trap '"$P/sbin/nginx" -p "$T" -c "$T/nginx.conf" -s quit 2>/dev/null || true' EXIT
for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break || sleep 0.1; done

fail=0 n=0
code() { curl -s -o /dev/null -w '%{http_code}' ${2:+-H "Authorization: Bearer $2"} "http://127.0.0.1:$PORT$1"; }
want() { # path token expected label
  n=$((n + 1))
  local got
  got=$(code "$1" "$2")
  [ "$got" = "$3" ] || { echo "FAIL $1 $4: got $got, want $3" && fail=1; }
}
for a in hs256 rs256 es256; do
  other=$([ $a = hs256 ] && echo es256 || echo hs256)
  for route in i b r; do
    deny=$([ $route = r ] && echo 403 || echo 401)
    for c in small real; do
      while read -r t; do want /$route/$a "$t" 200 "$c valid"; done < <(head -3 "$T/$a-$c.tok")
      while read -r t; do want /$route/$a "$t" "$deny" "$c tampered"; done < <(head -3 "$T/$a-$c.bad")
    done
    while read -r t; do want /$route/$a "$t" "$deny" expired; done < <(head -3 "$T/$a-expired.tok")
    want /$route/$a "" "$deny" missing
    want /$route/$a "$(head -1 "$T/$other-small.tok")" "$deny" "wrong alg ($other)"
  done
  [ "$(curl -s -D - -o /dev/null "http://127.0.0.1:$PORT/i/$a" | tr -d '\r' | grep -i '^www-authenticate:')" = 'WWW-Authenticate: Bearer realm="api"' ] ||
    { echo "FAIL /i/$a: WWW-Authenticate header" && fail=1; }
done

# batch mode under concurrency: 400 valid requests, 50 at a time, all three algorithms
for i in $(seq 400); do
  a=$(echo "hs256 rs256 es256" | cut -d' ' -f$((i % 3 + 1)))
  printf '/b/%s %s\n' $a "$(sed -n "$((i % 20 + 1))p" "$T/$a-real.tok")"
done >"$T/conc.txt"
bad=$(xargs -P 50 -L 1 sh -c 'curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $1" "http://127.0.0.1:'"$PORT"'$0"' <"$T/conc.txt" | grep -vc '^200$' || true)
[ "$bad" = 0 ] || { echo "FAIL batch concurrency: $bad of 400 not 200" && fail=1; }

if grep -E '\[(emerg|alert|crit)\]' "$T/error.log"; then fail=1; fi
[ $fail = 0 ] && echo "test.sh: $n checks + 400 concurrent batched requests OK (nginx $V)"
exit $fail
