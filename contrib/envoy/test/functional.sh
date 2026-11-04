#!/bin/sh
# functional.sh: start the stock Envoy v1.40.2 image with jwt_authn, then with cjwt_authn, send both the same
# requests and require identical status codes, bodies, forwarded payload, token removal and www-authenticate.
# Run from contrib/envoy on a Docker host after `make functional`'s build steps (it calls this script itself).
# The module is built for the Docker image's architecture: on macOS, run `make` inside the Dockerfile's image.
set -e
cd "$(dirname "$0")/.."
CLIENT=${CLIENT_IMG:-cjwt-envoy:build}
IMG=${ENVOY_IMG:-envoyproxy/envoy:v1.40.2}
docker image inspect "$CLIENT" >/dev/null 2>&1 || docker build -q -t "$CLIENT" . >/dev/null
A=$(docker run --rm "$CLIENT" uname -m)
T=build/tokens-e2e C=build/configs
[ -f "build/$A/libcjwt_authn.so" ] || {
  echo "build/$A/libcjwt_authn.so missing: build it for $A first" >&2
  exit 1
}
mk_bad() { # header.payload.sig with a changed claim but the original signature
  python3 -I - "$1" "$2" <<'PY'
import base64, json, sys
tok, what = sys.argv[1], sys.argv[2]
h, p, s = tok.split(".")
d = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
if what == "aud": d["aud"] = "https://other.example.com"
if what == "exp": d["exp"] = 1000
if what == "iss": d["iss"] = "https://evil.example.com/"
p2 = base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
print(h + "." + p2 + "." + s)
PY
}
out=$(mktemp -d)
trap 'docker rm -f cjwt-fn >/dev/null 2>&1 || true; rm -rf "$out"' EXIT
fail=0
for alg in HS256 RS256 ES256; do
  good=$(sed -n 1p $T/${alg}_realistic.txt)
  goods=$(sed -n 2p $T/${alg}_small.txt)
  bad=$(sed -n 1p $T/bad_${alg}.txt)
  set -- "good:$good" "goodsmall:$goods" "badsig:$bad" "aud:$(mk_bad "$good" aud)" "iss:$(mk_bad "$good" iss)" \
    "exp:$(mk_bad "$good" exp)" "garbage:abc.def" "missing:"
  for cfg in jwt_authn cjwt; do
    docker rm -f cjwt-fn >/dev/null 2>&1 || true
    docker run -d --name cjwt-fn -v "$PWD":/w -e ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/w/build/"$A" \
      "$IMG" envoy -c /w/$C/$cfg.json --concurrency 1 -l warn >/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      docker run --rm --network container:cjwt-fn "$CLIENT" curl -s -o /dev/null http://127.0.0.1:10000/ && break
      sleep 0.5
    done
    for case in "$@"; do
      name=${case%%:*} tok=${case#*:}
      hdr=
      [ -n "$tok" ] && hdr="Authorization: Bearer $tok"
      # shellcheck disable=SC2016 # $0 is expanded by the inner shell
      docker run --rm --network container:cjwt-fn "$CLIENT" sh -c \
        'curl -s -D - -o /tmp/b ${0:+-H "$0"} http://127.0.0.1:10000/; cat /tmp/b' "$hdr" |
        tr -d '\r' | awk -v n="$name" 'NR==1{s=$2} /^x-seen-payload:/{p=$2} /^x-seen-auth:/{a=$2} /^www-authenticate:/{w=1}
          {body=$0} END{printf "%s status=%s payload=%s auth=%s www=%s body=%s\n", n, s, length(p) ? substr(p,1,12) "...(" length(p) ")" : "-", length(a) ? "present" : "-", w ? "yes" : "-", body}' \
        >"$out/$cfg-$alg-$name.txt"
    done
    docker rm -f cjwt-fn >/dev/null
  done
  for case in "$@"; do
    name=${case%%:*}
    if cmp -s "$out/jwt_authn-$alg-$name.txt" "$out/cjwt-$alg-$name.txt"; then
      echo "same  $alg $(cat "$out/cjwt-$alg-$name.txt")"
    else
      echo "DIFF  $alg jwt_authn: $(cat "$out/jwt_authn-$alg-$name.txt")"
      echo "      $alg cjwt:      $(cat "$out/cjwt-$alg-$name.txt")"
      fail=1
    fi
  done
done
[ $fail = 0 ] && echo "functional: jwt_authn and cjwt_authn agree"
exit $fail
