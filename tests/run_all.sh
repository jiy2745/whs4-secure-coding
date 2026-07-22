#!/usr/bin/env bash
# 전체 테스트 실행 스크립트.
#   bash tests/run_all.sh
#
# 1) 기능 E2E + 보안 테스트 : rate limit 을 끈 서버(5099)에서 실행
#    (테스트가 수백 번 요청하므로 IP 제한에 먼저 걸리는 것을 피하기 위함)
# 2) Rate limit / Origin 테스트 : 기본 설정 서버(5098)에서 실행
set -u
cd "$(dirname "$0")/.."

PY="${PY:-.venv/bin/python}"
TMP="$(mktemp -d)"
FAILED=0

start_server() {  # $1=port  $2=db  $3=extra env
  rm -f "instance/$2"*
  env RATELIMIT_ENABLED="$3" PORT="$1" DATABASE_PATH="instance/$2" \
      nohup "$PY" app.py > "$TMP/server_$1.log" 2>&1 &
  echo $! > "$TMP/server_$1.pid"
  for _ in $(seq 1 30); do
    if curl -sf -o /dev/null "http://127.0.0.1:$1/"; then return 0; fi
    sleep 1
  done
  echo "서버($1) 기동 실패"; cat "$TMP/server_$1.log"; return 1
}

stop_server() { kill "$(cat "$TMP/server_$1.pid")" 2>/dev/null; }

echo "### 1. 기능 E2E + 보안 테스트 (port 5099)"
start_server 5099 e2e_test.db 0 || exit 1
RATELIMIT_ENABLED=0 DATABASE_PATH=instance/e2e_test.db \
  "$PY" -m flask --app app create-admin --username admin --password 'Admin!Pass123' >/dev/null 2>&1
"$PY" tests/e2e_security_test.py http://127.0.0.1:5099 || FAILED=1
echo
echo "### 2. 실시간 채팅(Socket.IO) 보안 테스트 (port 5099)"
"$PY" tests/chat_socket_test.py http://127.0.0.1:5099 || FAILED=1
echo
echo "### 3. 관리자 기능 테스트 (port 5099)"
"$PY" tests/admin_test.py http://127.0.0.1:5099 admin 'Admin!Pass123' || FAILED=1
stop_server 5099

echo
echo "### 4. Rate limit / Origin 테스트 (port 5098, 제한 활성화)"
start_server 5098 ratelimit_test.db 1 || exit 1
"$PY" tests/ratelimit_test.py http://127.0.0.1:5098 || FAILED=1
stop_server 5098

rm -rf "$TMP"
echo
if [ "$FAILED" -eq 0 ]; then echo "== 전체 테스트 통과 =="; else echo "== 실패한 테스트가 있습니다 =="; fi
exit "$FAILED"
