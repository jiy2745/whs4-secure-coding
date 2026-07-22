#!/usr/bin/env python3
"""IP 기준 Rate limit + 교차 출처(Origin) 차단 테스트.

Rate limit 이 켜진 서버(기본 설정)를 대상으로 실행한다.
    PORT=5098 python app.py &
    python tests/ratelimit_test.py http://127.0.0.1:5098
"""
import re
import sys
import uuid

import requests
import socketio
from socketio.exceptions import ConnectionError as SioConnectionError

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5098"
PASSWORD = "Test!Pass123"
CSRF_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


def csrf(session, path):
    return CSRF_RE.search(session.get(BASE + path).text).group(1)


print(f"=== Rate limit / Origin 테스트: {BASE} ===")

# 1) 로그인 IP Rate limit (10/분) ------------------------------------------------
# 계정 잠금과 구분하기 위해 매번 다른(존재하지 않는) 아이디로 시도한다.
session = requests.Session()
codes = []
for i in range(13):
    token = csrf(session, "/login")
    r = session.post(BASE + "/login",
                     data={"csrf_token": token, "username": f"nouser{uuid.uuid4().hex[:6]}",
                           "password": "WrongPass!123"})
    codes.append(r.status_code)
    if r.status_code == 429 and "요청이 너무 많습니다" in r.text:
        break
check("로그인 시도 IP Rate limit(10/분) 동작", 429 in codes, f"status={codes}")

# 2) 회원가입 Rate limit (10/시간) ----------------------------------------------
reg = requests.Session()
reg_codes = []
for i in range(12):
    token = csrf(reg, "/register")
    r = reg.post(BASE + "/register",
                 data={"csrf_token": token, "username": f"rl{uuid.uuid4().hex[:8]}",
                       "password": PASSWORD, "password_confirm": PASSWORD})
    reg_codes.append(r.status_code)
    if r.status_code == 429:
        break
check("회원가입 IP Rate limit(10/시간) 동작", 429 in reg_codes, f"status={reg_codes}")

# 3) 교차 출처 WebSocket 연결 차단 (CSWSH) ---------------------------------------
user = requests.Session()
name = f"origin{uuid.uuid4().hex[:6]}"
user.post(BASE + "/register", data={"csrf_token": csrf(user, "/register"), "username": name,
                                    "password": PASSWORD, "password_confirm": PASSWORD})
user.post(BASE + "/login", data={"csrf_token": csrf(user, "/login"),
                                 "username": name, "password": PASSWORD})
cookie = [c for c in user.cookies if c.name == "tsp_session"]
if cookie:
    cookie = cookie[0].value
    try:
        evil = socketio.Client(reconnection=False)
        evil.connect(BASE, headers={"Cookie": f"tsp_session={cookie}",
                                    "Origin": "http://evil.example"},
                     transports=["polling"], wait_timeout=5)
        connected = evil.connected
        evil.disconnect()
    except SioConnectionError:
        connected = False
    check("교차 출처(Origin) WebSocket 연결 차단", not connected)
else:
    check("교차 출처(Origin) WebSocket 연결 차단", False, "테스트 계정 로그인 실패(rate limit)")

print("\n--- 결과 요약 ---")
passed = sum(1 for _, ok in results if ok)
print(f"{passed}/{len(results)} 통과")
sys.exit(0 if passed == len(results) else 1)
