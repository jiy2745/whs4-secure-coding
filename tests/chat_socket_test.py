#!/usr/bin/env python3
"""실시간 채팅(Socket.IO) 보안 테스트.

    python tests/chat_socket_test.py http://127.0.0.1:5099
"""
import re
import sys
import time
import uuid

import requests
import socketio
from socketio.exceptions import ConnectionError as SioConnectionError

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5099"
PASSWORD = "Test!Pass123"
CSRF_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


def csrf(session, path):
    return CSRF_RE.search(session.get(BASE + path).text).group(1)


def new_user(prefix):
    username = f"{prefix}{uuid.uuid4().hex[:6]}"
    s = requests.Session()
    s.post(BASE + "/register", data={"csrf_token": csrf(s, "/register"), "username": username,
                                     "password": PASSWORD, "password_confirm": PASSWORD})
    s.post(BASE + "/login", data={"csrf_token": csrf(s, "/login"),
                                  "username": username, "password": PASSWORD})
    cookie = [c for c in s.cookies if c.name == "tsp_session"][0].value
    return s, username, cookie


def connect(cookie):
    client = socketio.Client(reconnection=False)
    client.connect(BASE, headers={"Cookie": f"tsp_session={cookie}"}, transports=["polling"],
                   wait_timeout=10)
    return client


print(f"=== Socket.IO 보안 테스트: {BASE} ===")

# 1) 인증 없는 연결 거부 -------------------------------------------------------
try:
    anon = socketio.Client(reconnection=False)
    anon.connect(BASE, transports=["polling"], wait_timeout=5)
    connected = anon.connected
    anon.disconnect()
except SioConnectionError:
    connected = False
check("소켓: 비인증 연결 거부", not connected)

# 2) 잘못된 세션 쿠키으로 연결 거부 ---------------------------------------------
try:
    forged = socketio.Client(reconnection=False)
    forged.connect(BASE, headers={"Cookie": "tsp_session=forged.invalid.cookie"},
                   transports=["polling"], wait_timeout=5)
    connected = forged.connected
    forged.disconnect()
except SioConnectionError:
    connected = False
check("소켓: 위조 세션 쿠키 연결 거부", not connected)

# 3) 인증된 연결 ---------------------------------------------------------------
alice_http, alice_name, alice_cookie = new_user("chatA")
bob_http, bob_name, bob_cookie = new_user("chatB")
alice = connect(alice_cookie)
check("소켓: 인증된 사용자 연결 성공", alice.connected)

received, errors = [], []
alice.on("global_message", lambda data: received.append(data))
alice.on("error_message", lambda data: errors.append(data))

# 4) 정상 메시지 전송 -----------------------------------------------------------
alice.emit("global_message", {"content": "안녕하세요 전체 채팅 테스트입니다"})
time.sleep(1.0)
check("소켓: 전체 채팅 메시지 브로드캐스트",
      any("전체 채팅 테스트" in m.get("content", "") for m in received))

# 5) XSS 페이로드 → 페이지 렌더 시 이스케이프 -------------------------------------
payload = '<script>alert("chat-xss")</script>'
alice.emit("global_message", {"content": payload})
time.sleep(1.0)
page = alice_http.get(BASE + "/chat").text
check("소켓: 채팅 XSS 페이로드 이스케이프 저장/출력",
      "<script>alert(\"chat-xss\")" not in page and "&lt;script&gt;" in page)

# 6) 서버측 길이 검증 -----------------------------------------------------------
errors.clear()
alice.emit("global_message", {"content": "가" * 600})
time.sleep(0.8)
check("소켓: 길이 초과 메시지 거부", any("500자" in e.get("message", "") for e in errors))

errors.clear()
alice.emit("global_message", {"content": "   "})
time.sleep(0.8)
check("소켓: 공백 메시지 거부", any("빈 메시지" in e.get("message", "") for e in errors))

errors.clear()
alice.emit("global_message", "문자열 페이로드")
time.sleep(0.8)
check("소켓: 잘못된 형식(dict 아님) 거부", any("잘못된 요청" in e.get("message", "") for e in errors))

errors.clear()
alice.emit("global_message", {"content": 12345})
time.sleep(0.8)
check("소켓: 숫자 content 거부", any("형식이 올바르지" in e.get("message", "") for e in errors))

# 7) Rate limit (10초당 10건) ---------------------------------------------------
errors.clear()
for i in range(16):
    alice.emit("global_message", {"content": f"스팸 테스트 {i}"})
time.sleep(2.0)
check("소켓: 채팅 Rate limit 동작", any("너무 빠르게" in e.get("message", "") for e in errors),
      f"error 수신 {len(errors)}건")

# 8) 1:1 메시지 라우팅 ----------------------------------------------------------
time.sleep(11)  # rate limit 창 초기화 대기
bob = connect(bob_cookie)
bob_received = []
bob.on("private_message", lambda data: bob_received.append(data))
alice_id = re.search(r"/users/([0-9a-f]{32})", alice_http.get(BASE + "/me").text).group(1)
bob_id = re.search(r"/users/([0-9a-f]{32})", bob_http.get(BASE + "/me").text).group(1)

alice.emit("private_message", {"to": bob_id, "content": "1:1 메시지 테스트"})
time.sleep(1.0)
check("소켓: 1:1 메시지 수신", any("1:1 메시지 테스트" in m.get("content", "") for m in bob_received))

errors.clear()
alice.emit("private_message", {"to": "not-a-valid-id", "content": "잘못된 대상"})
time.sleep(0.8)
check("소켓: 잘못된 대상 ID 거부", any("대상이 올바르지" in e.get("message", "") for e in errors))

errors.clear()
alice.emit("private_message", {"to": "f" * 32, "content": "존재하지 않는 사용자"})
time.sleep(0.8)
check("소켓: 존재하지 않는 대상 거부", any("찾을 수 없습니다" in e.get("message", "") for e in errors))

errors.clear()
alice.emit("private_message", {"to": alice_id, "content": "자기 자신에게"})
time.sleep(0.8)
check("소켓: 자기 자신에게 전송 거부", any("자기 자신" in e.get("message", "") for e in errors))

# 9) 제3자에게 메시지가 새지 않는지 --------------------------------------------
carol_http, _, carol_cookie = new_user("chatC")
carol = connect(carol_cookie)
carol_private = []
carol.on("private_message", lambda data: carol_private.append(data))
alice.emit("private_message", {"to": bob_id, "content": "비밀 대화 내용"})
time.sleep(1.2)
check("소켓: 1:1 메시지가 제3자에게 전달되지 않음",
      not any("비밀 대화 내용" in m.get("content", "") for m in carol_private))

for client in (alice, bob, carol):
    try:
        client.disconnect()
    except Exception:
        pass

print("\n--- 결과 요약 ---")
passed = sum(1 for _, ok in results if ok)
print(f"{passed}/{len(results)} 통과")
failed = [name for name, ok in results if not ok]
for name in failed:
    print(f"  - 실패: {name}")
sys.exit(1 if failed else 0)
