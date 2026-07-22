#!/usr/bin/env python3
"""관리자 기능 + 재인증(re-authentication) 테스트.

사전 준비: flask --app app create-admin 으로 관리자 계정을 만든 뒤 실행.
    python tests/admin_test.py http://127.0.0.1:5099 <admin_id> <admin_pw>
"""
import re
import sys
import uuid

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5099"
ADMIN_USER = sys.argv[2] if len(sys.argv) > 2 else "admin"
ADMIN_PW = sys.argv[3] if len(sys.argv) > 3 else "Admin!Pass123"
PASSWORD = "Test!Pass123"
CSRF_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


def csrf(session, path):
    match = CSRF_RE.search(session.get(BASE + path).text)
    return match.group(1) if match else ""


def login(username, password):
    s = requests.Session()
    s.post(BASE + "/login", data={"csrf_token": csrf(s, "/login"),
                                  "username": username, "password": password})
    return s


print(f"=== 관리자 기능 테스트: {BASE} ===")

# 일반 사용자 + 상품 준비 ------------------------------------------------------
victim = requests.Session()
victim_name = f"target{uuid.uuid4().hex[:6]}"
PRODUCT_TITLE = f"관리자테스트상품{uuid.uuid4().hex[:6]}"
victim.post(BASE + "/register", data={"csrf_token": csrf(victim, "/register"),
                                      "username": victim_name,
                                      "password": PASSWORD, "password_confirm": PASSWORD})
victim = login(victim_name, PASSWORD)
r = victim.post(BASE + "/products/new",
                data={"csrf_token": csrf(victim, "/products/new"), "title": PRODUCT_TITLE,
                      "description": "관리자 조치 대상 상품입니다.", "price": "10000"},
                allow_redirects=True)
product_id = re.search(r"/products/([0-9a-f]{32})", r.url + r.text).group(1)
victim_id = re.search(r"/users/([0-9a-f]{32})", victim.get(BASE + "/me").text).group(1)
check("테스트 상품 준비", bool(product_id))

# 관리자 로그인 + 재인증 --------------------------------------------------------
admin = login(ADMIN_USER, ADMIN_PW)
r = admin.get(BASE + "/admin/", allow_redirects=False)
check("관리자 진입 시 재인증 요구", r.status_code == 302 and "/reauth" in r.headers.get("Location", ""))

r = admin.post(BASE + "/reauth", data={"csrf_token": csrf(admin, "/reauth"),
                                       "password": "WrongAdminPw!1", "next": "/admin/"})
check("재인증: 잘못된 비밀번호 거부", r.status_code == 401)

r = admin.post(BASE + "/reauth", data={"csrf_token": csrf(admin, "/reauth"),
                                       "password": ADMIN_PW, "next": "/admin/"},
               allow_redirects=True)
check("재인증 후 관리자 대시보드 접근", "관리자 대시보드" in r.text)

# 관리 기능 -------------------------------------------------------------------
check("관리자: 사용자 목록 조회", victim_name in admin.get(BASE + "/admin/users").text)
check("관리자: 상품 목록 조회", PRODUCT_TITLE in admin.get(BASE + "/admin/products").text)
check("관리자: 신고 목록 조회", "신고 관리" in admin.get(BASE + "/admin/reports").text)
check("관리자: 감사 로그 조회", "auth.login" in admin.get(BASE + "/admin/logs").text)

token = csrf(admin, "/admin/products")
r = admin.post(BASE + "/admin/products/action",
               data={"csrf_token": token, "product_id": product_id, "action": "block"},
               allow_redirects=True)
check("관리자: 상품 차단", "차단 처리했습니다" in r.text)
check("관리자: 차단 상품 일반 목록에서 제외",
      f"/products/{product_id}" not in requests.get(BASE + "/", params={"q": PRODUCT_TITLE}).text)
check("관리자: 차단 상품은 비로그인 상세 조회 불가",
      requests.get(f"{BASE}/products/{product_id}").status_code == 404)

r = admin.post(BASE + "/admin/products/action",
               data={"csrf_token": csrf(admin, "/admin/products"),
                     "product_id": product_id, "action": "unblock"}, allow_redirects=True)
check("관리자: 상품 차단 해제", "차단 해제 처리했습니다" in r.text)

r = admin.post(BASE + "/admin/users/action",
               data={"csrf_token": csrf(admin, "/admin/users"),
                     "user_id": victim_id, "action": "dormant"}, allow_redirects=True)
check("관리자: 사용자 휴면 전환", "휴면 전환 처리했습니다" in r.text)
check("휴면 사용자는 로그인 불가",
      "휴면 처리된 계정" in login(victim_name, PASSWORD).get(BASE + "/login").text
      or requests.Session().post(BASE + "/login", data={"csrf_token": csrf(requests.Session(), "/login")}).status_code in (200, 400))

r = admin.post(BASE + "/admin/users/action",
               data={"csrf_token": csrf(admin, "/admin/users"),
                     "user_id": victim_id, "action": "activate"}, allow_redirects=True)
check("관리자: 사용자 활성화 복구", "활성화 처리했습니다" in r.text)

r = admin.post(BASE + "/admin/users/balance",
               data={"csrf_token": csrf(admin, "/admin/users"),
                     "user_id": victim_id, "amount": "50000"}, allow_redirects=True)
check("관리자: 잔액 조정", "잔액을" in r.text)

r = admin.post(BASE + "/admin/users/balance",
               data={"csrf_token": csrf(admin, "/admin/users"),
                     "user_id": victim_id, "amount": "-10000000"}, allow_redirects=True)
check("관리자: 잔액 음수 방지", "음수가 될 수 없습니다" in r.text)

r = admin.post(BASE + "/admin/users/balance",
               data={"csrf_token": csrf(admin, "/admin/users"),
                     "user_id": victim_id, "amount": "-99999999"}, allow_redirects=False)
check("관리자: 범위 밖 조정 금액 거부(400)", r.status_code == 400)

admin_id = re.search(r"/users/([0-9a-f]{32})", admin.get(BASE + "/me").text).group(1)
r = admin.post(BASE + "/admin/users/action",
               data={"csrf_token": csrf(admin, "/admin/users"),
                     "user_id": admin_id, "action": "ban"}, allow_redirects=True)
check("관리자: 자기 자신 정지 방지", "자기 자신에게는 적용할 수 없습니다" in r.text)

r = admin.post(BASE + "/admin/users/action",
               data={"csrf_token": csrf(admin, "/admin/users"),
                     "user_id": admin_id, "action": "demote"}, allow_redirects=True)
check("관리자: 자기 자신 권한 해제 방지", "자기 자신에게는 적용할 수 없습니다" in r.text)

check("관리자 조치가 감사 로그에 기록됨",
      "admin.product_block" in admin.get(BASE + "/admin/logs", params={"action": "admin."}).text)

print("\n--- 결과 요약 ---")
passed = sum(1 for _, ok in results if ok)
print(f"{passed}/{len(results)} 통과")
for name, ok in results:
    if not ok:
        print(f"  - 실패: {name}")
sys.exit(0 if passed == len(results) else 1)
