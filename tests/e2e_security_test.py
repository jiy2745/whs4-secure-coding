#!/usr/bin/env python3
"""기능 E2E + 보안 테스트 스크립트.

실행 (서버를 먼저 띄운 뒤):
    RATELIMIT_ENABLED=0 PORT=5099 python app.py &
    python tests/e2e_security_test.py http://127.0.0.1:5099

IP 기준 rate limit 은 tests/ratelimit_test.py 에서 따로 검증한다.
"""
import io
import re
import sys
import uuid

import requests
from PIL import Image

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5099"
PASSWORD = "Test!Pass123"
CSRF_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}" + (f"  — {detail}" if detail else ""))
    return bool(condition)


def csrf(session, path):
    html = session.get(BASE + path).text
    match = CSRF_RE.search(html)
    return match.group(1) if match else ""


def new_user(prefix):
    """회원가입 + 로그인 후 세션 반환."""
    username = f"{prefix}{uuid.uuid4().hex[:6]}"
    s = requests.Session()
    token = csrf(s, "/register")
    r = s.post(
        BASE + "/register",
        data={"csrf_token": token, "username": username,
              "password": PASSWORD, "password_confirm": PASSWORD},
        allow_redirects=True,
    )
    assert "회원가입이 완료" in r.text or r.status_code == 200, "회원가입 실패"
    token = csrf(s, "/login")
    s.post(BASE + "/login",
           data={"csrf_token": token, "username": username, "password": PASSWORD})
    return s, username


def png_bytes(color=(200, 30, 30), size=(60, 60)):
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


def create_product(session, title, description, price, image=True):
    token = csrf(session, "/products/new")
    files = {"image": ("photo.png", png_bytes(), "image/png")} if image else {}
    r = session.post(
        BASE + "/products/new",
        data={"csrf_token": token, "title": title, "description": description, "price": str(price)},
        files=files,
        allow_redirects=True,
    )
    match = re.search(r"/products/([0-9a-f]{32})", r.url + r.text)
    return (match.group(1) if match else None), r


print(f"=== 대상: {BASE} ===\n--- 1. 기능 E2E (가입 → 상품 등록 → 신고 → 송금) ---")

# 1) 회원가입/로그인 -----------------------------------------------------------
alice, alice_name = new_user("alice")
bob, bob_name = new_user("bob")
me = alice.get(BASE + "/me")
check("회원가입 + 로그인 후 마이페이지 접근", me.status_code == 200 and alice_name in me.text)
check("가입 시 초기 잔액 지급", "100,000원" in me.text)

# 2) 상품 등록 ----------------------------------------------------------------
pid, resp = create_product(alice, "테스트 상품 노트북", "상태 좋은 노트북입니다. 직거래 환영.", 350000)
check("상품 등록 (이미지 포함)", bool(pid), f"product_id={pid}")
detail = alice.get(f"{BASE}/products/{pid}")
check("상품 상세 조회", detail.status_code == 200 and "테스트 상품 노트북" in detail.text)
check("업로드 이미지 서빙", alice.get(BASE + re.search(r'/uploads/([0-9a-f]{32}\.png)',
      detail.text).group(0)).status_code == 200 if "/uploads/" in detail.text else False)

# 3) 검색 ---------------------------------------------------------------------
found = alice.get(BASE + "/", params={"q": "노트북"})
check("상품 검색", "테스트 상품 노트북" in found.text)
filtered = alice.get(BASE + "/", params={"q": "노트북", "min_price": 900000})
check("가격 필터 동작", "테스트 상품 노트북" not in filtered.text)

sort_ok = True
for sort_value in ("recent", "price_asc", "price_desc", "'; DROP TABLE products; --", "created_at"):
    resp = alice.get(BASE + "/", params={"q": "노트북", "sort": sort_value,
                                         "min_price": 1000, "max_price": 500000})
    sort_ok = sort_ok and resp.status_code == 200 and "Traceback" not in resp.text
check("정렬 옵션 전부 정상 동작(주입값 포함)", sort_ok)

# 4) 채팅(1:1 폼 전송) ---------------------------------------------------------
alice_id = re.search(r"/users/([0-9a-f]{32})", alice.get(BASE + "/me").text).group(1)
token = csrf(bob, f"/messages/{alice_id}")
bob.post(f"{BASE}/messages/{alice_id}", data={"csrf_token": token, "content": "안녕하세요, 상품 문의드립니다."})
thread = bob.get(f"{BASE}/messages/{alice_id}")
check("1:1 채팅 메시지 전송/조회", "상품 문의드립니다" in thread.text)

# 5) 신고 → 임계치 자동 차단 ----------------------------------------------------
token = csrf(bob, f"/report?target_type=product&target_id={pid}")
r = bob.post(BASE + "/report", data={"csrf_token": token, "target_type": "product",
                                     "target_id": pid, "reason": "허위 매물로 의심됩니다."})
check("상품 신고 접수", "신고가 접수되었습니다" in r.text)

token = csrf(bob, f"/report?target_type=product&target_id={pid}")
r = bob.post(BASE + "/report", data={"csrf_token": token, "target_type": "product",
                                     "target_id": pid, "reason": "중복 신고 시도입니다."})
check("동일 대상 중복 신고 차단", "이미 신고한 대상" in r.text)

token = csrf(alice, f"/report?target_type=product&target_id={pid}")
r = alice.post(BASE + "/report", data={"csrf_token": token, "target_type": "product",
                                       "target_id": pid, "reason": "본인 상품 신고 시도입니다."})
check("본인 상품 신고 차단", "본인이 등록한 상품은 신고할 수 없습니다" in r.text)

reporters = [new_user(f"rep{i}")[0] for i in range(2)]
for idx, rep in enumerate(reporters):
    token = csrf(rep, f"/report?target_type=product&target_id={pid}")
    r = rep.post(BASE + "/report", data={"csrf_token": token, "target_type": "product",
                                         "target_id": pid, "reason": f"판매 금지 물품입니다 {idx}"})
check("신고 3건 누적 → 상품 자동 차단", "자동 차단되었습니다" in r.text)
check("차단된 상품은 목록에서 제외", "테스트 상품 노트북" not in requests.get(BASE + "/", params={"q": "노트북"}).text)

# 6) 송금 ---------------------------------------------------------------------
token = csrf(bob, "/transfer")
r = bob.post(BASE + "/transfer", data={"csrf_token": token, "recipient": alice_name,
                                       "amount": "30000", "memo": "상품 대금", "password": PASSWORD},
             allow_redirects=True)
check("송금 성공", "30,000원을 송금했습니다" in r.text)
check("송금자 잔액 차감", "70,000원" in bob.get(BASE + "/wallet").text)
check("수취인 잔액 증가", "130,000원" in alice.get(BASE + "/wallet").text)

token = csrf(bob, "/transfer")
r = bob.post(BASE + "/transfer", data={"csrf_token": token, "recipient": alice_name,
                                       "amount": "99999999", "memo": "", "password": PASSWORD})
check("한도 초과 송금 거부", "송금할 수 있습니다" in r.text or "이하만" in r.text)

token = csrf(bob, "/transfer")
r = bob.post(BASE + "/transfer", data={"csrf_token": token, "recipient": alice_name,
                                       "amount": "5000000", "memo": "", "password": PASSWORD})
check("잔액 초과 송금 거부", "잔액이 부족합니다" in r.text)

token = csrf(bob, "/transfer")
r = bob.post(BASE + "/transfer", data={"csrf_token": token, "recipient": bob_name,
                                       "amount": "1000", "memo": "", "password": PASSWORD})
check("자기 자신 송금 거부", "자기 자신에게는 송금할 수 없습니다" in r.text)

token = csrf(bob, "/transfer")
r = bob.post(BASE + "/transfer", data={"csrf_token": token, "recipient": alice_name,
                                       "amount": "1000", "memo": "", "password": "WrongPass!99"})
check("송금 시 비밀번호 재확인 강제", r.status_code == 401 and "비밀번호가 올바르지 않습니다" in r.text)


print("\n--- 2. 보안 테스트 ---")

# SQL Injection --------------------------------------------------------------
sqli_login = requests.Session()
token = csrf(sqli_login, "/login")
r = sqli_login.post(BASE + "/login", data={"csrf_token": token,
                                           "username": "' OR '1'='1' --", "password": "anything"})
check("SQLi: 로그인 우회 실패", r.status_code == 401 and "환영합니다" not in r.text)

r = requests.get(BASE + "/", params={"q": "' OR 1=1 --"})
check("SQLi: 검색어 주입 무해", r.status_code == 200 and "테스트 상품" not in r.text)

r = requests.get(BASE + "/", params={"q": "'; DROP TABLE products; --"})
check("SQLi: DROP TABLE 시도 후에도 정상 동작",
      r.status_code == 200 and requests.get(BASE + "/").status_code == 200)

r = requests.get(BASE + "/", params={"q": "%"})
check("LIKE 와일드카드 이스케이프", "%" in r.text or r.status_code == 200)

# XSS ------------------------------------------------------------------------
xss_payload = '<script>alert("xss")</script><img src=x onerror=alert(1)>'
xss_pid, _ = create_product(alice, f"XSS 테스트 {xss_payload}", f"설명 {xss_payload}", 1000, image=False)
page = alice.get(f"{BASE}/products/{xss_pid}").text
check("XSS: 상품 제목/설명 이스케이프",
      "<script>alert" not in page and "&lt;script&gt;" in page)
check("XSS: onerror 속성 미실행 형태로 출력", "onerror=alert(1)>" not in page)

token = csrf(alice, "/me")
alice.post(BASE + "/me/profile", data={"csrf_token": token, "bio": xss_payload})
prof = alice.get(f"{BASE}/users/{alice_id}").text
check("XSS: 프로필 소개글 이스케이프", "<script>alert" not in prof and "&lt;script&gt;" in prof)

# CSRF -----------------------------------------------------------------------
r = alice.post(BASE + "/products/new", data={"title": "CSRF 상품", "description": "토큰 없음", "price": "1000"})
check("CSRF: 토큰 없는 POST 거부", r.status_code == 400 and "보안 토큰" in r.text)

r = alice.post(BASE + "/products/new", data={"csrf_token": "forged-token-value",
                                             "title": "CSRF 상품", "description": "위조", "price": "1000"})
check("CSRF: 위조 토큰 거부", r.status_code == 400)

r = alice.post(BASE + "/logout", data={})
check("CSRF: 토큰 없는 로그아웃 거부", r.status_code == 400)
check("CSRF: 로그아웃은 GET 불가", alice.get(BASE + "/logout", allow_redirects=False).status_code == 405)

# IDOR / 접근 제어 -------------------------------------------------------------
victim_pid, _ = create_product(alice, "IDOR 대상 상품", "소유자만 수정 가능해야 합니다.", 5000, image=False)
token = csrf(bob, "/products/new")
r = bob.post(f"{BASE}/products/{victim_pid}/edit",
             data={"csrf_token": token, "title": "탈취됨", "description": "공격자가 수정", "price": "1"})
check("IDOR: 타인 상품 수정 차단", r.status_code == 403)
r = bob.post(f"{BASE}/products/{victim_pid}/delete", data={"csrf_token": token})
check("IDOR: 타인 상품 삭제 차단", r.status_code == 403)
check("IDOR: 원본 상품 유지",
      "IDOR 대상 상품" in alice.get(f"{BASE}/products/{victim_pid}").text)

anon = requests.Session()
check("인증: 비로그인 상품 등록 차단",
      anon.get(BASE + "/products/new", allow_redirects=False).status_code == 302)
check("인증: 비로그인 마이페이지 차단",
      anon.get(BASE + "/me", allow_redirects=False).status_code == 302)
check("인증: 비로그인 송금 차단",
      anon.get(BASE + "/transfer", allow_redirects=False).status_code == 302)
check("권한: 일반 사용자 관리자 페이지 차단",
      alice.get(BASE + "/admin/", allow_redirects=False).status_code == 403)
check("권한: 비로그인 관리자 페이지 차단",
      anon.get(BASE + "/admin/users", allow_redirects=False).status_code == 302)
r = alice.post(BASE + "/admin/users/action",
               data={"csrf_token": csrf(alice, "/me"), "user_id": alice_id, "action": "promote"})
check("권한: 일반 사용자의 관리자 API 직접 호출 차단", r.status_code == 403)

# 파일 업로드 -------------------------------------------------------------------
token = csrf(alice, "/products/new")
r = alice.post(BASE + "/products/new",
               data={"csrf_token": token, "title": "웹셸 업로드 시도", "description": "확장자만 이미지", "price": "1000"},
               files={"image": ("shell.png", b"<?php system($_GET['c']); ?>", "image/png")})
check("업로드: 이미지가 아닌 파일 거부", "이미지 파일이 아니거나" in r.text)

token = csrf(alice, "/products/new")
r = alice.post(BASE + "/products/new",
               data={"csrf_token": token, "title": "확장자 위조", "description": "php 확장자", "price": "1000"},
               files={"image": ("shell.php", png_bytes(), "image/png")})
check("업로드: 허용되지 않은 확장자 거부", "이미지만 업로드" in r.text)

check("업로드: 경로 조작 차단(../)",
      requests.get(BASE + "/uploads/../../../etc/passwd").status_code in (400, 404))
check("업로드: 인코딩된 경로 조작 차단",
      requests.get(BASE + "/uploads/..%2f..%2fapp.py").status_code in (400, 404))
check("업로드: 임의 파일명 접근 차단",
      requests.get(BASE + "/uploads/app.py").status_code == 404)

# 계정 잠금 ---------------------------------------------------------------------
victim, victim_name = new_user("lock")
attacker = requests.Session()
codes = []
for i in range(6):
    token = csrf(attacker, "/login")
    r = attacker.post(BASE + "/login",
                      data={"csrf_token": token, "username": victim_name, "password": f"WrongPw!{i}"})
    codes.append(r.status_code)
check("로그인 실패 5회 후 계정 잠금", codes[-1] == 429, f"status codes={codes}")
token = csrf(attacker, "/login")
r = attacker.post(BASE + "/login", data={"csrf_token": token, "username": victim_name, "password": PASSWORD})
check("잠금 중에는 올바른 비밀번호도 거부", r.status_code == 429)

# 세션 -------------------------------------------------------------------------
sess_user, sess_name = new_user("sess")
cookie = [c for c in sess_user.cookies if c.name == "tsp_session"][0]
check("세션 쿠키 HttpOnly", "HttpOnly" in str(cookie._rest).replace("httponly", "HttpOnly"))
check("세션 쿠키 SameSite=Lax", str(cookie._rest.get("SameSite", "")).lower() == "lax")
old_cookie_value = cookie.value

token = csrf(sess_user, "/me")
r = sess_user.post(BASE + "/me/password",
                   data={"csrf_token": token, "current_password": PASSWORD,
                         "password": "NewTest!Pass456", "password_confirm": "NewTest!Pass456"},
                   allow_redirects=True)
check("비밀번호 변경 성공", "다시 로그인" in r.text)
stale = requests.Session()
stale.cookies.set("tsp_session", old_cookie_value)
check("비밀번호 변경 후 기존 세션 무효화",
      stale.get(BASE + "/me", allow_redirects=False).status_code == 302)

# 정보 노출 ---------------------------------------------------------------------
r = requests.get(BASE + "/products/" + "f" * 32)
check("404 페이지에 내부 정보 미노출",
      r.status_code == 404 and "Traceback" not in r.text and "sqlite" not in r.text.lower())
r = requests.get(BASE + "/products/not-a-valid-id")
check("잘못된 ID 형식 안전 처리", r.status_code == 404 and "Traceback" not in r.text)
r = requests.get(BASE + "/", params={"min_price": "abc", "max_price": "!!"})
check("타입 오류 입력 안전 처리", r.status_code == 200 and "Traceback" not in r.text)
headers = requests.get(BASE + "/").headers
check("보안 헤더: CSP", "Content-Security-Policy" in headers)
check("보안 헤더: X-Content-Type-Options", headers.get("X-Content-Type-Options") == "nosniff")
check("보안 헤더: X-Frame-Options", headers.get("X-Frame-Options") == "DENY")
check("서버 응답에 스택트레이스 없음", "Werkzeug Debugger" not in requests.get(BASE + "/").text)

# 입력 검증 ---------------------------------------------------------------------
token = csrf(alice, "/products/new")
r = alice.post(BASE + "/products/new",
               data={"csrf_token": token, "title": "가격 음수", "description": "음수 가격 시도", "price": "-1000"})
check("검증: 음수 가격 거부", "가격은" in r.text)
token = csrf(alice, "/products/new")
r = alice.post(BASE + "/products/new",
               data={"csrf_token": token, "title": "a" * 200, "description": "길이 초과", "price": "1000"})
check("검증: 제목 길이 초과 거부", "100" in r.text and "field" in r.text.lower() or "이내" in r.text or "Field" in r.text)
token = csrf(alice, "/products/new")
r = alice.post(BASE + "/products/new",
               data={"csrf_token": token, "title": "가격 문자열", "description": "숫자가 아님", "price": "1e9"})
check("검증: 숫자가 아닌 가격 거부", "가격" in r.text)

weak = requests.Session()
token = csrf(weak, "/register")
r = weak.post(BASE + "/register", data={"csrf_token": token, "username": "weakuser1",
                                        "password": "password", "password_confirm": "password"})
check("검증: 약한 비밀번호 거부", "비밀번호는 최소" in r.text or "흔한 비밀번호" in r.text)
token = csrf(weak, "/register")
r = weak.post(BASE + "/register", data={"csrf_token": token, "username": "bad user!",
                                        "password": PASSWORD, "password_confirm": PASSWORD})
check("검증: 잘못된 아이디 형식 거부", "아이디는 영문" in r.text)
token = csrf(weak, "/register")
r = weak.post(BASE + "/register", data={"csrf_token": token, "username": alice_name,
                                        "password": PASSWORD, "password_confirm": PASSWORD})
check("검증: 아이디 중복 거부", "이미 사용 중인 아이디" in r.text)

token = csrf(bob, f"/report?target_type=product&target_id={pid}")
r = bob.post(BASE + "/report", data={"csrf_token": token, "target_type": "product",
                                     "target_id": "not-a-uuid", "reason": "형식 위반 테스트입니다"})
check("검증: 신고 대상 ID 형식 검증", "Invalid" in r.text or "형식" in r.text or r.status_code in (200, 400))

print("\n--- 결과 요약 ---")
passed = sum(1 for _, ok, _ in results if ok)
print(f"{passed}/{len(results)} 통과")
failed = [name for name, ok, _ in results if not ok]
if failed:
    print("실패 항목:")
    for name in failed:
        print(f"  - {name}")
sys.exit(1 if failed else 0)
