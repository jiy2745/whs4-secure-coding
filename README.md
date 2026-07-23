# Tiny Second-hand Shopping Platform (시큐어 코딩 과제)

Flask 기반 중고거래 플랫폼입니다. **기능 구현만큼 "보안 약점이 없는 것"을 목표**로 만들었습니다.

- 보안 체크리스트(항목 / 구현 위치 / 확인 결과): [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)

---

## 1. 기능 요약

| 구분 | 기능 |
|---|---|
| 유저 관리 | 회원가입, 로그인/로그아웃, 사용자 조회·검색, 프로필 조회, 마이페이지(소개글·비밀번호 수정) |
| 상품 관리 | 상품 등록(사진 업로드), 내 상품 관리, 목록 조회(이름만) → 상세 페이지, 수정/삭제, 판매완료 전환 |
| 검색 | 상품명·설명 키워드 검색, 가격 범위 필터, 정렬(최신/가격), 페이지네이션, 사용자 검색 |
| 소통 | 실시간 전체 채팅(Socket.IO), 1:1 채팅, 쪽지함 |
| 신고/차단 | 상품·사용자 신고(사유 필수), 신고 3건 누적 시 상품 자동 차단, 5건 누적 시 사용자 휴면 전환 |
| 송금 | 사용자 간 송금(비밀번호 재확인), 지갑 잔액·거래 내역 |
| 관리자 | 대시보드(통계), 사용자 관리(활성/휴면/정지/권한/잔액), 상품 관리(차단/해제/삭제), 신고 처리, 감사 로그 조회 |

---

## 2. 환경 설정

### 2.1 요구 사항

- Ubuntu(WSL2 포함) 또는 Linux
- Python 3.10 이상 (개발/테스트 환경: Python 3.12)
- git

### 2.2 설치

```bash
git clone https://github.com/jiy2745/whs4-secure-coding

# 가상환경 (venv 또는 conda 중 편한 것)
python3 -m venv .venv
source .venv/bin/activate
#   conda 를 쓴다면:
#   conda create -n secure-coding python=3.12 -y && conda activate secure-coding

pip install -r requirements.txt
```

### 2.3 환경 변수 (선택)

```bash
cp .env.example .env      # 값을 비워두면 안전한 기본값이 사용됨
```

주요 항목:

| 변수 | 기본값 | 설명 |
|---|---|---|
| `SECRET_KEY` | 자동 생성 | 세션 서명 키. 비우면 `instance/secret_key` 에 자동 생성(권한 0600) |
| `SESSION_COOKIE_SECURE` | `0` | **HTTPS(ngrok)로 공개할 때는 반드시 `1`** — 쿠키에 Secure 플래그 부여 |
| `TRUST_PROXY_HEADERS` | `0` | ngrok 등 프록시 뒤에서 실제 클라이언트 IP를 쓰려면 `1` |
| `IDLE_TIMEOUT_MINUTES` | `20` | 무활동 자동 로그아웃 |
| `LOGIN_MAX_FAILURES` / `LOGIN_LOCKOUT_MINUTES` | `5` / `10` | 로그인 실패 임계치 / 잠금 시간 |
| `REPORT_BLOCK_THRESHOLD_PRODUCT` | `3` | 상품 자동 차단 신고 수 |
| `REPORT_DORMANT_THRESHOLD_USER` | `5` | 사용자 자동 휴면 신고 수 |
| `MAX_UPLOAD_MB` | `5` | 업로드 최대 크기 |
| `FLASK_DEBUG` | `0` | **운영에서는 절대 `1` 로 두지 말 것** (스택 트레이스·디버거 노출) |

### 2.4 초기화 및 관리자 계정 생성

```bash
flask --app app init-db                 # DB 스키마 생성 (첫 실행 시 자동 생성되므로 생략 가능)
flask --app app create-admin            # 관리자 계정 생성 (아이디/비밀번호 대화형 입력)
flask --app app seed-demo               # (선택) 데모 사용자·상품 데이터
```

`seed-demo` 로 만들어지는 데모 계정: `alice` / `bob` / `carol`, 비밀번호 `Demo!Pass123`
(**데모 전용입니다. 실제 공개 서비스에서는 사용하지 마세요.**)

---

## 3. 실행

```bash
python app.py
# → http://127.0.0.1:5000
```

포트를 바꾸려면 `PORT=8080 python app.py`.

---

## 4. ngrok 으로 외부에 공개하기

### 4.1 ngrok 설치

WSL(우분투)에서는 apt 로 설치하는 것을 권장합니다.

```bash
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
  | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
  && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
  | sudo tee /etc/apt/sources.list.d/ngrok.list \
  && sudo apt update && sudo apt install ngrok
```

계정 토큰 등록(최초 1회). 토큰은 https://dashboard.ngrok.com/get-started/your-authtoken 에서 발급받습니다.

```bash
ngrok config add-authtoken <YOUR_TOKEN>
```

### 4.2 실행

애플리케이션을 백그라운드로 실행한 뒤(HTTPS 로 서비스되므로 Secure 쿠키를 켠다), 같은 터미널에서 터널을 엽니다.

```bash
# 1) 앱을 백그라운드로 실행
SESSION_COOKIE_SECURE=1 TRUST_PROXY_HEADERS=1 python app.py &

# 2) 터널 열기
ngrok http 5000
```

출력된 `https://xxxx-xx-xx-xx-xx.ngrok-free.app` 주소로 접속합니다.

끝낼 때는 ngrok 을 `Ctrl+C` 로 멈춘 뒤, 백그라운드 앱도 종료합니다.

```bash
kill %1     # 백그라운드로 띄운 앱 종료 (안 되면: pkill -f "python app.py")
```

> **주의**
> - `SESSION_COOKIE_SECURE=1` 을 켜지 않으면 HTTPS 로 접속해도 쿠키에 Secure 플래그가 붙지 않습니다.
> - ngrok 무료 플랜은 접속 시 경고 페이지가 뜰 수 있습니다. (`ngrok http 5000 --request-header-add "ngrok-skip-browser-warning: true"`)
> - 실시간 채팅(WebSocket)은 ngrok 터널에서도 그대로 동작합니다. 서버가 동일 출처(Origin)만 허용하므로 다른 사이트에서의 접속은 차단됩니다.

---

## 5. 테스트

```bash
pip install -r requirements-dev.txt   # 테스트용 패키지(requests 등) 설치
bash tests/run_all.sh
```

4개 스위트가 순서대로 실행됩니다(총 **105개 검증 항목**).

| 스크립트 | 내용 | 항목 수 |
|---|---|---|
| `tests/e2e_security_test.py` | 기능 E2E(가입→상품→검색→채팅→신고→송금) + SQLi/XSS/CSRF/IDOR/업로드/세션/에러노출/입력검증 | 66 |
| `tests/chat_socket_test.py` | Socket.IO 인증·검증·rate limit·1:1 메시지 격리 | 15 |
| `tests/admin_test.py` | 관리자 권한·재인증·차단/휴면/잔액조정·감사 로그 | 21 |
| `tests/ratelimit_test.py` | IP 기준 rate limit, 교차 출처(Origin) WebSocket 차단 | 3 |

개별 실행 예:

```bash
RATELIMIT_ENABLED=0 PORT=5099 python app.py &      # 테스트용 서버 (IP 제한 해제)
python tests/e2e_security_test.py http://127.0.0.1:5099
```

> `RATELIMIT_ENABLED=0` 은 **테스트 전용**입니다. 테스트가 수백 번 요청을 보내기 때문에
> IP rate limit 에 먼저 걸리는 것을 피하기 위한 옵션이며, rate limit 자체는 `tests/ratelimit_test.py`
> 에서 기본 설정(활성화) 상태로 따로 검증합니다.

---

## 6. 프로젝트 구조

```
secure-coding/
├── app.py                  # 앱 팩토리, 오류 핸들러, CLI 명령
├── config.py               # 보안 관련 설정 일원화 (쿠키/세션/업로드/임계치)
├── db.py                   # SQLite 접근 계층 (전 쿼리 파라미터 바인딩, 트랜잭션)
├── schema.sql              # 스키마 + CHECK/UNIQUE/FK 제약
├── security.py             # 해싱, 세션 정책, 접근 제어 데코레이터, 감사 로그, 보안 헤더
├── forms.py                # 서버측 입력 검증 (WTForms) + CSRF
├── extensions.py           # CSRFProtect / Limiter / SocketIO 인스턴스
├── seed.py                 # 데모 데이터
├── blueprints/
│   ├── auth.py             # 회원가입/로그인/마이페이지/프로필/사용자 검색
│   ├── products.py         # 상품 CRUD/검색/이미지 업로드·서빙
│   ├── chat.py             # 전체 채팅 + 1:1 채팅 (HTTP + Socket.IO 핸들러)
│   ├── reports.py          # 신고 + 임계치 자동 차단/휴면
│   ├── transfers.py        # 송금(원자적 트랜잭션)
│   └── admin.py            # 관리자 기능
├── templates/              # Jinja2 (autoescape 기본 활성)
├── static/                 # CSS, chat.js, socket.io 클라이언트(번들 포함)
├── tests/                  # E2E + 보안 테스트
└── instance/               # DB, 업로드 파일, 로그, secret_key (git 제외)
```

---

## 7. 보안 요약

자세한 내용은 [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md) 참고.

- **비밀번호**: Argon2id 해싱(고유 salt 자동), 복잡도·흔한 비밀번호 검증, 변경 시 기존 세션 무효화
- **로그인 방어**: 계정별 5회 실패 시 10분 잠금 + IP 기준 rate limit(10회/분), 실패 시 동일한 응답·동일한 처리 시간
- **SQL Injection**: 모든 쿼리 `?` 파라미터 바인딩, `ORDER BY` 는 화이트리스트 매핑, `LIKE` 메타문자 이스케이프
- **XSS**: Jinja2 autoescape + `|safe` 미사용, 채팅은 `textContent` 로만 렌더, CSP(`script-src 'self'`)로 인라인 스크립트 차단
- **CSRF**: 모든 상태 변경 요청에 토큰(`CSRFProtect` 전역), SameSite=Lax, 로그아웃도 POST
- **세션**: HttpOnly / SameSite=Lax / (HTTPS 시)Secure, 절대 만료 60분·유휴 20분, 로그인 시 세션 재발급(고정 공격 방지), 민감 작업 재인증
- **접근 제어**: `@login_required` / `@admin_required` / 소유자 검증(IDOR 방지), 관리자 API 직접 호출 차단
- **파일 업로드**: 확장자 화이트리스트 + Pillow 실제 포맷 검증 + 재인코딩 + 서버 생성 UUID 파일명 + 웹 루트 밖 저장 + 전용 서빙 라우트
- **오류 처리**: 사용자에게는 일반 메시지만, 스택 트레이스·SQL·경로는 `instance/app.log` 에만 기록
- **감사 로그**: 로그인/신고/송금/관리자 조치 등 보안 행위 기록(민감 정보 제외)

---

## 8. 라이선스 / 참고

교육 과제용 프로젝트입니다.

- 과제 원본 스펙/스켈레톤: <https://github.com/ugonfor/secure-coding>
  (요구사항과 기능 명세를 따랐으며, 애플리케이션 코드는 보안 요구사항에 맞춰 새로 작성했습니다.)
- 참고 자료: KISA 시큐어 코딩 가이드, OWASP Top 10, OWASP ASVS.
