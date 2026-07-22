# 보안 체크리스트

작성 기준: 강의자료 31p 체크리스트 예시(4개 섹션 21개 항목)를 **모두** 포함하고,
과제에서 직접 설계한 기능(송금 / 검색 / 관리자)에 대한 항목을 추가했습니다.

- **확인 방법** 열의 테스트 이름은 `tests/` 의 자동화 테스트 항목명입니다. 전체 실행: `bash tests/run_all.sh`
- 최종 실행 결과: **105개 항목 전부 통과** (E2E·보안 66 / 채팅 15 / 관리자 21 / Rate limit 3)

---

## A. 회원가입 및 프로필 관리 (강의자료 체크리스트 1~7)

| # | 체크리스트 항목 | 구현 위치 | 구현 내용 | 확인 방법 | 결과 |
|---|---|---|---|---|---|
| A-1 | **서버측 입력 검증** — username/password 길이·허용 문자·형식 검증, XSS 대비 필터링·인코딩 | `forms.py:98` (RegisterForm), `forms.py:59` (NoControlChars), `forms.py:36` (strip_filter/NFC 정규화) | 아이디는 `^[A-Za-z0-9_]{3,20}$` 화이트리스트, 비밀번호 10~128자, 제어문자 차단, 유니코드 NFC 정규화로 동형이의 아이디 방지 | `검증: 잘못된 아이디 형식 거부`, `검증: 약한 비밀번호 거부`, `검증: 아이디 중복 거부` | ✅ |
| A-2 | **CSRF 보호** — 회원가입·로그인·프로필 수정 등 모든 폼 | `extensions.py:9` (`CSRFProtect`), `app.py:164` (`csrf.init_app`), 모든 폼은 `FlaskForm` 상속(`forms.py`), 템플릿의 `{{ form.csrf_token }}` | 앱 전역에서 POST/PUT/PATCH/DELETE 에 토큰 검증. 토큰 누락·위조 시 400 + 안내 페이지 | `CSRF: 토큰 없는 POST 거부`, `CSRF: 위조 토큰 거부`, `CSRF: 토큰 없는 로그아웃 거부` | ✅ |
| A-3 | **비밀번호 보안** — 평문 저장 금지, bcrypt/Argon2 + 고유 salt | `security.py:36` (Argon2id 파라미터), `security.py:52` (`hash_password`), `blueprints/auth.py:54` (가입 시 해싱) | Argon2id(time_cost=3, memory=64MiB, parallelism=2), salt 는 해시마다 자동 생성되어 해시 문자열에 포함. `needs_rehash` 로 파라미터 변경 시 로그인 시점에 자동 재해싱(`auth.py:111`) | DB 확인 + `회원가입 + 로그인 후 마이페이지 접근` | ✅ |
| A-4 | **세션 쿠키 설정** — HttpOnly, HTTPS 환경에서 Secure | `config.py:58-60`, `config.py:57` (쿠키 이름) | `HttpOnly=True`, `SameSite=Lax` 상시 적용. `SESSION_COOKIE_SECURE` 는 환경변수로 제어하며 ngrok(HTTPS) 배포 시 `1` (README 4.2) | `세션 쿠키 HttpOnly`, `세션 쿠키 SameSite=Lax` | ✅ |
| A-5 | **세션 만료 및 재인증** — 일정 시간 후 만료, 민감 작업 시 재인증 | `config.py:62-67`, `security.py:135` (`enforce_session_policy`), `security.py:229` (`reauth_required`), `blueprints/auth.py:139` (`/reauth`) | 절대 만료 60분 + 유휴 20분 자동 로그아웃. 관리자 페이지는 최근 10분 내 비밀번호 재확인 필수(로그인만으로는 통과 불가). 송금은 매 건 비밀번호 입력 | `관리자 진입 시 재인증 요구`, `재인증: 잘못된 비밀번호 거부`, `송금 시 비밀번호 재확인 강제` | ✅ |
| A-6 | **실패 로그인 방어** — 실패 횟수에 따른 계정 잠금/지연 | `security.py:251` (`login_lock_state`), `security.py:265` (`register_login_failure`), `blueprints/auth.py:68`(로그인), `extensions.py:12` (IP rate limit) | 계정별 5회 연속 실패 → 10분 잠금(429). 추가로 IP당 로그인 10회/분, 60회/시간 제한 | `로그인 실패 5회 후 계정 잠금`, `잠금 중에는 올바른 비밀번호도 거부`, `로그인 시도 IP Rate limit(10/분) 동작` | ✅ |
| A-7 | **오류 메시지** — 스택 트레이스·DB 정보 미노출 | `app.py:42-95` (오류 핸들러), `templates/error.html`, `app.py:28` (파일 로깅) | 400/403/404/413/429/500 및 처리되지 않은 예외 전부 동일한 안내 페이지. 예외 상세는 `instance/app.log` 에만 기록. `FLASK_DEBUG` 기본 0 | `404 페이지에 내부 정보 미노출`, `잘못된 ID 형식 안전 처리`, `타입 오류 입력 안전 처리`, `서버 응답에 스택트레이스 없음` | ✅ |

**추가 구현 (체크리스트 확장)**

| # | 항목 | 구현 위치 | 확인 방법 | 결과 |
|---|---|---|---|---|
| A-8 | 세션 고정(Session Fixation) 방지 — 로그인 시 세션 재발급 | `security.py:114` (`start_user_session` → `session.clear()`) | `비밀번호 변경 후 기존 세션 무효화` | ✅ |
| A-9 | 비밀번호 변경 시 기존 세션 전부 무효화 | `security.py:155-165` (auth_at vs password_changed_at 비교), `blueprints/auth.py:226` | `비밀번호 변경 후 기존 세션 무효화` | ✅ |
| A-10 | 사용자 열거(User Enumeration) 방지 | `security.py:46` (더미 해시), `security.py:56` (`verify_password`), `blueprints/auth.py:97` (동일 메시지) | `SQLi: 로그인 우회 실패` | ✅ |
| A-11 | 오픈 리다이렉트 방지 (`next` 파라미터) | `security.py:392` (`safe_redirect_target`) | 코드 리뷰 (외부 URL 은 홈으로 강제) | ✅ |
| A-12 | 로그아웃은 POST + CSRF 토큰 | `blueprints/auth.py:126`, `templates/base.html` | `CSRF: 로그아웃은 GET 불가` | ✅ |

---

## B. 상품 등록 및 관리 (강의자료 체크리스트 8~12)

| # | 체크리스트 항목 | 구현 위치 | 구현 내용 | 확인 방법 | 결과 |
|---|---|---|---|---|---|
| B-1 | **폼 입력 검증** — 제목/설명/가격 서버측 검증, 필수 항목, 가격 숫자 형식·범위 | `forms.py:171` (ProductForm), `config.py:95-99` (한도값) | 제목 1~100자, 설명 1~2000자, 가격은 정수 0~100,000,000 범위. 클라이언트 입력을 신뢰하지 않고 서버에서 재검증 | `검증: 음수 가격 거부`, `검증: 제목 길이 초과 거부`, `검증: 숫자가 아닌 가격 거부` | ✅ |
| B-2 | **XSS 방어** — 상품 설명 등 HTML/스크립트 이스케이프 | `app.py:150` (autoescape 명시), `templates/products/detail.html`(`|safe` 미사용), `security.py:358` (CSP) | Jinja2 autoescape 로 모든 사용자 입력 이스케이프. 프로젝트 전체에서 `|safe` 를 한 번도 쓰지 않음. CSP `script-src 'self'` 로 인라인 스크립트 실행 자체를 차단 | `XSS: 상품 제목/설명 이스케이프`, `XSS: onerror 속성 미실행 형태로 출력`, `XSS: 프로필 소개글 이스케이프` | ✅ |
| B-3 | **인증된 사용자만 등록** — 등록/수정/삭제는 로그인 사용자만 | `security.py:186` (`login_required`), `blueprints/products.py:218/274/320` | 상품 등록·수정·삭제 라우트 전부 `@login_required` | `인증: 비로그인 상품 등록 차단` | ✅ |
| B-4 | **소유자 확인** — 수정/삭제 시 요청자가 소유자인지 검증 (IDOR) | `blueprints/products.py:65` (`_require_owner_or_admin`), `products.py:276/322/339` | URL 의 상품 ID 만 바꿔 접근하면 403 + 감사 로그 기록. UPDATE 문에도 `seller_id = ?` 조건 중복 적용 | `IDOR: 타인 상품 수정 차단`, `IDOR: 타인 상품 삭제 차단`, `IDOR: 원본 상품 유지` | ✅ |
| B-5 | **데이터 무결성** — DB 저장 전 필수 항목·형식 검증 | `forms.py:171`, `schema.sql:26-38` (CHECK 제약) | 애플리케이션 검증 + DB CHECK(길이/가격 범위/status 값/FK) 이중 방어 | `검증: 음수 가격 거부` 및 스키마 CHECK | ✅ |

**추가 구현 (파일 업로드 — 과제 보안 요구사항)**

| # | 항목 | 구현 위치 | 구현 내용 | 확인 방법 | 결과 |
|---|---|---|---|---|---|
| B-6 | 업로드 확장자 화이트리스트 | `forms.py:205` (`FileAllowed`), `config.py:83` | png/jpg/jpeg/gif/webp 만 허용 | `업로드: 허용되지 않은 확장자 거부` | ✅ |
| B-7 | 실제 파일 내용 검증(확장자 위조 차단) | `blueprints/products.py:84` (`_save_image`) | Pillow 로 이미지 헤더 검증 후 **재인코딩**하여 저장 → EXIF·주석에 숨긴 페이로드 제거 | `업로드: 이미지가 아닌 파일 거부` | ✅ |
| B-8 | 파일명 처리(경로 조작·덮어쓰기 방지) | `blueprints/products.py:111` (UUID 생성), `products.py:27` (`STORED_FILENAME_RE`), `products.py:132` (`uploaded_file`) | 사용자 파일명을 쓰지 않고 서버가 UUID 생성. 서빙 시 `^[0-9a-f]{32}\.(png|jpg|gif|webp)$` 정규식과 정확히 일치해야만 응답 | `업로드: 경로 조작 차단(../)`, `업로드: 인코딩된 경로 조작 차단`, `업로드: 임의 파일명 접근 차단` | ✅ |
| B-9 | 업로드 크기 제한 / 디컴프레션 폭탄 방지 | `config.py:81` (`MAX_CONTENT_LENGTH` 5MB), `config.py:85` (`MAX_IMAGE_PIXELS`), `app.py:69` (413 핸들러) | 요청 본문 5MB 상한, 4천만 픽셀 초과 이미지 거부 | 413 오류 핸들러 + 코드 리뷰 | ✅ |
| B-10 | 업로드 파일은 웹 루트 밖에 저장 + 전용 라우트로만 서빙 | `config.py:78` (`instance/uploads`), `blueprints/products.py:132` | `static/` 밖에 저장하고 MIME 고정 + `X-Content-Type-Options: nosniff` + `CSP: sandbox` 헤더로 응답 | `업로드 이미지 서빙`, `업로드: 임의 파일명 접근 차단` | ✅ |

---

## C. 실시간 채팅 및 메시징 (강의자료 체크리스트 13~17)

| # | 체크리스트 항목 | 구현 위치 | 구현 내용 | 확인 방법 | 결과 |
|---|---|---|---|---|---|
| C-1 | **메시지 내용 검증** — 길이 제한, 허용 문자, XSS 이스케이프 | `blueprints/chat.py:43` (`_clean_message`), `forms.py:308` (MessageForm) | 1~500자, 공백 전용 거부, 제어문자 거부. 출력은 템플릿 autoescape + JS `textContent` | `소켓: 길이 초과 메시지 거부`, `소켓: 공백 메시지 거부`, `소켓: 채팅 XSS 페이로드 이스케이프 저장/출력` | ✅ |
| C-2 | **사용자 인증** — Socket 연결 시 인증 상태 확인 | `blueprints/chat.py:167` (`handle_connect` → `return False`), `chat.py:156` (`_authenticated_user`) | 세션이 없거나 비활성 계정이면 연결 거부. **이벤트마다** 세션을 다시 확인해 연결 후 정지된 계정도 즉시 차단 | `소켓: 비인증 연결 거부`, `소켓: 위조 세션 쿠키 연결 거부` | ✅ |
| C-3 | **메시지 검증** — 클라이언트 수신 데이터의 형식·내용 서버 검증 | `blueprints/chat.py:187/217` (payload 타입 검사), `chat.py:43` | dict 가 아니거나 content 가 문자열이 아니면 거부, 대상 ID 는 32자리 hex 정규식 검증 | `소켓: 잘못된 형식(dict 아님) 거부`, `소켓: 숫자 content 거부`, `소켓: 잘못된 대상 ID 거부` | ✅ |
| C-4 | **Rate Limiting** — 단기간 과도한 메시지 제한(스팸 방지) | `security.py:330` (`SlidingWindowLimiter`), `blueprints/chat.py:38/195/237` | 사용자별 10초당 10건. 초과 시 `error_message` 반환하고 저장하지 않음 | `소켓: 채팅 Rate limit 동작` | ✅ |
| C-5 | **연결 암호화** — 운영 환경에서 WSS(SSL/TLS) | README 4.2 (ngrok HTTPS), `config.py:60` (`SESSION_COOKIE_SECURE`), `security.py:358` (HSTS) | ngrok HTTPS 로 서비스하면 Socket.IO 가 자동으로 `wss://` 사용. HTTPS 요청에는 HSTS 헤더 부여 | ngrok 배포 시 브라우저 개발자도구에서 `wss://` 확인 | ✅ |

**추가 구현**

| # | 항목 | 구현 위치 | 확인 방법 | 결과 |
|---|---|---|---|---|
| C-6 | 교차 출처 WebSocket 하이재킹(CSWSH) 방지 | `extensions.py:20` (`cors_allowed_origins=None` → 동일 출처만) | `교차 출처(Origin) WebSocket 연결 차단` | ✅ |
| C-7 | 1:1 메시지가 제3자에게 새지 않음 | `blueprints/chat.py:250` (개인 룸 전송), `chat.py:173` (`join_room(user_id)`) | `소켓: 1:1 메시지가 제3자에게 전달되지 않음` | ✅ |
| C-8 | 자기 자신·존재하지 않는 대상에게 전송 차단 | `blueprints/chat.py:225-231` | `소켓: 자기 자신에게 전송 거부`, `소켓: 존재하지 않는 대상 거부` | ✅ |

---

## D. 안전 거래 및 신고 (강의자료 체크리스트 18~21)

| # | 체크리스트 항목 | 구현 위치 | 구현 내용 | 확인 방법 | 결과 |
|---|---|---|---|---|---|
| D-1 | **폼 입력 검증** — target_id·reason 검증, 길이 제한, XSS 방어 | `forms.py:251` (ReportForm) | `target_id` 는 32자리 hex 정규식, `target_type` 은 select 화이트리스트, 사유 5~500자 + 제어문자 차단 | `검증: 신고 대상 ID 형식 검증` | ✅ |
| D-2 | **인증된 사용자 접근** — 신고는 로그인 사용자만 | `blueprints/reports.py:72` (`@login_required`) | 비로그인 시 로그인 페이지로 리다이렉트 | `인증: 비로그인 송금 차단`(동일 데코레이터 계열), 코드 리뷰 | ✅ |
| D-3 | **데이터 무결성 및 로그 관리** — 올바른 형식 저장 + 신고 활동 감사 로그 | `schema.sql:41-51` (CHECK/UNIQUE), `blueprints/reports.py:131` (`audit("report.created")`), `security.py:303` (`audit`) | 신고 접수·임계치 자동 조치·관리자 처리 모두 `audit_logs` 에 기록(IP 포함, 민감정보 제외) | `관리자: 감사 로그 조회`, `관리자 조치가 감사 로그에 기록됨` | ✅ |
| D-4 | **신고 남용 방지** — 반복 신고 제한, 건수 제한, 관리자 검토 | `schema.sql:50` (UNIQUE 제약), `blueprints/reports.py:125` (중복 처리), `reports.py:101-110` (24시간 10건 제한), `blueprints/admin.py:185` (신고 검토 화면) | 동일 대상 1회만 신고 가능(DB UNIQUE), 24시간 10건 상한, 본인/본인 상품 신고 금지, 모든 신고는 관리자 검토 큐로 | `동일 대상 중복 신고 차단`, `본인 상품 신고 차단`, `관리자: 신고 목록 조회` | ✅ |

**추가 구현 (자동 차단 — 요구사항 "악성 유저·상품 차단")**

| # | 항목 | 구현 위치 | 확인 방법 | 결과 |
|---|---|---|---|---|
| D-5 | 신고 3건 누적 시 상품 자동 차단 | `blueprints/reports.py:31` (`_apply_threshold`), `config.py:109` | `신고 3건 누적 → 상품 자동 차단`, `차단된 상품은 목록에서 제외` | ✅ |
| D-6 | 신고 5건 누적 시 사용자 자동 휴면 | `blueprints/reports.py:56-68`, `config.py:110` | `관리자: 사용자 휴면 전환`, `휴면 사용자는 로그인 불가` | ✅ |
| D-7 | 휴면/정지 계정은 로그인 및 세션 즉시 차단 | `blueprints/auth.py:100` (로그인 거부), `security.py:167` (세션 정책) | `휴면 사용자는 로그인 불가` | ✅ |

---

## E. 송금 (직접 설계한 요구사항)

| # | 항목 | 구현 위치 | 구현 내용 | 확인 방법 | 결과 |
|---|---|---|---|---|---|
| E-1 | 금액 형식·범위 서버 검증 | `forms.py:276` (TransferForm), `config.py:103-105` | 정수, 100원~10,000,000원 | `한도 초과 송금 거부` | ✅ |
| E-2 | 송금 시 비밀번호 재확인(민감 작업 재인증) | `blueprints/transfers.py:55` | 매 송금마다 비밀번호 검증, 실패 시 401 + 감사 로그 | `송금 시 비밀번호 재확인 강제` | ✅ |
| E-3 | 원자적 트랜잭션 + 경쟁 조건 차단 | `db.py:85` (`transaction`, BEGIN IMMEDIATE), `blueprints/transfers.py:81` | 출금·입금·기록을 한 트랜잭션으로. 실패 시 전체 롤백 | `송금자 잔액 차감`, `수취인 잔액 증가` | ✅ |
| E-4 | 잔액 부족 / 음수 잔액 방지 | `blueprints/transfers.py:85-92`, `schema.sql:15` (`CHECK (balance >= 0)`) | 앱 검증 + `balance >= ?` 조건부 UPDATE + DB CHECK 삼중 방어 | `잔액 초과 송금 거부`, `관리자: 잔액 음수 방지` | ✅ |
| E-5 | 자기 자신 송금 금지 | `blueprints/transfers.py:75`, `schema.sql:75` (CHECK) | 앱 + DB 이중 차단 | `자기 자신 송금 거부` | ✅ |
| E-6 | 송금 rate limit + 감사 로그 | `blueprints/transfers.py:41` (10회/시간), `transfers.py:118` (`audit`) | 자동화된 대량 송금 차단, 전 건 기록 | 코드 리뷰 + `관리자: 감사 로그 조회` | ✅ |

## F. 검색 (직접 설계한 요구사항)

| # | 항목 | 구현 위치 | 구현 내용 | 확인 방법 | 결과 |
|---|---|---|---|---|---|
| F-1 | 검색어 SQL Injection 방지 | `db.py:63-80` (파라미터 바인딩), `blueprints/products.py:161-186` | 조건절은 코드가 만든 고정 문자열, 사용자 값은 전부 `?` 바인딩 | `SQLi: 검색어 주입 무해`, `SQLi: DROP TABLE 시도 후에도 정상 동작` | ✅ |
| F-2 | LIKE 메타문자 이스케이프 | `db.py:102` (`like_escape`), `products.py:170`, `auth.py:273`, `admin.py:81` | `%`, `_`, `\` 이스케이프 + `ESCAPE '\'` 사용 | `LIKE 와일드카드 이스케이프` | ✅ |
| F-3 | 정렬 파라미터 화이트리스트 | `blueprints/products.py:40` (`SORT_SQL`) | 사용자 입력을 ORDER BY 에 직접 넣지 않고 사전 정의된 3개 값에만 매핑 | 코드 리뷰 + `SQLi: 검색어 주입 무해` | ✅ |
| F-4 | 검색 입력 길이/타입 검증, 페이지네이션 상한 | `forms.py:215` (SearchForm), `products.py:179-183` | 검색어 50자, 페이지 1~1000, 잘못된 타입은 무시하고 기본값 사용 | `타입 오류 입력 안전 처리`, `가격 필터 동작` | ✅ |
| F-5 | 차단 상품·비활성 판매자 상품 노출 차단 | `blueprints/products.py:159`, `products.py:256-259` | 목록·상세 모두에서 제외(소유자·관리자만 열람) | `차단된 상품은 목록에서 제외`, `관리자: 차단 상품은 비로그인 상세 조회 불가` | ✅ |

## G. 관리자 (직접 설계한 요구사항)

| # | 항목 | 구현 위치 | 구현 내용 | 확인 방법 | 결과 |
|---|---|---|---|---|---|
| G-1 | 관리자 라우트 권한 검증 | `security.py:197` (`admin_required`), `blueprints/admin.py` 전 라우트 | 로그인 + `role='admin'` 서버측 확인. 실패 시 403 + 감사 로그 | `권한: 일반 사용자 관리자 페이지 차단`, `권한: 일반 사용자의 관리자 API 직접 호출 차단` | ✅ |
| G-2 | 관리자 진입 시 재인증 | `security.py:229` (`reauth_required`) | 로그인 상태여도 최근 10분 내 비밀번호 재확인이 없으면 차단 | `관리자 진입 시 재인증 요구` | ✅ |
| G-3 | 관리자 행위 전량 감사 로그 | `blueprints/admin.py` 각 액션의 `security.audit(...)` | 사용자 상태 변경/권한 변경/잔액 조정/상품 차단·삭제/신고 처리 기록 | `관리자 조치가 감사 로그에 기록됨` | ✅ |
| G-4 | 관리자 자기 파괴 방지(락아웃 방지) | `blueprints/admin.py:88`, `admin.py:105` | 자기 자신 정지/휴면/강등 불가, 마지막 관리자 강등 불가 | `관리자: 자기 자신 정지 방지`, `관리자: 자기 자신 권한 해제 방지` | ✅ |
| G-5 | 관리자 액션도 CSRF 토큰 + 입력 검증 | `forms.py:325-360` (Admin*Form) | 모든 액션이 POST + 토큰 + 값 화이트리스트/정규식 검증 | `관리자: 범위 밖 조정 금액 거부(400)` | ✅ |

## H. 공통 / 인프라

| # | 항목 | 구현 위치 | 구현 내용 | 확인 방법 | 결과 |
|---|---|---|---|---|---|
| H-1 | 모든 DB 쿼리 파라미터 바인딩 | `db.py` 전체 (`query_all`/`query_one`/`execute`/`transaction`) | 프로젝트 전체에서 f-string/`%`/`+` 로 SQL 을 만들지 않음(조건절 조립 시에도 값은 `?`) | `SQLi: 로그인 우회 실패` 외 SQLi 테스트 4건 | ✅ |
| H-2 | 보안 응답 헤더 | `security.py:358` (`install_security_headers`) | CSP(`script-src 'self'`), `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, HTTPS 시 HSTS, 로그인 상태에서 `Cache-Control: no-store` | `보안 헤더: CSP`, `보안 헤더: X-Content-Type-Options`, `보안 헤더: X-Frame-Options` | ✅ |
| H-3 | 비밀 정보 관리 | `config.py:29` (`load_secret_key`), `.gitignore` | 하드코딩 키 없음. 키 파일은 0600 권한으로 자동 생성되고 git 에서 제외. `.env` 도 제외 | 코드 리뷰 + `.gitignore` | ✅ |
| H-4 | IP 기준 rate limit(전역) | `extensions.py:12` | 기본 600회/시간 + 라우트별 제한(로그인·가입·상품등록·신고·송금) | `로그인 시도 IP Rate limit(10/분) 동작`, `회원가입 IP Rate limit(10/시간) 동작` | ✅ |
| H-5 | 신뢰할 수 없는 프록시 헤더 처리 | `security.py:76` (`client_ip`), `config.py:125` | 기본값은 X-Forwarded-For 무시(IP 위조로 rate limit 우회 방지). 프록시를 신뢰할 때만 명시적으로 활성화 | 코드 리뷰 | ✅ |
| H-6 | 디버그 모드 기본 비활성 | `app.py:220` | `FLASK_DEBUG` 기본 0, 켜면 경고 출력 | `서버 응답에 스택트레이스 없음` | ✅ |
| H-7 | 식별자 열거 방지 | `db.py:34` (`new_id` = UUID4) | 순차 정수 ID 대신 UUID 사용 | 코드 리뷰 | ✅ |
