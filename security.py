"""보안 공통 모듈.

- 비밀번호 해싱(Argon2id)          → hash_password / verify_password
- 세션 수명 관리, 세션 고정 방지    → start_user_session / enforce_session_policy
- 접근 제어 데코레이터              → login_required / admin_required / reauth_required
- 계정 잠금(로그인 실패 제한)       → register_login_failure / login_lock_state
- 감사 로그                         → audit
- 보안 응답 헤더(CSP 등)            → install_security_headers
- 채팅 스팸 방지(Rate limit)        → SlidingWindowLimiter
- 오픈 리다이렉트 방지              → safe_redirect_target
"""
import functools
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import (
    abort,
    current_app,
    flash,
    g,
    redirect,
    request,
    session,
    url_for,
)

import db as database

# Argon2id : 2015 Password Hashing Competition 우승 알고리즘.
# salt 는 라이브러리가 해시마다 자동 생성해 해시 문자열에 포함한다.
_hasher = PasswordHasher(
    time_cost=3,          # 반복 횟수
    memory_cost=65536,    # 64 MiB — GPU 대량 크래킹 비용 상승
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

# 존재하지 않는 계정으로 로그인 시도했을 때 응답 시간을 맞추기 위한 더미 해시
# (계정 존재 여부가 응답 시간으로 새는 것을 막는다 = 사용자 열거 방지)
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing-equalization")


# --------------------------------------------------------------------------
# 비밀번호
# --------------------------------------------------------------------------
def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(stored_hash: str | None, plain: str) -> bool:
    """비밀번호 검증. 계정이 없어도 동일한 비용을 소모한다."""
    target = stored_hash or _DUMMY_HASH
    try:
        _hasher.verify(target, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return stored_hash is not None


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# --------------------------------------------------------------------------
# 요청 컨텍스트 / 사용자
# --------------------------------------------------------------------------
def client_ip() -> str:
    """클라이언트 IP.

    X-Forwarded-For 는 조작 가능하므로 신뢰 설정(TRUST_PROXY_HEADERS)이 켜진
    경우에만 사용한다. 기본은 소켓 주소.
    """
    if current_app.config.get("TRUST_PROXY_HEADERS"):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:45]
    return (request.remote_addr or "unknown")[:45]


def current_user():
    """세션의 user_id 로 사용자 조회 (요청당 1회 캐시)."""
    if "user" in g:
        return g.user
    user = None
    user_id = session.get("user_id")
    if user_id:
        user = database.query_one(
            "SELECT id, username, bio, role, status, balance, created_at, last_login_at, "
            "       password_changed_at "
            "FROM users WHERE id = ?",
            (user_id,),
        )
    g.user = user
    return user


def is_admin() -> bool:
    user = current_user()
    return bool(user and user["role"] == "admin")


# --------------------------------------------------------------------------
# 세션
# --------------------------------------------------------------------------
def start_user_session(user_id: str) -> None:
    """로그인 성공 시 호출.

    session.clear() 로 기존 세션 값을 전부 버리고 새 세션 쿠키를 발급받는다.
    → 공격자가 미리 심어둔 세션 값을 그대로 승격시키는 세션 고정(Session Fixation) 공격 방지.
    """
    session.clear()
    session["user_id"] = user_id
    session["auth_at"] = time.time()      # 로그인 시각
    # reauth_at 은 일부러 넣지 않는다.
    # → 로그인만으로는 민감 작업(관리자 페이지 등)이 열리지 않고,
    #   해당 작업을 처음 시도하는 시점에 비밀번호를 다시 확인한다.
    session["last_seen"] = time.time()
    session.permanent = True
    session.modified = True


def end_user_session() -> None:
    session.clear()


def enforce_session_policy() -> None:
    """before_request 훅.

    1) 유휴 시간 초과 → 세션 폐기 (절대 만료는 PERMANENT_SESSION_LIFETIME 이 담당)
    2) 정지/휴면 계정은 즉시 로그아웃
    """
    if "user_id" not in session:
        return
    idle_limit = current_app.config["IDLE_TIMEOUT_MINUTES"] * 60
    last_seen = session.get("last_seen", 0)
    if time.time() - last_seen > idle_limit:
        end_user_session()
        g.session_expired = True
        return
    session["last_seen"] = time.time()

    user = current_user()
    if user is None:
        end_user_session()
        return

    # 비밀번호 변경 이전에 발급된 세션은 무효 (탈취된 세션 강제 종료)
    try:
        changed_at = datetime.fromisoformat(user["password_changed_at"]).timestamp()
    except (TypeError, ValueError):
        changed_at = 0
    if session.get("auth_at", 0) < changed_at:
        end_user_session()
        g.pop("user", None)
        g.session_expired = True
        return

    if user["status"] != "active":
        end_user_session()
        g.pop("user", None)
        g.account_blocked = user["status"]


def reauth_fresh() -> bool:
    window = current_app.config["REAUTH_WINDOW_MINUTES"] * 60
    return (time.time() - session.get("reauth_at", 0)) <= window


def mark_reauth() -> None:
    session["reauth_at"] = time.time()
    session.modified = True


# --------------------------------------------------------------------------
# 접근 제어 데코레이터
# --------------------------------------------------------------------------
def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("로그인이 필요합니다.", "error")
            return redirect(url_for("auth.login", next=request.full_path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    """관리자 전용. 로그인 여부와 role 을 서버에서 반드시 확인한다."""

    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            flash("로그인이 필요합니다.", "error")
            return redirect(url_for("auth.login", next=request.full_path))
        if user["role"] != "admin":
            audit("admin.access_denied", target_type="route", target_id=request.path)
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def _reauth_next() -> str:
    """재인증 후 돌아갈 경로.

    POST 라우트로 되돌리면 GET 요청이 되어 405 가 나므로, GET 요청일 때만
    현재 경로를 쓰고 그 외에는 같은 사이트의 referer(경로만) → 홈 순으로 되돌린다.
    """
    if request.method == "GET":
        return request.full_path
    referrer = request.referrer or ""
    parsed = urlparse(referrer)
    if referrer and parsed.netloc == request.host and parsed.path:
        return parsed.path
    return url_for("products.index")


def reauth_required(view):
    """민감 작업(관리자 페이지 등) 전 재인증 강제.

    로그인만 되어 있다고 통과시키지 않는다. 마지막 비밀번호 확인이
    REAUTH_WINDOW_MINUTES 이내여야 한다.
    """

    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("auth.login", next=request.full_path))
        if not reauth_fresh():
            flash("보안을 위해 비밀번호를 다시 확인합니다.", "info")
            return redirect(url_for("auth.reauth", next=_reauth_next()))
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------
# 계정 잠금 (로그인 실패 제한)
# --------------------------------------------------------------------------
def login_lock_state(user_row) -> tuple[bool, int]:
    """(잠김 여부, 남은 초)"""
    if user_row is None or not user_row["locked_until"]:
        return False, 0
    try:
        until = datetime.fromisoformat(user_row["locked_until"])
    except ValueError:
        return False, 0
    remaining = (until - datetime.now(timezone.utc)).total_seconds()
    if remaining > 0:
        return True, int(remaining)
    return False, 0


def register_login_failure(user_row) -> None:
    """실패 횟수 증가, 임계치 초과 시 계정 잠금."""
    if user_row is None:
        return
    max_fail = current_app.config["LOGIN_MAX_FAILURES"]
    lock_minutes = current_app.config["LOGIN_LOCKOUT_MINUTES"]
    failures = user_row["failed_logins"] + 1
    if failures >= max_fail:
        until = (datetime.now(timezone.utc) + timedelta(minutes=lock_minutes)).isoformat(
            timespec="seconds"
        )
        database.execute(
            "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
            (failures, until, user_row["id"]),
        )
        audit(
            "auth.account_locked",
            actor_id=user_row["id"],
            target_type="user",
            target_id=user_row["id"],
            detail=f"{failures}회 연속 실패로 {lock_minutes}분 잠금",
        )
    else:
        database.execute(
            "UPDATE users SET failed_logins = ? WHERE id = ?", (failures, user_row["id"])
        )


def reset_login_failures(user_id: str) -> None:
    database.execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
        (database.now_iso(), user_id),
    )


# --------------------------------------------------------------------------
# 감사 로그
# --------------------------------------------------------------------------
def audit(action: str, actor_id: str | None = None, target_type: str | None = None,
          target_id: str | None = None, detail: str = "") -> None:
    """보안 관련 행위를 남긴다. 비밀번호 등 민감 값은 절대 기록하지 않는다."""
    if actor_id is None:
        actor_id = session.get("user_id")
    try:
        database.execute(
            "INSERT INTO audit_logs (id, actor_id, action, target_type, target_id, detail, ip, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                database.new_id(),
                actor_id,
                action[:64],
                target_type,
                target_id,
                detail[:500],
                client_ip(),
                database.now_iso(),
            ),
        )
    except Exception:  # 감사 로그 실패가 기능을 막아서는 안 된다
        current_app.logger.exception("감사 로그 기록 실패: %s", action)


# --------------------------------------------------------------------------
# Rate limit (채팅 스팸 방지 등 인메모리 슬라이딩 윈도우)
# --------------------------------------------------------------------------
class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: int):
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = self._events[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.max_events:
                return False
            bucket.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


# --------------------------------------------------------------------------
# 보안 응답 헤더
# --------------------------------------------------------------------------
def install_security_headers(app) -> None:
    @app.after_request
    def _headers(response):
        host = request.host
        # 인라인 스크립트/스타일을 전면 금지한다. (XSS 가 발생해도 실행을 막는 2차 방어)
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            f"connect-src 'self' ws://{host} wss://{host}; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "object-src 'none'; "
            "frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        # 인증이 필요한 페이지는 캐시 금지
        if session.get("user_id"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


# --------------------------------------------------------------------------
# 오픈 리다이렉트 방지
# --------------------------------------------------------------------------
def safe_redirect_target(target: str | None, fallback_endpoint: str = "products.index") -> str:
    """next 파라미터 검증: 같은 사이트의 경로만 허용한다."""
    if target:
        parsed = urlparse(target)
        if not parsed.scheme and not parsed.netloc and target.startswith("/"):
            return target
    return url_for(fallback_endpoint)
