"""애플리케이션 설정.

보안에 직접 영향을 주는 값은 모두 이 파일 한 곳에 모아 두고, 운영 환경에서는
환경변수(.env)로 덮어쓴다. 기본값은 "안전한 쪽"으로 잡는다.
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def load_secret_key() -> str:
    """SECRET_KEY 로드.

    1) 환경변수 SECRET_KEY 우선.
    2) 없으면 instance/secret_key 파일에서 읽고, 그래도 없으면 새로 생성(0600).
    코드에 하드코딩된 기본 키를 두지 않는다. (하드코딩 키 = 세션 위조 가능)
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key and len(env_key) >= 32:
        return env_key
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    key_file = INSTANCE_DIR / "secret_key"
    if key_file.exists():
        value = key_file.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_urlsafe(64)
    key_file.write_text(value, encoding="utf-8")
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass  # Windows 마운트(/mnt/c) 등에서는 무시
    return value


class Config:
    # --- 세션/쿠키 ---
    SECRET_KEY = load_secret_key()
    SESSION_COOKIE_NAME = "tsp_session"
    SESSION_COOKIE_HTTPONLY = True          # JS(document.cookie)에서 접근 불가 → XSS 시 세션 탈취 방지
    SESSION_COOKIE_SAMESITE = "Lax"         # 크로스 사이트 POST에 쿠키 미전송 → CSRF 2차 방어
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)  # HTTPS(ngrok) 배포 시 1
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_env_int("SESSION_LIFETIME_MINUTES", 60))
    SESSION_REFRESH_EACH_REQUEST = True

    # 유휴 시간 초과(마지막 요청 이후 N분) → 세션 폐기
    IDLE_TIMEOUT_MINUTES = _env_int("IDLE_TIMEOUT_MINUTES", 20)
    # 민감 작업(비밀번호 변경, 송금, 관리자 페이지) 재인증 유효 시간
    REAUTH_WINDOW_MINUTES = _env_int("REAUTH_WINDOW_MINUTES", 10)

    # --- Rate limit ---
    # 기본값은 항상 True. 자동화 테스트에서만 RATELIMIT_ENABLED=0 으로 끈다.
    RATELIMIT_ENABLED = _env_bool("RATELIMIT_ENABLED", True)

    # --- CSRF ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600              # 토큰 유효 1시간
    WTF_CSRF_SSL_STRICT = True

    # --- DB / 업로드 ---
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(INSTANCE_DIR / "market.db"))
    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", str(INSTANCE_DIR / "uploads"))
    MAX_CONTENT_LENGTH = _env_int("MAX_UPLOAD_MB", 5) * 1024 * 1024   # 요청 본문 상한(업로드 DoS 방지)
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
    ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG", "GIF", "WEBP"}            # Pillow가 판별한 실제 포맷
    MAX_IMAGE_PIXELS = 40_000_000                                     # 디컴프레션 폭탄 방지

    # --- 인증/계정 잠금 ---
    LOGIN_MAX_FAILURES = _env_int("LOGIN_MAX_FAILURES", 5)
    LOGIN_LOCKOUT_MINUTES = _env_int("LOGIN_LOCKOUT_MINUTES", 10)
    PASSWORD_MIN_LENGTH = 10
    PASSWORD_MAX_LENGTH = 128
    USERNAME_MIN_LENGTH = 3
    USERNAME_MAX_LENGTH = 20

    # --- 도메인 규칙 ---
    PRODUCT_TITLE_MAX = 100
    PRODUCT_DESC_MAX = 2000
    PRICE_MIN = 0
    PRICE_MAX = 100_000_000            # 1억원
    BIO_MAX = 500
    MESSAGE_MAX = 500
    REPORT_REASON_MIN = 5
    REPORT_REASON_MAX = 500
    TRANSFER_MIN = 100
    TRANSFER_MAX = 10_000_000
    TRANSFER_MEMO_MAX = 100
    SEARCH_QUERY_MAX = 50

    # 신고 임계치 (초과 시 자동 차단/휴면)
    REPORT_BLOCK_THRESHOLD_PRODUCT = _env_int("REPORT_BLOCK_THRESHOLD_PRODUCT", 3)
    REPORT_DORMANT_THRESHOLD_USER = _env_int("REPORT_DORMANT_THRESHOLD_USER", 5)
    REPORT_DAILY_LIMIT_PER_USER = _env_int("REPORT_DAILY_LIMIT_PER_USER", 10)

    # 채팅 스팸 방지 (사용자당 WINDOW초 안에 최대 MAX건)
    CHAT_RATE_MAX = _env_int("CHAT_RATE_MAX", 10)
    CHAT_RATE_WINDOW = _env_int("CHAT_RATE_WINDOW", 10)

    # 신규 가입자 초기 잔액(데모용 포인트)
    SIGNUP_BONUS = _env_int("SIGNUP_BONUS", 100_000)

    # --- 기타 ---
    JSON_SORT_KEYS = False
    TEMPLATES_AUTO_RELOAD = False
    PREFERRED_URL_SCHEME = "https"
    # ngrok 등 프록시 뒤에서 실제 클라이언트 IP를 신뢰할지 여부 (기본: 신뢰 안 함)
    TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", False)
