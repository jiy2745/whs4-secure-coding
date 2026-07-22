"""확장 객체 단일 인스턴스 (순환 import 방지용)."""
from flask_limiter import Limiter
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect

from security import client_ip

# 모든 POST/PUT/PATCH/DELETE 요청에 CSRF 토큰 검증을 강제한다.
csrf = CSRFProtect()

# IP 기준 요청 제한 (로그인 무차별 대입, 스팸 등록 방지)
limiter = Limiter(
    key_func=client_ip,
    default_limits=["600 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
)

# 실시간 채팅. async_mode='threading' → 별도 워커 없이 표준 스레드로 동작.
# cors_allowed_origins=None → 동일 출처(Origin)에서 온 연결만 허용 (CSWSH 방지)
socketio = SocketIO(
    cors_allowed_origins=None,
    async_mode="threading",
    logger=False,
    engineio_logger=False,
)
