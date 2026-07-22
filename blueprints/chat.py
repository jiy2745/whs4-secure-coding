"""실시간 전체 채팅 + 1:1 채팅.

WebSocket 이벤트도 HTTP 요청과 똑같이 취급한다.
- 연결 시 세션 인증 확인 (인증 안 되면 연결 거부)
- 수신 데이터 형식/길이 서버측 검증
- 사용자별 Rate limit (스팸 방지)
- 저장/전송은 평문 그대로 두고, 출력 시점에 이스케이프(템플릿 autoescape, JS textContent)
"""
import re

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_socketio import disconnect, emit, join_room

import db as database
import security
from config import Config
from forms import MessageForm

bp = Blueprint("chat", __name__)

ID_RE = re.compile(r"^[0-9a-f]{32}$")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

GLOBAL_ROOM = "global"
HISTORY_LIMIT = 50

# 사용자당 CHAT_RATE_WINDOW 초 안에 CHAT_RATE_MAX 건까지만 허용
message_limiter = security.SlidingWindowLimiter(
    max_events=Config.CHAT_RATE_MAX, window_seconds=Config.CHAT_RATE_WINDOW
)


def _clean_message(raw) -> str:
    """소켓으로 들어온 메시지 검증. 실패 시 ValueError."""
    if not isinstance(raw, str):
        raise ValueError("메시지 형식이 올바르지 않습니다.")
    content = raw.strip()
    if not content:
        raise ValueError("빈 메시지는 보낼 수 없습니다.")
    if len(content) > Config.MESSAGE_MAX:
        raise ValueError(f"메시지는 {Config.MESSAGE_MAX}자 이하여야 합니다.")
    if CONTROL_CHARS.search(content):
        raise ValueError("사용할 수 없는 문자가 포함되어 있습니다.")
    return content


def _store_message(sender_id: str, recipient_id: str | None, content: str) -> dict:
    message_id = database.new_id()
    created_at = database.now_iso()
    database.execute(
        "INSERT INTO messages (id, sender_id, recipient_id, content, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (message_id, sender_id, recipient_id, content, created_at),
    )
    return {"id": message_id, "created_at": created_at}


def _active_user(user_id: str):
    if not ID_RE.match(user_id or ""):
        return None
    return database.query_one(
        "SELECT id, username, status FROM users WHERE id = ? AND status = 'active'", (user_id,)
    )


# --------------------------------------------------------------------------
# 페이지
# --------------------------------------------------------------------------
@bp.route("/chat")
@security.login_required
def global_chat():
    rows = database.query_all(
        "SELECT m.id, m.content, m.created_at, u.username, u.id AS sender_id "
        "FROM messages m JOIN users u ON u.id = m.sender_id "
        "WHERE m.recipient_id IS NULL AND u.status = 'active' "
        "ORDER BY m.created_at DESC LIMIT ?",
        (HISTORY_LIMIT,),
    )
    return render_template("chat/global.html", messages=list(reversed(rows)))


@bp.route("/messages")
@security.login_required
def inbox():
    """1:1 대화 상대 목록 (가장 최근 메시지 기준)."""
    me = security.current_user()["id"]
    rows = database.query_all(
        "SELECT u.id AS partner_id, u.username AS partner_name, "
        "       MAX(m.created_at) AS last_at, "
        "       (SELECT content FROM messages m2 "
        "         WHERE ((m2.sender_id = ? AND m2.recipient_id = u.id) "
        "             OR (m2.sender_id = u.id AND m2.recipient_id = ?)) "
        "         ORDER BY m2.created_at DESC LIMIT 1) AS last_content "
        "FROM messages m "
        "JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END "
        "WHERE (m.sender_id = ? OR m.recipient_id = ?) AND m.recipient_id IS NOT NULL "
        "GROUP BY u.id, u.username ORDER BY last_at DESC LIMIT 50",
        (me, me, me, me, me),
    )
    return render_template("chat/inbox.html", threads=rows)


@bp.route("/messages/<user_id>", methods=["GET", "POST"])
@security.login_required
def direct_chat(user_id: str):
    me = security.current_user()
    if not ID_RE.match(user_id):
        abort(404)
    if user_id == me["id"]:
        flash("자기 자신과는 대화할 수 없습니다.", "error")
        return redirect(url_for("chat.inbox"))
    partner = database.query_one(
        "SELECT id, username, status FROM users WHERE id = ?", (user_id,)
    )
    if partner is None or partner["status"] == "banned":
        abort(404)

    form = MessageForm()
    if form.validate_on_submit():   # WebSocket 이 막힌 환경을 위한 폼 전송 경로
        if partner["status"] != "active":
            flash("상대방이 활동할 수 없는 상태입니다.", "error")
        elif not message_limiter.allow(me["id"]):
            flash("메시지를 너무 빠르게 보내고 있습니다. 잠시 후 다시 시도해 주세요.", "error")
        else:
            _store_message(me["id"], partner["id"], form.content.data)
            security.audit("chat.dm_sent", target_type="user", target_id=partner["id"])
            return redirect(url_for("chat.direct_chat", user_id=user_id))

    rows = database.query_all(
        "SELECT m.id, m.content, m.created_at, m.sender_id, u.username "
        "FROM messages m JOIN users u ON u.id = m.sender_id "
        "WHERE (m.sender_id = ? AND m.recipient_id = ?) "
        "   OR (m.sender_id = ? AND m.recipient_id = ?) "
        "ORDER BY m.created_at DESC LIMIT ?",
        (me["id"], partner["id"], partner["id"], me["id"], HISTORY_LIMIT),
    )
    return render_template(
        "chat/direct.html", partner=partner, messages=list(reversed(rows)), form=form
    )


# --------------------------------------------------------------------------
# Socket.IO 이벤트
# --------------------------------------------------------------------------
def register_socket_handlers(socketio) -> None:
    def _authenticated_user():
        """소켓 이벤트마다 세션을 재확인한다 (연결 후 상태 변화 반영)."""
        user_id = session.get("user_id")
        if not user_id:
            return None
        return database.query_one(
            "SELECT id, username, status FROM users WHERE id = ? AND status = 'active'",
            (user_id,),
        )

    @socketio.on("connect")
    def handle_connect(auth=None):
        user = _authenticated_user()
        if user is None:
            # 인증되지 않은 연결은 즉시 끊는다.
            return False
        join_room(GLOBAL_ROOM)
        join_room(user["id"])          # 1:1 수신용 개인 룸
        emit("system", {"message": "채팅 서버에 연결되었습니다."})
        return None

    @socketio.on("disconnect")
    def handle_disconnect(_reason=None):
        return None

    @socketio.on("global_message")
    def handle_global_message(payload):
        user = _authenticated_user()
        if user is None:
            disconnect()
            return
        if not isinstance(payload, dict):
            emit("error_message", {"message": "잘못된 요청입니다."})
            return
        try:
            content = _clean_message(payload.get("content"))
        except ValueError as exc:
            emit("error_message", {"message": str(exc)})
            return
        if not message_limiter.allow(user["id"]):
            emit("error_message", {"message": "메시지를 너무 빠르게 보내고 있습니다."})
            return

        meta = _store_message(user["id"], None, content)
        emit(
            "global_message",
            {
                "id": meta["id"],
                "sender_id": user["id"],
                "username": user["username"],
                "content": content,          # 클라이언트는 textContent 로만 출력한다
                "created_at": meta["created_at"],
            },
            to=GLOBAL_ROOM,
        )

    @socketio.on("private_message")
    def handle_private_message(payload):
        user = _authenticated_user()
        if user is None:
            disconnect()
            return
        if not isinstance(payload, dict):
            emit("error_message", {"message": "잘못된 요청입니다."})
            return
        target_id = payload.get("to")
        if not isinstance(target_id, str) or not ID_RE.match(target_id):
            emit("error_message", {"message": "대상이 올바르지 않습니다."})
            return
        if target_id == user["id"]:
            emit("error_message", {"message": "자기 자신에게는 보낼 수 없습니다."})
            return
        partner = _active_user(target_id)
        if partner is None:
            emit("error_message", {"message": "상대방을 찾을 수 없습니다."})
            return
        try:
            content = _clean_message(payload.get("content"))
        except ValueError as exc:
            emit("error_message", {"message": str(exc)})
            return
        if not message_limiter.allow(user["id"]):
            emit("error_message", {"message": "메시지를 너무 빠르게 보내고 있습니다."})
            return

        meta = _store_message(user["id"], partner["id"], content)
        message = {
            "id": meta["id"],
            "sender_id": user["id"],
            "username": user["username"],
            "to": partner["id"],
            "content": content,
            "created_at": meta["created_at"],
        }
        emit("private_message", message, to=partner["id"])   # 수신자 개인 룸
        emit("private_message", message)                      # 발신자 본인 화면
