"""회원가입 / 로그인 / 로그아웃 / 마이페이지 / 프로필 조회."""
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

import db as database
import security
from extensions import limiter
from forms import (
    DeleteForm,
    LoginForm,
    PasswordChangeForm,
    ProfileForm,
    ReauthForm,
    RegisterForm,
)

bp = Blueprint("auth", __name__)

# 로그인/가입 화면은 GET 은 제한하지 않고 POST(실제 시도)만 제한한다.
_post_only = lambda: request.method != "POST"  # noqa: E731


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", exempt_when=_post_only)
def register():
    if security.current_user():
        return redirect(url_for("products.index"))
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        # 아이디 중복 확인 (username 컬럼은 UNIQUE COLLATE NOCASE)
        exists = database.query_one("SELECT id FROM users WHERE username = ?", (username,))
        if exists:
            # 존재 여부를 알려주지 않을 수도 있으나, 회원가입 UX 상 중복 안내는 필요하다.
            form.username.errors.append("이미 사용 중인 아이디입니다.")
        else:
            now = database.now_iso()
            user_id = database.new_id()
            database.execute(
                "INSERT INTO users (id, username, password_hash, bio, role, status, balance, "
                "created_at, password_changed_at) VALUES (?, ?, ?, '', 'user', 'active', ?, ?, ?)",
                (
                    user_id,
                    username,
                    security.hash_password(form.password.data),  # 평문 저장 금지
                    current_app.config["SIGNUP_BONUS"],
                    now,
                    now,
                ),
            )
            security.audit("auth.register", actor_id=user_id, target_type="user", target_id=user_id)
            flash("회원가입이 완료되었습니다. 로그인해 주세요.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute; 60 per hour", exempt_when=_post_only)
def login():
    if security.current_user():
        return redirect(url_for("products.index"))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        user = database.query_one(
            "SELECT id, username, password_hash, role, status, failed_logins, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        )
        locked, remaining = security.login_lock_state(user)
        if locked:
            security.audit("auth.login_blocked_locked", actor_id=user["id"], detail=username)
            flash(f"로그인 시도가 너무 많습니다. {remaining // 60 + 1}분 후 다시 시도해 주세요.", "error")
            return render_template("auth/login.html", form=form), 429

        # 계정이 없어도 동일한 비용으로 검증한다 (사용자 열거 방지)
        password_ok = security.verify_password(
            user["password_hash"] if user else None, form.password.data
        )
        if not password_ok:
            security.register_login_failure(user)
            security.audit(
                "auth.login_failed",
                actor_id=user["id"] if user else None,
                detail=f"username={username[:20]}",
            )
            # 아이디/비밀번호 중 무엇이 틀렸는지 알려주지 않는다.
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
            return render_template("auth/login.html", form=form), 401

        if user["status"] != "active":
            security.audit("auth.login_blocked_status", actor_id=user["id"], detail=user["status"])
            message = (
                "신고 누적으로 휴면 처리된 계정입니다. 관리자에게 문의하세요."
                if user["status"] == "dormant"
                else "이용이 정지된 계정입니다."
            )
            flash(message, "error")
            return render_template("auth/login.html", form=form), 403

        # 오래된 파라미터로 만들어진 해시는 로그인 시점에 조용히 재해싱
        if security.needs_rehash(user["password_hash"]):
            database.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (security.hash_password(form.password.data), user["id"]),
            )

        security.reset_login_failures(user["id"])
        security.start_user_session(user["id"])   # 세션 고정 방지: 기존 세션 폐기 후 재발급
        security.audit("auth.login", actor_id=user["id"])
        flash(f"{user['username']}님, 환영합니다.", "success")
        return redirect(security.safe_redirect_target(request.args.get("next")))
    return render_template("auth/login.html", form=form)


@bp.route("/logout", methods=["POST"])
def logout():
    """로그아웃은 반드시 POST + CSRF 토큰. (GET 로그아웃은 CSRF 로 강제 로그아웃 가능)"""
    user = security.current_user()
    if user:
        security.audit("auth.logout", actor_id=user["id"])
    security.end_user_session()
    flash("로그아웃되었습니다.", "info")
    return redirect(url_for("products.index"))


@bp.route("/reauth", methods=["GET", "POST"])
@security.login_required
@limiter.limit("10 per minute", exempt_when=_post_only)
def reauth():
    """민감 작업 전 비밀번호 재확인."""
    form = ReauthForm()
    next_url = security.safe_redirect_target(request.args.get("next") or request.form.get("next"))
    if form.validate_on_submit():
        user = security.current_user()
        row = database.query_one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
        if security.verify_password(row["password_hash"] if row else None, form.password.data):
            security.mark_reauth()
            security.audit("auth.reauth_success")
            return redirect(next_url)
        security.audit("auth.reauth_failed")
        flash("비밀번호가 올바르지 않습니다.", "error")
        return render_template("auth/reauth.html", form=form, next_url=next_url), 401
    return render_template("auth/reauth.html", form=form, next_url=next_url)


@bp.route("/me", methods=["GET"])
@security.login_required
def my_page():
    user = security.current_user()
    profile_form = ProfileForm(bio=user["bio"])
    password_form = PasswordChangeForm()
    products = database.query_all(
        "SELECT id, title, price, status, image_path, report_count, created_at "
        "FROM products WHERE seller_id = ? ORDER BY created_at DESC",
        (user["id"],),
    )
    transfers = database.query_all(
        "SELECT t.id, t.amount, t.memo, t.created_at, "
        "       s.username AS sender_name, r.username AS receiver_name, "
        "       t.sender_id, t.receiver_id "
        "FROM transfers t "
        "JOIN users s ON s.id = t.sender_id "
        "JOIN users r ON r.id = t.receiver_id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.created_at DESC LIMIT 20",
        (user["id"], user["id"]),
    )
    return render_template(
        "auth/my_page.html",
        profile_form=profile_form,
        password_form=password_form,
        products=products,
        transfers=transfers,
        delete_form=DeleteForm(),
    )


@bp.route("/me/profile", methods=["POST"])
@security.login_required
def update_profile():
    user = security.current_user()
    form = ProfileForm()
    if form.validate_on_submit():
        database.execute(
            "UPDATE users SET bio = ? WHERE id = ?", (form.bio.data or "", user["id"])
        )
        security.audit("user.profile_updated", target_type="user", target_id=user["id"])
        flash("소개글이 저장되었습니다.", "success")
    else:
        for errors in form.errors.values():
            for message in errors:
                flash(message, "error")
    return redirect(url_for("auth.my_page"))


@bp.route("/me/password", methods=["POST"])
@security.login_required
@limiter.limit("5 per 10 minutes")
def change_password():
    # 이 라우트는 폼에서 현재 비밀번호를 직접 입력받아 검증하므로
    # (reauth_required 대신) 그 자체가 재인증 절차다.
    user = security.current_user()
    form = PasswordChangeForm()
    if form.validate_on_submit():
        row = database.query_one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
        if not security.verify_password(row["password_hash"] if row else None,
                                        form.current_password.data):
            security.audit("user.password_change_failed", target_type="user", target_id=user["id"])
            flash("현재 비밀번호가 올바르지 않습니다.", "error")
            return redirect(url_for("auth.my_page"))
        if form.current_password.data == form.password.data:
            flash("이전과 다른 비밀번호를 사용하세요.", "error")
            return redirect(url_for("auth.my_page"))
        database.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
            (security.hash_password(form.password.data), database.now_iso_micro(), user["id"]),
        )
        security.audit("user.password_changed", target_type="user", target_id=user["id"])
        # 비밀번호 변경 → 기존 세션 무효화 후 재로그인 요구
        security.end_user_session()
        flash("비밀번호가 변경되었습니다. 새 비밀번호로 다시 로그인해 주세요.", "success")
        return redirect(url_for("auth.login"))
    for errors in form.errors.values():
        for message in errors:
            flash(message, "error")
    return redirect(url_for("auth.my_page"))


@bp.route("/users/<user_id>", methods=["GET"])
@security.login_required
def profile(user_id: str):
    """다른 사용자 프로필 조회. 비밀번호 해시 등 민감 컬럼은 SELECT 하지 않는다."""
    if not (len(user_id) == 32 and all(c in "0123456789abcdef" for c in user_id)):
        abort(404)
    user = database.query_one(
        "SELECT id, username, bio, role, status, created_at FROM users WHERE id = ?", (user_id,)
    )
    if user is None:
        abort(404)
    viewer = security.current_user()
    products = database.query_all(
        "SELECT id, title, price, status, image_path FROM products "
        "WHERE seller_id = ? AND status != 'blocked' ORDER BY created_at DESC LIMIT 50",
        (user_id,),
    )
    return render_template(
        "auth/profile.html",
        profile_user=user,
        products=products,
        is_self=(viewer["id"] == user_id),
    )


@bp.route("/users", methods=["GET"])
@security.login_required
def user_list():
    """사용자 조회 기능 (아이디 부분 검색)."""
    raw_q = (request.args.get("q") or "").strip()[: current_app.config["SEARCH_QUERY_MAX"]]
    if raw_q:
        pattern = f"%{database.like_escape(raw_q)}%"
        users = database.query_all(
            "SELECT id, username, bio, status, created_at FROM users "
            "WHERE username LIKE ? ESCAPE '\\' ORDER BY username LIMIT 50",
            (pattern,),
        )
    else:
        users = database.query_all(
            "SELECT id, username, bio, status, created_at FROM users ORDER BY created_at DESC LIMIT 50"
        )
    return render_template("auth/user_list.html", users=users, q=raw_q)
