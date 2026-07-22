"""관리자 페이지 — 플랫폼의 모든 요소 관리.

모든 라우트는 @admin_required(로그인 + role='admin' 서버측 검증)와
@reauth_required(최근 비밀번호 재확인)를 함께 적용한다.
관리자 행위는 예외 없이 감사 로그에 남긴다.
"""
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

import db as database
import security
from blueprints.products import _delete_image
from forms import AdminBalanceForm, AdminProductForm, AdminReportForm, AdminUserForm

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@security.admin_required
@security.reauth_required
def dashboard():
    stats = {
        "users": database.query_value("SELECT COUNT(*) FROM users", default=0),
        "active_users": database.query_value(
            "SELECT COUNT(*) FROM users WHERE status = 'active'", default=0
        ),
        "dormant_users": database.query_value(
            "SELECT COUNT(*) FROM users WHERE status != 'active'", default=0
        ),
        "products": database.query_value("SELECT COUNT(*) FROM products", default=0),
        "blocked_products": database.query_value(
            "SELECT COUNT(*) FROM products WHERE status = 'blocked'", default=0
        ),
        "pending_reports": database.query_value(
            "SELECT COUNT(*) FROM reports WHERE status = 'pending'", default=0
        ),
        "transfers": database.query_value("SELECT COUNT(*) FROM transfers", default=0),
        "transfer_volume": database.query_value(
            "SELECT COALESCE(SUM(amount), 0) FROM transfers", default=0
        ),
    }
    recent_logs = database.query_all(
        "SELECT a.action, a.detail, a.ip, a.created_at, u.username "
        "FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id "
        "ORDER BY a.created_at DESC LIMIT 20"
    )
    return render_template("admin/dashboard.html", stats=stats, logs=recent_logs)


@bp.route("/users")
@security.admin_required
@security.reauth_required
def users():
    q = (request.args.get("q") or "").strip()[:50]
    if q:
        pattern = f"%{database.like_escape(q)}%"
        rows = database.query_all(
            "SELECT id, username, role, status, balance, report_count, created_at, last_login_at "
            "FROM users WHERE username LIKE ? ESCAPE '\\' ORDER BY created_at DESC LIMIT 100",
            (pattern,),
        )
    else:
        rows = database.query_all(
            "SELECT id, username, role, status, balance, report_count, created_at, last_login_at "
            "FROM users ORDER BY created_at DESC LIMIT 100"
        )
    return render_template(
        "admin/users.html", users=rows, q=q, form=AdminUserForm(), balance_form=AdminBalanceForm()
    )


@bp.route("/users/action", methods=["POST"])
@security.admin_required
@security.reauth_required
def user_action():
    form = AdminUserForm()
    if not form.validate_on_submit():
        abort(400)
    me = security.current_user()
    target_id = form.user_id.data
    target = database.query_one("SELECT id, username, role, status FROM users WHERE id = ?", (target_id,))
    if target is None:
        abort(404)

    # 관리자가 자기 자신을 정지/강등해서 시스템을 잠그는 사고 방지
    if target_id == me["id"] and form.action.data in ("dormant", "ban", "demote"):
        flash("자기 자신에게는 적용할 수 없습니다.", "error")
        return redirect(url_for("admin.users"))

    actions = {
        "activate": ("UPDATE users SET status = 'active', failed_logins = 0, locked_until = NULL WHERE id = ?", "활성화"),
        "dormant": ("UPDATE users SET status = 'dormant' WHERE id = ?", "휴면 전환"),
        "ban": ("UPDATE users SET status = 'banned' WHERE id = ?", "이용 정지"),
        "promote": ("UPDATE users SET role = 'admin' WHERE id = ?", "관리자 지정"),
        "demote": ("UPDATE users SET role = 'user' WHERE id = ?", "관리자 해제"),
    }
    sql, label = actions[form.action.data]

    if form.action.data == "demote":
        admin_count = database.query_value("SELECT COUNT(*) FROM users WHERE role = 'admin'", default=0)
        if admin_count <= 1:
            flash("마지막 관리자는 해제할 수 없습니다.", "error")
            return redirect(url_for("admin.users"))

    database.execute(sql, (target_id,))
    security.audit(
        f"admin.user_{form.action.data}", target_type="user", target_id=target_id,
        detail=f"{target['username']} → {label}",
    )
    flash(f"{target['username']} 계정을 {label} 처리했습니다.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/balance", methods=["POST"])
@security.admin_required
@security.reauth_required
def adjust_balance():
    """잔액 조정(충전/회수). 감사 로그 필수."""
    form = AdminBalanceForm()
    if not form.validate_on_submit():
        abort(400)
    target = database.query_one(
        "SELECT id, username, balance FROM users WHERE id = ?", (form.user_id.data,)
    )
    if target is None:
        abort(404)
    new_balance = target["balance"] + form.amount.data
    if new_balance < 0:
        flash("잔액은 음수가 될 수 없습니다.", "error")
        return redirect(url_for("admin.users"))
    database.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, target["id"]))
    security.audit(
        "admin.balance_adjusted", target_type="user", target_id=target["id"],
        detail=f"{target['balance']} → {new_balance}",
    )
    flash(f"{target['username']} 잔액을 {new_balance:,}원으로 조정했습니다.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/products")
@security.admin_required
@security.reauth_required
def products():
    rows = database.query_all(
        "SELECT p.id, p.title, p.price, p.status, p.report_count, p.created_at, u.username AS seller_name "
        "FROM products p JOIN users u ON u.id = p.seller_id ORDER BY p.report_count DESC, p.created_at DESC LIMIT 100"
    )
    return render_template("admin/products.html", products=rows, form=AdminProductForm())


@bp.route("/products/action", methods=["POST"])
@security.admin_required
@security.reauth_required
def product_action():
    form = AdminProductForm()
    if not form.validate_on_submit():
        abort(400)
    product = database.query_one(
        "SELECT id, title, image_path FROM products WHERE id = ?", (form.product_id.data,)
    )
    if product is None:
        abort(404)
    action = form.action.data
    if action == "delete":
        _delete_image(product["image_path"])
        database.execute("DELETE FROM products WHERE id = ?", (product["id"],))
        label = "삭제"
    else:
        status = "blocked" if action == "block" else "active"
        database.execute(
            "UPDATE products SET status = ?, updated_at = ? WHERE id = ?",
            (status, database.now_iso(), product["id"]),
        )
        label = "차단" if action == "block" else "차단 해제"
    security.audit(
        f"admin.product_{action}", target_type="product", target_id=product["id"],
        detail=f"{product['title'][:50]} → {label}",
    )
    flash(f"상품을 {label} 처리했습니다.", "success")
    return redirect(url_for("admin.products"))


@bp.route("/reports")
@security.admin_required
@security.reauth_required
def reports():
    status_filter = request.args.get("status", "pending")
    if status_filter not in ("pending", "resolved", "dismissed", "all"):
        status_filter = "pending"
    if status_filter == "all":
        rows = database.query_all(
            "SELECT r.*, rep.username AS reporter_name, COALESCE(p.title, u.username) AS target_label "
            "FROM reports r JOIN users rep ON rep.id = r.reporter_id "
            "LEFT JOIN products p ON r.target_type = 'product' AND p.id = r.target_id "
            "LEFT JOIN users u ON r.target_type = 'user' AND u.id = r.target_id "
            "ORDER BY r.created_at DESC LIMIT 100"
        )
    else:
        rows = database.query_all(
            "SELECT r.*, rep.username AS reporter_name, COALESCE(p.title, u.username) AS target_label "
            "FROM reports r JOIN users rep ON rep.id = r.reporter_id "
            "LEFT JOIN products p ON r.target_type = 'product' AND p.id = r.target_id "
            "LEFT JOIN users u ON r.target_type = 'user' AND u.id = r.target_id "
            "WHERE r.status = ? ORDER BY r.created_at DESC LIMIT 100",
            (status_filter,),
        )
    return render_template(
        "admin/reports.html", reports=rows, status_filter=status_filter, form=AdminReportForm()
    )


@bp.route("/reports/action", methods=["POST"])
@security.admin_required
@security.reauth_required
def report_action():
    form = AdminReportForm()
    if not form.validate_on_submit():
        abort(400)
    report = database.query_one("SELECT * FROM reports WHERE id = ?", (form.report_id.data,))
    if report is None:
        abort(404)
    status = "resolved" if form.action.data == "resolve" else "dismissed"
    database.execute("UPDATE reports SET status = ? WHERE id = ?", (status, report["id"]))
    security.audit(
        f"admin.report_{form.action.data}", target_type="report", target_id=report["id"],
        detail=f"{report['target_type']}:{report['target_id']} → {status}",
    )
    flash("신고를 처리했습니다.", "success")
    return redirect(url_for("admin.reports"))


@bp.route("/logs")
@security.admin_required
@security.reauth_required
def logs():
    action_filter = (request.args.get("action") or "").strip()[:64]
    if action_filter:
        rows = database.query_all(
            "SELECT a.*, u.username FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id "
            "WHERE a.action LIKE ? ESCAPE '\\' ORDER BY a.created_at DESC LIMIT 200",
            (f"%{database.like_escape(action_filter)}%",),
        )
    else:
        rows = database.query_all(
            "SELECT a.*, u.username FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id "
            "ORDER BY a.created_at DESC LIMIT 200"
        )
    return render_template("admin/logs.html", logs=rows, action_filter=action_filter)
