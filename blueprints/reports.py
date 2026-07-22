"""신고 기능 + 신고 누적에 따른 자동 차단/휴면 처리."""
import sqlite3

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

import db as database
import security
from extensions import limiter
from forms import ReportForm

bp = Blueprint("reports", __name__)


def _target_label(target_type: str, target_id: str) -> str | None:
    """신고 대상이 실제로 존재하는지 확인하고 표시용 이름을 돌려준다."""
    if target_type == "product":
        row = database.query_one("SELECT title FROM products WHERE id = ?", (target_id,))
        return row["title"] if row else None
    row = database.query_one("SELECT username FROM users WHERE id = ?", (target_id,))
    return row["username"] if row else None


def _apply_threshold(target_type: str, target_id: str) -> str | None:
    """신고 누적 임계치를 넘으면 자동 조치. 조치했으면 설명 문자열을 반환."""
    count = database.query_value(
        "SELECT COUNT(*) FROM reports WHERE target_type = ? AND target_id = ? AND status != 'dismissed'",
        (target_type, target_id),
        default=0,
    )
    if target_type == "product":
        database.execute(
            "UPDATE products SET report_count = ? WHERE id = ?", (count, target_id)
        )
        threshold = current_app.config["REPORT_BLOCK_THRESHOLD_PRODUCT"]
        if count >= threshold:
            changed = database.execute(
                "UPDATE products SET status = 'blocked' WHERE id = ? AND status != 'blocked'",
                (target_id,),
            ).rowcount
            if changed:
                security.audit(
                    "product.auto_blocked", target_type="product", target_id=target_id,
                    detail=f"신고 {count}건 누적(임계치 {threshold})",
                )
                return f"신고 {count}건 누적으로 해당 상품이 자동 차단되었습니다."
    else:
        database.execute("UPDATE users SET report_count = ? WHERE id = ?", (count, target_id))
        threshold = current_app.config["REPORT_DORMANT_THRESHOLD_USER"]
        if count >= threshold:
            changed = database.execute(
                "UPDATE users SET status = 'dormant' WHERE id = ? AND status = 'active' AND role != 'admin'",
                (target_id,),
            ).rowcount
            if changed:
                security.audit(
                    "user.auto_dormant", target_type="user", target_id=target_id,
                    detail=f"신고 {count}건 누적(임계치 {threshold})",
                )
                return f"신고 {count}건 누적으로 해당 사용자가 휴면 전환되었습니다."
    return None


@bp.route("/report", methods=["GET", "POST"])
@security.login_required
@limiter.limit("20 per hour", exempt_when=lambda: request.method != "POST")
def create():
    me = security.current_user()
    form = ReportForm()
    if request.method == "GET":
        form.target_type.data = request.args.get("target_type", "product")
        form.target_id.data = request.args.get("target_id", "")

    if form.validate_on_submit():
        target_type = form.target_type.data
        target_id = form.target_id.data

        label = _target_label(target_type, target_id)
        if label is None:
            flash("신고 대상을 찾을 수 없습니다.", "error")
            return render_template("reports/form.html", form=form, target_label=None), 404

        # 자기 자신 / 자기 상품 신고 금지
        if target_type == "user" and target_id == me["id"]:
            flash("자기 자신은 신고할 수 없습니다.", "error")
            return render_template("reports/form.html", form=form, target_label=label), 400
        if target_type == "product":
            owner = database.query_value("SELECT seller_id FROM products WHERE id = ?", (target_id,))
            if owner == me["id"]:
                flash("본인이 등록한 상품은 신고할 수 없습니다.", "error")
                return render_template("reports/form.html", form=form, target_label=label), 400

        # 신고 남용 방지 : 하루 신고 건수 상한
        daily_limit = current_app.config["REPORT_DAILY_LIMIT_PER_USER"]
        today_count = database.query_value(
            "SELECT COUNT(*) FROM reports WHERE reporter_id = ? AND created_at >= datetime('now', '-1 day')",
            (me["id"],),
            default=0,
        )
        if today_count >= daily_limit:
            security.audit("report.rate_limited", detail=f"24시간 내 {today_count}건")
            flash(f"24시간 내 신고 한도({daily_limit}건)를 초과했습니다.", "error")
            return render_template("reports/form.html", form=form, target_label=label), 429

        try:
            database.execute(
                "INSERT INTO reports (id, reporter_id, target_type, target_id, reason, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                (
                    database.new_id(),
                    me["id"],
                    target_type,
                    target_id,
                    form.reason.data,
                    database.now_iso(),
                ),
            )
        except sqlite3.IntegrityError:
            # UNIQUE(reporter_id, target_type, target_id) — 동일 대상 반복 신고 차단
            flash("이미 신고한 대상입니다. 중복 신고는 접수되지 않습니다.", "error")
            return render_template("reports/form.html", form=form, target_label=label), 409

        security.audit(
            "report.created", target_type=target_type, target_id=target_id,
            detail=f"사유 길이 {len(form.reason.data)}자",
        )
        action_message = _apply_threshold(target_type, target_id)
        flash("신고가 접수되었습니다. 관리자가 검토합니다.", "success")
        if action_message:
            flash(action_message, "info")
        return redirect(url_for("products.index"))

    target_label = None
    if form.target_id.data:
        target_label = _target_label(form.target_type.data or "product", form.target_id.data)
    return render_template("reports/form.html", form=form, target_label=target_label)


@bp.route("/me/reports")
@security.login_required
def my_reports():
    me = security.current_user()
    rows = database.query_all(
        "SELECT r.id, r.target_type, r.target_id, r.reason, r.status, r.created_at, "
        "       COALESCE(p.title, u.username) AS target_label "
        "FROM reports r "
        "LEFT JOIN products p ON r.target_type = 'product' AND p.id = r.target_id "
        "LEFT JOIN users u    ON r.target_type = 'user'    AND u.id = r.target_id "
        "WHERE r.reporter_id = ? ORDER BY r.created_at DESC LIMIT 100",
        (me["id"],),
    )
    return render_template("reports/my_reports.html", reports=rows)
