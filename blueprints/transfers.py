"""사용자 간 송금 (지갑).

돈이 오가는 기능이므로 다음을 모두 만족해야 한다.
- 로그인 + CSRF + 비밀번호 재확인(민감 작업 재인증)
- 금액 범위/형식 서버측 검증, 자기 자신 송금 금지
- 출금·입금·기록을 하나의 트랜잭션으로 처리 (BEGIN IMMEDIATE → 경쟁 조건 차단)
- 잔액 부족 시 전체 롤백, DB CHECK(balance >= 0) 로 2차 방어
- 모든 송금은 감사 로그에 기록
"""
import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, url_for

import db as database
import security
from extensions import limiter
from forms import TransferForm

bp = Blueprint("transfers", __name__)


@bp.route("/wallet")
@security.login_required
def wallet():
    me = security.current_user()
    history = database.query_all(
        "SELECT t.id, t.amount, t.memo, t.created_at, t.sender_id, t.receiver_id, "
        "       s.username AS sender_name, r.username AS receiver_name, p.title AS product_title "
        "FROM transfers t "
        "JOIN users s ON s.id = t.sender_id "
        "JOIN users r ON r.id = t.receiver_id "
        "LEFT JOIN products p ON p.id = t.product_id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.created_at DESC LIMIT 50",
        (me["id"], me["id"]),
    )
    return render_template("transfers/wallet.html", history=history)


@bp.route("/transfer", methods=["GET", "POST"])
@security.login_required
@limiter.limit("10 per hour", exempt_when=lambda: request.method != "POST")
def transfer():
    me = security.current_user()
    form = TransferForm()

    if request.method == "GET":
        # 상품 상세에서 "판매자에게 송금" 으로 넘어온 경우 초기값 채우기
        form.recipient.data = request.args.get("to", "")
        form.product_id.data = request.args.get("product_id", "")

    if form.validate_on_submit():
        # 1) 비밀번호 재확인 (민감 작업 재인증)
        row = database.query_one("SELECT password_hash FROM users WHERE id = ?", (me["id"],))
        if not security.verify_password(row["password_hash"] if row else None, form.password.data):
            security.audit("transfer.password_failed")
            flash("비밀번호가 올바르지 않습니다.", "error")
            return render_template("transfers/transfer.html", form=form), 401
        security.mark_reauth()

        # 2) 수취인 확인
        recipient = database.query_one(
            "SELECT id, username, status FROM users WHERE username = ?", (form.recipient.data,)
        )
        if recipient is None or recipient["status"] != "active":
            flash("받는 사람을 찾을 수 없거나 송금할 수 없는 계정입니다.", "error")
            return render_template("transfers/transfer.html", form=form), 404
        if recipient["id"] == me["id"]:
            flash("자기 자신에게는 송금할 수 없습니다.", "error")
            return render_template("transfers/transfer.html", form=form), 400

        amount = form.amount.data
        product_id = form.product_id.data or None
        if product_id:
            exists = database.query_value("SELECT id FROM products WHERE id = ?", (product_id,))
            if not exists:
                product_id = None

        # 3) 원자적 이체
        try:
            with database.transaction() as conn:
                sender = conn.execute(
                    "SELECT balance FROM users WHERE id = ?", (me["id"],)
                ).fetchone()
                if sender is None or sender["balance"] < amount:
                    raise ValueError("잔액이 부족합니다.")
                conn.execute(
                    "UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?",
                    (amount, me["id"], amount),
                )
                conn.execute(
                    "UPDATE users SET balance = balance + ? WHERE id = ?",
                    (amount, recipient["id"]),
                )
                conn.execute(
                    "INSERT INTO transfers (id, sender_id, receiver_id, amount, memo, product_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        database.new_id(),
                        me["id"],
                        recipient["id"],
                        amount,
                        form.memo.data or "",
                        product_id,
                        database.now_iso(),
                    ),
                )
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("transfers/transfer.html", form=form), 400
        except sqlite3.IntegrityError:
            # CHECK(balance >= 0) 등 DB 제약 위반 → 내부 상세는 감추고 일반 메시지만
            security.audit("transfer.failed", detail="DB 제약 위반")
            flash("송금을 처리할 수 없습니다. 입력값을 확인해 주세요.", "error")
            return render_template("transfers/transfer.html", form=form), 400

        security.audit(
            "transfer.completed", target_type="user", target_id=recipient["id"],
            detail=f"{amount}원 송금",
        )
        flash(f"{recipient['username']}님에게 {amount:,}원을 송금했습니다.", "success")
        return redirect(url_for("transfers.wallet"))

    return render_template("transfers/transfer.html", form=form)
