"""상품 등록 / 조회 / 수정 / 삭제 / 검색 / 이미지 서빙."""
import re
import uuid
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from PIL import Image, UnidentifiedImageError

import db as database
import security
from extensions import limiter
from forms import DeleteForm, ProductForm, ProductStatusForm, ReportForm, SearchForm

bp = Blueprint("products", __name__)

ID_RE = re.compile(r"^[0-9a-f]{32}$")
STORED_FILENAME_RE = re.compile(r"^[0-9a-f]{32}\.(png|jpg|gif|webp)$")

# Pillow 가 판별한 실제 포맷 → 저장 확장자/MIME (사용자가 준 확장자는 신뢰하지 않는다)
FORMAT_TO_EXT = {"PNG": "png", "JPEG": "jpg", "GIF": "gif", "WEBP": "webp"}
EXT_TO_MIME = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
}

# 정렬 옵션은 화이트리스트로 고정된 SQL 조각에만 매핑한다.
# (사용자 입력을 ORDER BY 에 그대로 넣으면 SQL Injection)
# 컬럼은 테이블 별칭까지 포함해 고정한다.
# (products/users 양쪽에 created_at 이 있어 별칭이 없으면 "ambiguous column" 오류)
SORT_SQL = {
    "recent": "p.created_at DESC",
    "price_asc": "p.price ASC, p.created_at DESC",
    "price_desc": "p.price DESC, p.created_at DESC",
}
PER_PAGE = 12


def _valid_id(value: str) -> bool:
    return bool(value and ID_RE.match(value))


def _get_product_or_404(product_id: str):
    if not _valid_id(product_id):
        abort(404)
    row = database.query_one(
        "SELECT p.*, u.username AS seller_name, u.status AS seller_status "
        "FROM products p JOIN users u ON u.id = p.seller_id WHERE p.id = ?",
        (product_id,),
    )
    if row is None:
        abort(404)
    return row


def _require_owner_or_admin(product) -> None:
    """소유자 확인 (IDOR 방지).

    URL 의 상품 ID 만 바꿔서 남의 상품을 수정/삭제하려는 시도를 여기서 차단한다.
    """
    user = security.current_user()
    if user is None:
        abort(403)
    if product["seller_id"] != user["id"] and user["role"] != "admin":
        security.audit(
            "product.access_denied", target_type="product", target_id=product["id"],
            detail="소유자가 아닌 사용자의 수정/삭제 시도",
        )
        abort(403)


# --------------------------------------------------------------------------
# 이미지 업로드
# --------------------------------------------------------------------------
def _save_image(file_storage) -> str | None:
    """업로드 이미지 저장.

    1) 확장자 화이트리스트 (폼 단계에서 1차)
    2) Pillow 로 실제 이미지인지 검증 → 확장자만 이미지인 웹셸/스크립트 차단
    3) 재인코딩하여 저장 → EXIF·주석에 숨긴 페이로드 제거
    4) 파일명은 서버가 생성한 UUID (사용자 파일명 미사용 → 경로 조작/덮어쓰기 불가)
    5) 웹 루트(static) 밖에 저장하고 전용 라우트로만 서빙 → 업로드 디렉터리 코드 실행 불가
    """
    if not file_storage or not file_storage.filename:
        return None

    Image.MAX_IMAGE_PIXELS = current_app.config["MAX_IMAGE_PIXELS"]  # 디컴프레션 폭탄 방지
    try:
        probe = Image.open(file_storage.stream)
        probe.verify()                       # 헤더/구조 검증 (verify 후에는 재사용 불가)
        detected = (probe.format or "").upper()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        raise ValueError("이미지 파일이 아니거나 손상된 파일입니다.")

    if detected not in current_app.config["ALLOWED_IMAGE_FORMATS"]:
        raise ValueError("허용되지 않는 이미지 형식입니다. (png/jpg/gif/webp)")

    ext = FORMAT_TO_EXT[detected]
    stored_name = f"{uuid.uuid4().hex}.{ext}"
    target = Path(current_app.config["UPLOAD_DIR"]) / stored_name

    file_storage.stream.seek(0)
    try:
        image = Image.open(file_storage.stream)
        image.load()
        if detected == "JPEG" and image.mode not in ("RGB", "L"):
            image = image.convert("RGB")
        # 원본 메타데이터를 버리고 새로 인코딩한다.
        image.save(target, format=detected)
    except (OSError, ValueError, Image.DecompressionBombError):
        target.unlink(missing_ok=True)
        raise ValueError("이미지를 처리할 수 없습니다.")
    return stored_name


def _delete_image(stored_name: str | None) -> None:
    if not stored_name or not STORED_FILENAME_RE.match(stored_name):
        return
    (Path(current_app.config["UPLOAD_DIR"]) / stored_name).unlink(missing_ok=True)


@bp.route("/uploads/<path:filename>")
def uploaded_file(filename: str):
    """업로드 이미지 서빙.

    파일명이 서버가 만든 형식(32자리 hex + 허용 확장자)과 정확히 일치할 때만 응답한다.
    → '../../etc/passwd' 같은 경로 조작(Path Traversal) 자체가 성립하지 않는다.
    """
    if not STORED_FILENAME_RE.match(filename):
        abort(404)
    ext = filename.rsplit(".", 1)[1]
    response = send_from_directory(
        current_app.config["UPLOAD_DIR"], filename, mimetype=EXT_TO_MIME[ext]
    )
    # 브라우저가 내용을 보고 타입을 추측(HTML 로 해석)하지 못하게 한다.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Disposition"] = "inline"
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


# --------------------------------------------------------------------------
# 목록 / 검색
# --------------------------------------------------------------------------
@bp.route("/")
def index():
    form = SearchForm(request.args, meta={"csrf": False})
    form.validate()   # 검증 실패한 값은 아래에서 무시된다

    conditions = ["p.status != 'blocked'", "u.status = 'active'"]
    params: list = []

    keyword = form.q.data if not form.q.errors else None
    if keyword:
        pattern = f"%{database.like_escape(keyword)}%"
        conditions.append("(p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\')")
        params.extend([pattern, pattern])

    min_price = form.min_price.data if not form.min_price.errors else None
    max_price = form.max_price.data if not form.max_price.errors else None
    if min_price is not None:
        conditions.append("p.price >= ?")
        params.append(min_price)
    if max_price is not None:
        conditions.append("p.price <= ?")
        params.append(max_price)

    order_sql = SORT_SQL.get(form.sort.data or "recent", SORT_SQL["recent"])

    try:
        page = max(1, min(int(request.args.get("page", 1)), 1000))
    except (TypeError, ValueError):
        page = 1
    offset = (page - 1) * PER_PAGE

    where_sql = " AND ".join(conditions)
    total = database.query_value(
        f"SELECT COUNT(*) FROM products p JOIN users u ON u.id = p.seller_id WHERE {where_sql}",
        tuple(params),
        default=0,
    )
    rows = database.query_all(
        # NOTE: where_sql/order_sql 은 코드가 만든 고정 문자열이고,
        #       사용자 값은 전부 ? 로 바인딩된다.
        f"SELECT p.id, p.title, p.price, p.status, p.image_path, p.created_at, "
        f"       u.username AS seller_name, u.id AS seller_id "
        f"FROM products p JOIN users u ON u.id = p.seller_id "
        f"WHERE {where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?",
        tuple(params) + (PER_PAGE, offset),
    )
    return render_template(
        "products/index.html",
        products=rows,
        form=form,
        page=page,
        total=total,
        per_page=PER_PAGE,
        has_next=(offset + PER_PAGE) < total,
    )


# --------------------------------------------------------------------------
# 등록 / 상세 / 수정 / 삭제
# --------------------------------------------------------------------------
@bp.route("/products/new", methods=["GET", "POST"])
@security.login_required
@limiter.limit("20 per hour", exempt_when=lambda: request.method != "POST")
def create():
    form = ProductForm()
    if form.validate_on_submit():
        user = security.current_user()
        try:
            stored = _save_image(form.image.data)
        except ValueError as exc:
            form.image.errors.append(str(exc))
            return render_template("products/form.html", form=form, product=None), 400
        now = database.now_iso()
        product_id = database.new_id()
        database.execute(
            "INSERT INTO products (id, title, description, price, seller_id, image_path, "
            "status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)",
            (
                product_id,
                form.title.data,
                form.description.data,
                form.price.data,
                user["id"],
                stored,
                now,
                now,
            ),
        )
        security.audit("product.created", target_type="product", target_id=product_id)
        flash("상품이 등록되었습니다.", "success")
        return redirect(url_for("products.detail", product_id=product_id))
    return render_template("products/form.html", form=form, product=None)


@bp.route("/products/<product_id>")
def detail(product_id: str):
    product = _get_product_or_404(product_id)
    user = security.current_user()
    is_owner = bool(user and user["id"] == product["seller_id"])
    is_admin = bool(user and user["role"] == "admin")

    # 차단된 상품/휴면 판매자의 상품은 소유자와 관리자만 볼 수 있다.
    if product["status"] == "blocked" and not (is_owner or is_admin):
        abort(404)
    if product["seller_status"] != "active" and not (is_owner or is_admin):
        abort(404)

    return render_template(
        "products/detail.html",
        product=product,
        is_owner=is_owner,
        delete_form=DeleteForm(),
        status_form=ProductStatusForm(status=product["status"]),
        report_form=ReportForm(target_type="product", target_id=product["id"]),
    )


@bp.route("/products/<product_id>/edit", methods=["GET", "POST"])
@security.login_required
def edit(product_id: str):
    product = _get_product_or_404(product_id)
    _require_owner_or_admin(product)          # ← 소유자 검증 (IDOR 방지)

    form = ProductForm(data={
        "title": product["title"],
        "description": product["description"],
        "price": product["price"],
    })
    if form.validate_on_submit():
        stored = product["image_path"]
        if form.image.data:
            try:
                new_name = _save_image(form.image.data)
            except ValueError as exc:
                form.image.errors.append(str(exc))
                return render_template("products/form.html", form=form, product=product), 400
            if new_name:
                _delete_image(stored)
                stored = new_name
        elif form.remove_image.data:
            _delete_image(stored)
            stored = None

        database.execute(
            "UPDATE products SET title = ?, description = ?, price = ?, image_path = ?, "
            "updated_at = ? WHERE id = ? AND (seller_id = ? OR ?)",
            (
                form.title.data,
                form.description.data,
                form.price.data,
                stored,
                database.now_iso(),
                product_id,
                security.current_user()["id"],
                1 if security.is_admin() else 0,
            ),
        )
        security.audit("product.updated", target_type="product", target_id=product_id)
        flash("상품 정보가 수정되었습니다.", "success")
        return redirect(url_for("products.detail", product_id=product_id))
    return render_template("products/form.html", form=form, product=product)


@bp.route("/products/<product_id>/delete", methods=["POST"])
@security.login_required
def delete(product_id: str):
    product = _get_product_or_404(product_id)
    _require_owner_or_admin(product)
    form = DeleteForm()
    if not form.validate_on_submit():
        abort(400)
    _delete_image(product["image_path"])
    database.execute("DELETE FROM products WHERE id = ?", (product_id,))
    security.audit("product.deleted", target_type="product", target_id=product_id)
    flash("상품이 삭제되었습니다.", "success")
    return redirect(url_for("auth.my_page"))


@bp.route("/products/<product_id>/status", methods=["POST"])
@security.login_required
def change_status(product_id: str):
    """판매중 ↔ 판매완료. 차단(blocked) 상태는 관리자만 바꿀 수 있다."""
    product = _get_product_or_404(product_id)
    _require_owner_or_admin(product)
    form = ProductStatusForm()
    if not form.validate_on_submit():
        abort(400)
    if product["status"] == "blocked" and not security.is_admin():
        abort(403)
    database.execute(
        "UPDATE products SET status = ?, updated_at = ? WHERE id = ?",
        (form.status.data, database.now_iso(), product_id),
    )
    security.audit(
        "product.status_changed", target_type="product", target_id=product_id,
        detail=f"{product['status']} → {form.status.data}",
    )
    flash("상품 상태가 변경되었습니다.", "success")
    return redirect(url_for("products.detail", product_id=product_id))
