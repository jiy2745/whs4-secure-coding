"""서버측 입력 검증 (WTForms).

★ 원칙 ★
- 클라이언트(HTML maxlength, JS)는 편의일 뿐이며 신뢰하지 않는다.
  모든 값은 이 파일의 폼을 통과해야만 서비스 로직으로 들어간다.
- 화이트리스트 방식(허용할 형식을 규정)으로 검증한다.
- 폼 클래스는 FlaskForm 을 상속하므로 CSRF 토큰 검증이 자동으로 적용된다.
  (GET 검색 폼만 예외적으로 csrf=False — 상태를 바꾸지 않으므로)
"""
import re
import unicodedata

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileSize
from wtforms import (
    BooleanField,
    HiddenField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    TextAreaField,
)
from wtforms.validators import (
    DataRequired,
    EqualTo,
    InputRequired,
    Length,
    NumberRange,
    Optional,
    Regexp,
    ValidationError,
)

from config import Config

USERNAME_RE = r"^[A-Za-z0-9_]{3,20}$"
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# 너무 흔해서 크리덴셜 스터핑에 즉시 뚫리는 비밀번호
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789", "1234567890",
    "qwertyuiop", "qwerty123", "letmein123", "administrator", "iloveyou1",
    "1q2w3e4r5t", "abcd1234!", "welcome123", "secret123",
}


def strip_filter(value):
    """앞뒤 공백 제거 + 유니코드 정규화(NFC).

    정규화를 하지 않으면 시각적으로 같은 아이디를 다른 코드포인트로 만들어
    사칭(homograph)하는 것이 가능해진다.
    """
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value).strip()
    return value


class NoControlChars:
    """제어문자(NUL 등) 차단 — 로그 위변조/파서 혼동 방지."""

    def __init__(self, message="사용할 수 없는 문자가 포함되어 있습니다."):
        self.message = message

    def __call__(self, form, field):
        if field.data and CONTROL_CHARS.search(field.data):
            raise ValidationError(self.message)


def validate_password_strength(form, field):
    """비밀번호 복잡도 검증."""
    pw = field.data or ""
    if len(pw) < Config.PASSWORD_MIN_LENGTH:
        raise ValidationError(f"비밀번호는 최소 {Config.PASSWORD_MIN_LENGTH}자 이상이어야 합니다.")
    classes = sum(
        bool(pattern.search(pw))
        for pattern in (
            re.compile(r"[a-z]"),
            re.compile(r"[A-Z]"),
            re.compile(r"[0-9]"),
            re.compile(r"[^A-Za-z0-9]"),
        )
    )
    if classes < 3:
        raise ValidationError("영문 대문자/소문자/숫자/특수문자 중 3종류 이상을 포함해야 합니다.")
    if pw.lower() in COMMON_PASSWORDS:
        raise ValidationError("너무 흔한 비밀번호입니다. 다른 값을 사용하세요.")
    username = getattr(getattr(form, "username", None), "data", None)
    if username and username.lower() in pw.lower():
        raise ValidationError("비밀번호에 아이디를 포함할 수 없습니다.")
    if " " in pw.strip() and pw.strip() != pw:
        raise ValidationError("비밀번호 앞뒤에 공백을 넣을 수 없습니다.")


# --------------------------------------------------------------------------
# 계정
# --------------------------------------------------------------------------
class RegisterForm(FlaskForm):
    username = StringField(
        "아이디",
        filters=[strip_filter],
        validators=[
            DataRequired(message="아이디를 입력하세요."),
            Length(min=Config.USERNAME_MIN_LENGTH, max=Config.USERNAME_MAX_LENGTH),
            Regexp(USERNAME_RE, message="아이디는 영문/숫자/밑줄 3~20자만 가능합니다."),
        ],
    )
    password = PasswordField(
        "비밀번호",
        validators=[
            InputRequired(message="비밀번호를 입력하세요."),
            Length(max=Config.PASSWORD_MAX_LENGTH),
            validate_password_strength,
        ],
    )
    password_confirm = PasswordField(
        "비밀번호 확인",
        validators=[
            InputRequired(),
            EqualTo("password", message="비밀번호가 일치하지 않습니다."),
        ],
    )


class LoginForm(FlaskForm):
    username = StringField(
        "아이디",
        filters=[strip_filter],
        validators=[DataRequired(), Length(max=Config.USERNAME_MAX_LENGTH)],
    )
    password = PasswordField(
        "비밀번호", validators=[InputRequired(), Length(max=Config.PASSWORD_MAX_LENGTH)]
    )


class ReauthForm(FlaskForm):
    password = PasswordField(
        "비밀번호", validators=[InputRequired(), Length(max=Config.PASSWORD_MAX_LENGTH)]
    )


class ProfileForm(FlaskForm):
    bio = TextAreaField(
        "소개글",
        filters=[strip_filter],
        validators=[Optional(), Length(max=Config.BIO_MAX), NoControlChars()],
    )


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField(
        "현재 비밀번호", validators=[InputRequired(), Length(max=Config.PASSWORD_MAX_LENGTH)]
    )
    password = PasswordField(
        "새 비밀번호",
        validators=[
            InputRequired(),
            Length(max=Config.PASSWORD_MAX_LENGTH),
            validate_password_strength,
        ],
    )
    password_confirm = PasswordField(
        "새 비밀번호 확인",
        validators=[InputRequired(), EqualTo("password", message="비밀번호가 일치하지 않습니다.")],
    )


# --------------------------------------------------------------------------
# 상품
# --------------------------------------------------------------------------
class ProductForm(FlaskForm):
    title = StringField(
        "상품명",
        filters=[strip_filter],
        validators=[
            DataRequired(message="상품명을 입력하세요."),
            Length(min=1, max=Config.PRODUCT_TITLE_MAX),
            NoControlChars(),
        ],
    )
    description = TextAreaField(
        "상품 설명",
        filters=[strip_filter],
        validators=[
            DataRequired(message="상품 설명을 입력하세요."),
            Length(min=1, max=Config.PRODUCT_DESC_MAX),
            NoControlChars(),
        ],
    )
    price = IntegerField(
        "가격(원)",
        validators=[
            InputRequired(message="가격을 숫자로 입력하세요."),
            NumberRange(
                min=Config.PRICE_MIN,
                max=Config.PRICE_MAX,
                message=f"가격은 {Config.PRICE_MIN}~{Config.PRICE_MAX:,}원 사이여야 합니다.",
            ),
        ],
    )
    image = FileField(
        "상품 사진",
        validators=[
            Optional(),
            FileAllowed(
                sorted(Config.ALLOWED_IMAGE_EXTENSIONS),
                message="png/jpg/jpeg/gif/webp 이미지만 업로드할 수 있습니다.",
            ),
            FileSize(max_size=Config.MAX_CONTENT_LENGTH, message="파일이 너무 큽니다."),
        ],
    )
    remove_image = BooleanField("사진 삭제")


class SearchForm(FlaskForm):
    """GET 검색 폼 — 상태를 변경하지 않으므로 CSRF 토큰 미사용."""

    class Meta:
        csrf = False

    q = StringField(
        "검색어",
        filters=[strip_filter],
        validators=[Optional(), Length(max=Config.SEARCH_QUERY_MAX), NoControlChars()],
    )
    min_price = IntegerField("최소 가격", validators=[Optional(), NumberRange(min=0, max=Config.PRICE_MAX)])
    max_price = IntegerField("최대 가격", validators=[Optional(), NumberRange(min=0, max=Config.PRICE_MAX)])
    sort = SelectField(
        "정렬",
        choices=[("recent", "최신순"), ("price_asc", "낮은 가격순"), ("price_desc", "높은 가격순")],
        default="recent",
        validators=[Optional()],
    )


class ProductStatusForm(FlaskForm):
    """판매중 ↔ 판매완료 전환 (CSRF 토큰 전용 폼)."""

    status = SelectField(
        "상태", choices=[("active", "판매중"), ("sold", "판매완료")], validators=[DataRequired()]
    )


class DeleteForm(FlaskForm):
    """삭제 등 파괴적 동작 — CSRF 토큰만 담는 빈 폼."""


# --------------------------------------------------------------------------
# 신고 / 송금 / 채팅
# --------------------------------------------------------------------------
class ReportForm(FlaskForm):
    target_type = SelectField(
        "신고 유형",
        choices=[("product", "상품"), ("user", "사용자")],
        validators=[DataRequired()],
    )
    target_id = HiddenField(
        "대상 ID", filters=[strip_filter],
        validators=[DataRequired(), Length(min=32, max=32), Regexp(r"^[0-9a-f]{32}$")],
    )
    reason = TextAreaField(
        "신고 사유",
        filters=[strip_filter],
        validators=[
            DataRequired(message="신고 사유를 입력하세요."),
            Length(
                min=Config.REPORT_REASON_MIN,
                max=Config.REPORT_REASON_MAX,
                message=f"신고 사유는 {Config.REPORT_REASON_MIN}~{Config.REPORT_REASON_MAX}자로 작성하세요.",
            ),
            NoControlChars(),
        ],
    )


class TransferForm(FlaskForm):
    recipient = StringField(
        "받는 사람 아이디",
        filters=[strip_filter],
        validators=[DataRequired(), Regexp(USERNAME_RE, message="올바른 아이디 형식이 아닙니다.")],
    )
    amount = IntegerField(
        "금액(원)",
        validators=[
            InputRequired(message="금액을 숫자로 입력하세요."),
            NumberRange(
                min=Config.TRANSFER_MIN,
                max=Config.TRANSFER_MAX,
                message=f"{Config.TRANSFER_MIN:,}원 이상 {Config.TRANSFER_MAX:,}원 이하만 송금할 수 있습니다.",
            ),
        ],
    )
    memo = StringField(
        "메모",
        filters=[strip_filter],
        validators=[Optional(), Length(max=Config.TRANSFER_MEMO_MAX), NoControlChars()],
    )
    product_id = HiddenField(
        validators=[Optional(), Regexp(r"^[0-9a-f]{32}$", message="잘못된 상품입니다.")]
    )
    password = PasswordField(
        "비밀번호 확인",
        validators=[InputRequired(message="송금하려면 비밀번호를 입력하세요."),
                    Length(max=Config.PASSWORD_MAX_LENGTH)],
    )


class MessageForm(FlaskForm):
    """1:1 채팅 전송 폼 (WebSocket 실패 시 폼 전송 대비)."""

    content = TextAreaField(
        "메시지",
        filters=[strip_filter],
        validators=[
            DataRequired(),
            Length(min=1, max=Config.MESSAGE_MAX),
            NoControlChars(),
        ],
    )


# --------------------------------------------------------------------------
# 관리자
# --------------------------------------------------------------------------
class AdminUserForm(FlaskForm):
    action = SelectField(
        choices=[
            ("activate", "활성화"),
            ("dormant", "휴면 전환"),
            ("ban", "영구 정지"),
            ("promote", "관리자 지정"),
            ("demote", "관리자 해제"),
        ],
        validators=[DataRequired()],
    )
    user_id = HiddenField(validators=[DataRequired(), Regexp(r"^[0-9a-f]{32}$")])


class AdminProductForm(FlaskForm):
    action = SelectField(
        choices=[("block", "차단"), ("unblock", "차단 해제"), ("delete", "삭제")],
        validators=[DataRequired()],
    )
    product_id = HiddenField(validators=[DataRequired(), Regexp(r"^[0-9a-f]{32}$")])


class AdminReportForm(FlaskForm):
    action = SelectField(
        choices=[("resolve", "처리 완료"), ("dismiss", "기각")], validators=[DataRequired()]
    )
    report_id = HiddenField(validators=[DataRequired(), Regexp(r"^[0-9a-f]{32}$")])


class AdminBalanceForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired(), Regexp(r"^[0-9a-f]{32}$")])
    amount = IntegerField(
        "조정 금액",
        validators=[
            InputRequired(),
            NumberRange(min=-Config.TRANSFER_MAX, max=Config.TRANSFER_MAX),
        ],
    )
