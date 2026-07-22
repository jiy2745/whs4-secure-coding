"""Tiny Second-hand Shopping Platform — 애플리케이션 팩토리.

실행:
    python app.py                 # 개발 서버 (기본 0.0.0.0:5000)
    flask --app app init-db       # DB 초기화
    flask --app app create-admin  # 관리자 계정 생성
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

import click
from dotenv import load_dotenv
from flask import Flask, flash, g, render_template, request, session
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

load_dotenv()

import db as database  # noqa: E402
import security  # noqa: E402
from config import INSTANCE_DIR, Config  # noqa: E402
from extensions import csrf, limiter, socketio  # noqa: E402


def _configure_logging(app: Flask) -> None:
    """로그는 파일에 남기고, 사용자에게는 절대 노출하지 않는다."""
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        INSTANCE_DIR / "app.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
    )
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def _register_error_handlers(app: Flask) -> None:
    """오류 응답 표준화.

    스택 트레이스·SQL 문·파일 경로 같은 내부 정보는 화면에 절대 내보내지 않고
    서버 로그에만 남긴다. (정보 노출 취약점 방지)
    """

    def render_error(code: int, message: str):
        return render_template("error.html", code=code, message=message), code

    @app.errorhandler(CSRFError)
    def handle_csrf(error):
        app.logger.warning("CSRF 검증 실패: %s %s (%s)", request.method, request.path, error.description)
        return render_error(400, "보안 토큰이 유효하지 않거나 만료되었습니다. 페이지를 새로고침한 뒤 다시 시도해 주세요.")

    @app.errorhandler(400)
    def handle_400(_error):
        return render_error(400, "잘못된 요청입니다.")

    @app.errorhandler(403)
    def handle_403(_error):
        return render_error(403, "이 작업을 수행할 권한이 없습니다.")

    @app.errorhandler(404)
    def handle_404(_error):
        return render_error(404, "요청하신 페이지를 찾을 수 없습니다.")

    @app.errorhandler(413)
    def handle_413(_error):
        limit_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return render_error(413, f"업로드 용량 제한({limit_mb}MB)을 초과했습니다.")

    @app.errorhandler(429)
    def handle_429(_error):
        return render_error(429, "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.")

    @app.errorhandler(500)
    def handle_500(_error):
        return render_error(500, "일시적인 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.")

    @app.errorhandler(Exception)
    def handle_unexpected(error):
        if isinstance(error, HTTPException):
            return error
        # 예외 상세는 로그로만
        app.logger.exception("처리되지 않은 예외: %s %s", request.method, request.path)
        return render_error(500, "일시적인 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.")


def _register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db_command():
        """DB 스키마를 생성한다."""
        database.init_db()
        click.echo(f"DB 초기화 완료: {app.config['DATABASE_PATH']}")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.password_option()
    def create_admin_command(username, password):
        """관리자 계정을 생성한다 (비밀번호는 화면에 표시되지 않음)."""
        from forms import USERNAME_RE
        import re

        database.init_db()
        if not re.match(USERNAME_RE, username):
            click.echo("아이디는 영문/숫자/밑줄 3~20자여야 합니다.", err=True)
            sys.exit(1)
        if len(password) < app.config["PASSWORD_MIN_LENGTH"]:
            click.echo(f"비밀번호는 최소 {app.config['PASSWORD_MIN_LENGTH']}자 이상이어야 합니다.", err=True)
            sys.exit(1)
        exists = database.query_one("SELECT id FROM users WHERE username = ?", (username,))
        if exists:
            database.execute("UPDATE users SET role = 'admin' WHERE id = ?", (exists["id"],))
            click.echo(f"기존 사용자 '{username}' 을(를) 관리자로 승격했습니다.")
            return
        now = database.now_iso()
        database.execute(
            "INSERT INTO users (id, username, password_hash, bio, role, status, balance, "
            "created_at, password_changed_at) VALUES (?, ?, ?, '', 'admin', 'active', ?, ?, ?)",
            (
                database.new_id(),
                username,
                security.hash_password(password),
                app.config["SIGNUP_BONUS"],
                now,
                now,
            ),
        )
        click.echo(f"관리자 계정 '{username}' 생성 완료.")

    @app.cli.command("seed-demo")
    def seed_demo_command():
        """데모용 사용자/상품 데이터를 넣는다 (개발 편의용)."""
        from seed import seed_demo_data

        database.init_db()
        seed_demo_data()
        click.echo("데모 데이터 생성 완료 (README 참고).")


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_object)

    # Jinja2 는 .html 템플릿에 대해 기본적으로 자동 이스케이프(autoescape)가 켜져 있다.
    # 명시적으로 한 번 더 확인 — 이 값이 꺼지면 전 페이지가 XSS 에 노출된다.
    app.jinja_env.autoescape = True
    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

    _configure_logging(app)

    if app.config.get("TRUST_PROXY_HEADERS"):
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    database.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    socketio.init_app(app, manage_session=False)
    security.install_security_headers(app)

    with app.app_context():
        database.init_db()

    # --- 요청 훅 -----------------------------------------------------------
    @app.before_request
    def _session_policy():
        security.enforce_session_policy()
        if g.pop("session_expired", False):
            flash("장시간 활동이 없어 자동 로그아웃되었습니다. 다시 로그인해 주세요.", "info")
        blocked = g.pop("account_blocked", None)
        if blocked == "dormant":
            flash("신고 누적으로 휴면 상태가 된 계정입니다. 관리자에게 문의하세요.", "error")
        elif blocked == "banned":
            flash("이용이 정지된 계정입니다.", "error")

    @app.context_processor
    def _inject_globals():
        return {
            "current_user": security.current_user(),
            "is_admin": security.is_admin(),
            "config": app.config,
        }

    # --- 블루프린트 --------------------------------------------------------
    from blueprints.admin import bp as admin_bp
    from blueprints.auth import bp as auth_bp
    from blueprints.chat import bp as chat_bp
    from blueprints.chat import register_socket_handlers
    from blueprints.products import bp as products_bp
    from blueprints.reports import bp as reports_bp
    from blueprints.transfers import bp as transfers_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(transfers_bp)
    app.register_blueprint(admin_bp)
    register_socket_handlers(socketio)

    _register_error_handlers(app)
    _register_cli(app)
    return app


app = create_app()


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0").strip().lower() in ("1", "true", "yes")
    if debug:
        print("[경고] 디버그 모드는 스택 트레이스와 대화형 콘솔을 노출합니다. 배포 환경에서 사용하지 마세요.")
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
