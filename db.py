"""SQLite 접근 계층.

★ 보안 원칙 ★
이 모듈이 제공하는 함수만 사용해서 DB에 접근한다. 모든 함수는
`sql` 과 `params` 를 분리해서 받고 sqlite3 의 파라미터 바인딩(`?`)을 사용한다.
f-string / % / + 로 SQL 문자열을 만드는 코드는 프로젝트 어디에도 없다.
(SQL Injection 원천 차단)
"""
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g

SCHEMA_FILE = Path(__file__).resolve().parent / "schema.sql"


def now_iso() -> str:
    """UTC ISO8601 문자열(초 단위). 화면에 표시되는 시각 컬럼용."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def now_iso_micro() -> str:
    """UTC ISO8601 문자열(마이크로초 단위).

    password_changed_at 처럼 "세션 발급 시각과 크기를 비교"하는 값은 초 단위로
    자르면 같은 초에 만들어진 세션이 무효화를 빠져나간다. 그래서 별도 함수를 둔다.
    """
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def new_id() -> str:
    """추측 불가능한 식별자. 순차 정수 ID를 쓰지 않는 이유는 열거(enumeration) 방지."""
    return uuid.uuid4().hex


def get_db() -> sqlite3.Connection:
    """요청 단위 커넥션. 요청이 끝나면 teardown 에서 닫힌다."""
    if "db" not in g:
        conn = sqlite3.connect(
            current_app.config["DATABASE_PATH"],
            timeout=10,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")   # FK 제약 활성화(기본 OFF라 반드시 켜야 함)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        g.db = conn
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


# --- 질의 헬퍼 : params 는 항상 튜플/딕셔너리로 바인딩된다 --------------------

def query_all(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    return get_db().execute(sql, params).fetchall()


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    return get_db().execute(sql, params).fetchone()


def query_value(sql: str, params: tuple = (), default=None):
    row = query_one(sql, params)
    return row[0] if row is not None else default


def execute(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    """INSERT/UPDATE/DELETE 실행 후 커밋."""
    conn = get_db()
    cur = conn.execute(sql, params)
    conn.commit()
    return cur


@contextmanager
def transaction():
    """여러 문장을 원자적으로 실행 (예: 송금 = 출금 + 입금 + 기록).

    중간에 예외가 나면 전부 롤백되므로 "돈이 사라지는" 상태가 생기지 않는다.
    BEGIN IMMEDIATE 로 쓰기 락을 즉시 잡아 동시 요청 간 경쟁 조건(race condition)을 막는다.
    """
    conn = get_db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()


def like_escape(term: str) -> str:
    """LIKE 패턴 메타문자 이스케이프.

    사용자가 '%' 를 넣어 전체 행을 긁어가거나 인덱스를 무력화하지 못하게 한다.
    실제 질의에서는 반드시 ESCAPE '\\' 와 함께 사용한다.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def init_db() -> None:
    """스키마 생성 (이미 있으면 그대로 둔다)."""
    db_path = Path(current_app.config["DATABASE_PATH"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
    conn.commit()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
