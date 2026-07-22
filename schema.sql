-- Tiny Second-hand Shopping Platform : 데이터베이스 스키마
-- 모든 제약(CHECK/UNIQUE/FK)은 "애플리케이션 검증이 뚫려도 DB에서 한 번 더 막는다"는
-- 다층 방어(defense in depth) 목적이다.

PRAGMA foreign_keys = ON;

-- 사용자 -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                  TEXT PRIMARY KEY,                      -- UUID4 (순차 정수 금지 → 열거/IDOR 난이도 상승)
    username            TEXT NOT NULL UNIQUE COLLATE NOCASE,   -- 대소문자 무시 중복 방지
    password_hash       TEXT NOT NULL,                         -- Argon2id 해시 (평문 저장 금지)
    bio                 TEXT NOT NULL DEFAULT '',
    role                TEXT NOT NULL DEFAULT 'user'   CHECK (role   IN ('user', 'admin')),
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'dormant', 'banned')),
    balance             INTEGER NOT NULL DEFAULT 0     CHECK (balance >= 0),  -- 음수 잔액 원천 차단
    failed_logins       INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,
    report_count        INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    password_changed_at TEXT NOT NULL,
    last_login_at       TEXT
);

-- 상품 ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS products (
    id           TEXT PRIMARY KEY,
    title        TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 100),
    description  TEXT NOT NULL CHECK (length(description) <= 2000),
    price        INTEGER NOT NULL CHECK (price >= 0 AND price <= 100000000),
    seller_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    image_path   TEXT,                                          -- instance/uploads 내부 파일명만 저장
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked', 'sold')),
    report_count INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_products_seller  ON products(seller_id);
CREATE INDEX IF NOT EXISTS idx_products_status  ON products(status, created_at DESC);

-- 신고 ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id          TEXT PRIMARY KEY,
    reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK (target_type IN ('user', 'product')),
    target_id   TEXT NOT NULL,
    reason      TEXT NOT NULL CHECK (length(reason) BETWEEN 5 AND 500),
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved', 'dismissed')),
    created_at  TEXT NOT NULL,
    -- 같은 사람이 같은 대상을 반복 신고하는 것을 DB 차원에서 차단 (신고 남용 방지)
    UNIQUE (reporter_id, target_type, target_id)
);
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, created_at DESC);

-- 채팅 메시지 (recipient_id IS NULL → 전체 채팅) -----------------------------
CREATE TABLE IF NOT EXISTS messages (
    id           TEXT PRIMARY KEY,
    sender_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    content      TEXT NOT NULL CHECK (length(content) BETWEEN 1 AND 500),
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_global ON messages(created_at DESC) WHERE recipient_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_dm     ON messages(sender_id, recipient_id, created_at DESC);

-- 송금 ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS transfers (
    id          TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount      INTEGER NOT NULL CHECK (amount > 0),
    memo        TEXT NOT NULL DEFAULT '',
    product_id  TEXT REFERENCES products(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL,
    CHECK (sender_id <> receiver_id)          -- 자기 자신에게 송금 금지
);
CREATE INDEX IF NOT EXISTS idx_transfers_sender   ON transfers(sender_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transfers_receiver ON transfers(receiver_id, created_at DESC);

-- 감사 로그 (보안 관련 행위 기록) --------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id          TEXT PRIMARY KEY,
    actor_id    TEXT,                 -- 비로그인 행위(로그인 실패 등)는 NULL 가능
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    detail      TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor   ON audit_logs(actor_id, created_at DESC);
