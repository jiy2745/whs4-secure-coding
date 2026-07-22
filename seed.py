"""데모 데이터 생성 (개발/시연 편의용).

주의: 여기서 만드는 계정은 데모용이므로 실제 배포 시에는 사용하지 말 것.
비밀번호는 여기서도 평문 저장하지 않고 Argon2 로 해싱한다.
"""
import db as database
import security

DEMO_PASSWORD = "Demo!Pass123"

DEMO_USERS = [
    ("alice", "가구와 소형가전을 주로 판매합니다."),
    ("bob", "책과 전자기기 위주로 거래해요."),
    ("carol", "취미용품 판매합니다."),
]

DEMO_PRODUCTS = [
    ("alice", "원목 책상", "사용감 있지만 튼튼한 1200x600 원목 책상입니다. 직거래 선호합니다.", 45000),
    ("alice", "무선 청소기", "2년 사용한 무선 청소기입니다. 배터리 교체 완료.", 89000),
    ("bob", "파이썬 코딩 도장", "거의 새 책입니다. 필기 없음.", 12000),
    ("bob", "기계식 키보드", "적축 텐키리스, 키캡 포함해서 드립니다.", 55000),
    ("carol", "캠핑 의자 2개", "접이식 캠핑 의자 2개 세트입니다.", 30000),
]


def seed_demo_data() -> None:
    now = database.now_iso()
    ids = {}
    for username, bio in DEMO_USERS:
        existing = database.query_one("SELECT id FROM users WHERE username = ?", (username,))
        if existing:
            ids[username] = existing["id"]
            continue
        user_id = database.new_id()
        ids[username] = user_id
        database.execute(
            "INSERT INTO users (id, username, password_hash, bio, role, status, balance, "
            "created_at, password_changed_at) VALUES (?, ?, ?, ?, 'user', 'active', 200000, ?, ?)",
            (user_id, username, security.hash_password(DEMO_PASSWORD), bio, now, now),
        )

    for seller, title, description, price in DEMO_PRODUCTS:
        exists = database.query_one(
            "SELECT id FROM products WHERE title = ? AND seller_id = ?", (title, ids[seller])
        )
        if exists:
            continue
        database.execute(
            "INSERT INTO products (id, title, description, price, seller_id, image_path, status, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, NULL, 'active', ?, ?)",
            (database.new_id(), title, description, price, ids[seller], now, now),
        )
