import sqlite3
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                hashed_password TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                country_code TEXT,
                cloud_provider TEXT,
                is_tor INTEGER,
                is_vpn INTEGER,
                is_proxy INTEGER,
                is_bot INTEGER,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)
