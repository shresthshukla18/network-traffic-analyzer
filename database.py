import sqlite3
from pathlib import Path

DATABASE_PATH = Path("data/traffic.db")


def create_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.cursor()
        # Enable WAL mode for smooth concurrent reads and writes
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                source_port TEXT,
                destination_port TEXT,
                packet_length INTEGER,
                session_id TEXT,
                tcp_flags TEXT
            )
        """)

        columns = {
            row[1] for row in cursor.execute("PRAGMA table_info(packets)").fetchall()
        }

        if "session_id" not in columns:
            cursor.execute("ALTER TABLE packets ADD COLUMN session_id TEXT")

        if "tcp_flags" not in columns:
            cursor.execute("ALTER TABLE packets ADD COLUMN tcp_flags TEXT")

    print(f"[+] Database ready with WAL mode: {DATABASE_PATH}")


if __name__ == "__main__":
    create_database()
