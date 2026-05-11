import os
import sqlite3


def _db_path():
    return os.path.join(os.getenv("DATA_DIR", "/app/data"), "qr_cache.db")

def migrate():
    conn = sqlite3.connect(_db_path())
    cursor = conn.cursor()
    # Add wallet column and a 'sent' flag
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN wallet_address TEXT;")
        cursor.execute("ALTER TABLE scans ADD COLUMN tokens_sent INTEGER DEFAULT 0;")
        conn.commit()
        print("Database updated successfully!")
    except sqlite3.OperationalError:
        print("Columns already exist.")
    conn.close()

if __name__ == "__main__":
    migrate()
