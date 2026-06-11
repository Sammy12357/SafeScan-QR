"""
One-off database migration script.

Adds the wallet-reward columns (``wallet_address`` and ``tokens_sent``) to the
``scans`` table on an existing database. Safe to re-run: if the columns already
exist SQLite raises OperationalError, which we catch and ignore. Run directly
with ``python scrop.py``.
"""
import os
import sqlite3


def _db_path():
    """Locate the SQLite file the same way the app does (env-driven)."""
    return os.getenv("SQLITE_DB_PATH") or os.path.join(os.getenv("DATA_DIR", "/var/data"), "qr_cache.db")

def migrate():
    """Add the wallet reward columns to ``scans`` if they aren't there yet."""
    conn = sqlite3.connect(_db_path())
    cursor = conn.cursor()
    # Add wallet column and a 'sent' flag
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN wallet_address TEXT;")
        cursor.execute("ALTER TABLE scans ADD COLUMN tokens_sent INTEGER DEFAULT 0;")
        conn.commit()
        print("Database updated successfully!")
    except sqlite3.OperationalError:
        # Raised when the columns already exist - re-running the migration is a no-op.
        print("Columns already exist.")
    conn.close()

if __name__ == "__main__":
    migrate()
