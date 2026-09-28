"""Create the CMS SQLite database.

Usage:
    python db/init_db.py            # create cms.db with schema + starter data
    python db/init_db.py --reset    # delete and recreate
    python db/init_db.py --no-seed  # schema only
"""
import argparse
import hashlib
import os
import sqlite3
from pathlib import Path

DB_DIR = Path(__file__).resolve().parent
DB_PATH = DB_DIR / "cms.db"


def hash_password(password: str) -> str:
    """PBKDF2-SHA256 hash stored as 'pbkdf2_sha256$iterations$salt$hash'."""
    iterations = 600_000
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="delete the existing database first")
    parser.add_argument("--no-seed", action="store_true", help="skip starter data")
    parser.add_argument("--admin-password", default="changeme", help="password for the seeded admin user")
    args = parser.parse_args()

    if args.reset and DB_PATH.exists():
        DB_PATH.unlink()
    elif DB_PATH.exists():
        raise SystemExit(f"{DB_PATH} already exists. Use --reset to recreate it.")

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript((DB_DIR / "schema.sql").read_text(encoding="utf-8"))

        if not args.no_seed:
            conn.executescript((DB_DIR / "seed.sql").read_text(encoding="utf-8"))
            conn.execute("UPDATE users SET password_hash = ? WHERE id = 1", (hash_password(args.admin_password),))

        conn.commit()
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
    finally:
        conn.close()

    print(f"Created {DB_PATH}")
    print(f"Tables ({len(tables)}): {', '.join(tables)}")
    if not args.no_seed:
        print(f"Admin login: admin@example.com / {args.admin_password}")


if __name__ == "__main__":
    main()
