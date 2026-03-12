import os
import json
import pymysql
from datetime import datetime

DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "mysql"),
    "user":     os.getenv("DB_USER", "ojs"),
    "password": os.getenv("DB_PASSWORD", "ojspassword"),
    "database": os.getenv("DB_NAME", "ojs"),
    "charset":  "utf8mb4",
}


def get_connection():
    return pymysql.connect(**DB_CONFIG)


def init_db():
    """Buat tabel scan_results jika belum ada."""
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                tool        VARCHAR(50),
                risk_score  INT,
                risk_level  VARCHAR(50),
                findings    JSON,
                scanned_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
    conn.commit()
    conn.close()
    print("[DB] Table scan_results ready")


def save_scan_result(tool: str, findings: list, score: dict):
    """Simpan hasil scan ke database."""
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_results (tool, risk_score, risk_level, findings)
            VALUES (%s, %s, %s, %s)
            """,
            (tool, score["score"], score["level"], json.dumps(findings))
        )
    conn.commit()
    conn.close()
    print(f"[DB] Saved {tool} scan result — score: {score['score']}")


def get_all_results() -> list:
    """Ambil semua hasil scan dari database."""
    conn = get_connection()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("SELECT * FROM scan_results ORDER BY scanned_at DESC")
        rows = cur.fetchall()
    conn.close()

    # Parse JSON field
    for row in rows:
        if isinstance(row["findings"], str):
            row["findings"] = json.loads(row["findings"])
        if isinstance(row["scanned_at"], datetime):
            row["scanned_at"] = row["scanned_at"].isoformat()

    return rows