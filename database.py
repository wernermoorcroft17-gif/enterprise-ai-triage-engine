import sqlite3
from datetime import datetime, timezone

class DatabaseTransactionError(Exception):
    """PCAP: Custom exception class for database-layer errors."""
    pass

class TriageDatabaseManager:
    """PCAP & DP-300: OOP Data Access Layer with parameterized SQL and B-Tree indexing."""

    def __init__(self, db_filename: str = "triage_records.db"):
        self.db_filename = db_filename
        self._bootstrap_schema()

    def _connect(self):
        return sqlite3.connect(self.db_filename)

    def _bootstrap_schema(self):
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS tickets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        redacted_text TEXT NOT NULL,
                        pii_count INTEGER NOT NULL,
                        category TEXT NOT NULL,
                        sentiment TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        engine_used TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                # DP-300: Non-clustered composite index to optimize filtered queries
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_tickets_category_sentiment
                    ON tickets(category, sentiment)
                """)
                conn.commit()
        except sqlite3.Error as err:
            raise DatabaseTransactionError(f"Schema initialization failed: {err}")

    def log_ticket(self, redacted_text: str, pii_count: int, category: str, sentiment: str, confidence: float, engine_used: str) -> dict:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                # DP-300: Parameterized query (?) prevents SQL Injection vulnerabilities
                cursor.execute("""
                    INSERT INTO tickets (redacted_text, pii_count, category, sentiment, confidence, engine_used, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (redacted_text, pii_count, category, sentiment, confidence, engine_used, timestamp))
                conn.commit()
                return {
                    "id": cursor.lastrowid,
                    "redacted_text": redacted_text,
                    "pii_count": pii_count,
                    "category": category,
                    "sentiment": sentiment,
                    "confidence": confidence,
                    "engine_used": engine_used,
                    "created_at": timestamp
                }
        except sqlite3.Error as err:
            raise DatabaseTransactionError(f"Insert transaction failed: {err}")

    def get_all_tickets(self, limit: int = 20) -> list[dict]:
        try:
            with self._connect() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, redacted_text, pii_count, category, sentiment, confidence, engine_used, created_at
                    FROM tickets
                    ORDER BY id DESC
                    LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as err:
            raise DatabaseTransactionError(f"Read query failed: {err}")