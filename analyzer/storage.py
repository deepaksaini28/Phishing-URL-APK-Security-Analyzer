import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone


def connect(database):
    os.makedirs(os.path.dirname(os.path.abspath(database)), exist_ok=True)
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def database_connection(database):
    connection = connect(database)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database(database):
    with database_connection(database) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                sha256 TEXT,
                risk TEXT NOT NULL,
                score INTEGER,
                created_at TEXT NOT NULL,
                details TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS scans_created_at ON scans(created_at DESC)"
        )


def save_scan(database, kind, subject, sha256, risk, score, details):
    created_at = datetime.now(timezone.utc).isoformat()
    with database_connection(database) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans(kind, subject, sha256, risk, score, created_at, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (kind, subject, sha256, risk, score, created_at, json.dumps(details)),
        )
        return cursor.lastrowid, created_at


def list_scans(database, limit=100):
    with database_connection(database) as connection:
        rows = connection.execute(
            """
            SELECT id, kind, subject, sha256, risk, score, created_at
            FROM scans ORDER BY created_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_scan(database, scan_id):
    with database_connection(database) as connection:
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = json.loads(result["details"])
        return result


def count_scans(database):
    with database_connection(database) as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM scans").fetchone()
        return row["count"]
