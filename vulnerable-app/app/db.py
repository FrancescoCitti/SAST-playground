"""Database access layer with an intentional SQL injection."""

import sqlite3

from .config import DATABASE_PATH


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def find_user(username):
    """Look up a user by name.

    VULN #1: SQL injection.
    Expected tool(s): Semgrep (p/security-audit / p/owasp-top-ten), CodeQL
    (taint tracking from the `username` parameter into the query).

    The user-controlled ``username`` is concatenated straight into the SQL
    string, so input like ``' OR '1'='1`` rewrites the query. The safe form is
    a parameterised query: ``cursor.execute("... WHERE name = ?", (username,))``.
    """
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT id, name, email FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
