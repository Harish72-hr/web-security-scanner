import sqlite3


def init_db():

    conn = sqlite3.connect("scanner.db")

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            url TEXT,

            is_onion INTEGER,

            risk_level TEXT,

            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)

    conn.commit()
    conn.close()


def save_scan(url, is_onion=False, risk_level="Unknown"):

    conn = sqlite3.connect("scanner.db")

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scans
        (url, is_onion, risk_level)
        VALUES (?, ?, ?)
        """,
        (url, int(is_onion), risk_level)
    )

    conn.commit()
    conn.close()


def get_last_scans():

    conn = sqlite3.connect("scanner.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT url
        FROM scans
        ORDER BY id DESC
        LIMIT 5
    """)

    data = cursor.fetchall()

    conn.close()

    return [x[0] for x in data]


def get_dashboard_stats():

    conn = sqlite3.connect("scanner.db")

    cursor = conn.cursor()

    # Total scans
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    # Onion scans
    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE is_onion = 1"
    )
    onion_scans = cursor.fetchone()[0]

    # Normal scans
    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE is_onion = 0"
    )
    normal_scans = cursor.fetchone()[0]

    # Risk levels
    cursor.execute("""
        SELECT risk_level, COUNT(*)
        FROM scans
        GROUP BY risk_level
    """)

    risk_data = cursor.fetchall()

    conn.close()

    risk_stats = {
        "Low": 0,
        "Medium": 0,
        "High": 0
    }

    for risk, count in risk_data:

        if risk in risk_stats:
            risk_stats[risk] = count

    return {
        "total_scans": total_scans,
        "onion_scans": onion_scans,
        "normal_scans": normal_scans,
        "risk_stats": risk_stats
    }
def get_recent_scans(limit=10):

    conn = sqlite3.connect("scanner.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            url,
            risk_level,
            is_onion,
            scan_date
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    data = cursor.fetchall()

    conn.close()

    return data