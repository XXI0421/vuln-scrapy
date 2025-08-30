import sqlite3
from pathlib import Path

class CvePipeline:
    def open_spider(self, spider):
        DB_PATH = Path(__file__).resolve().parents[3] / "vuln-db" / "std" / "vuln.db"
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS vuln(
            cve TEXT UNIQUE,
            cvss REAL,
            description TEXT,
            patch_commit TEXT,
            exp_url TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")

    def process_item(self, item, spider):
        self.conn.execute("""
        INSERT OR IGNORE INTO vuln(cve, cvss, description, patch_commit, exp_url)
        VALUES (?,?,?,?,?)
        """, (item["cve"], item["cvss"], item["description"], item["patch_commit"], item["exp_url"]))
        return item

    def close_spider(self, spider):
        if hasattr(self, 'conn'):
            self.conn.commit()
            self.conn.close()