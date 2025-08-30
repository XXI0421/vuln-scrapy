import sqlite3, datetime, os
from itemadapter import ItemAdapter

DB_PATH = r"D:\pythonProject1\intel-engine\intel.db"

class SQLitePipeline:
    def open_spider(self, spider):
        self.conn = sqlite3.connect(DB_PATH)
        self.cur  = self.conn.cursor()
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS assets(
                ip        TEXT,
                port      INTEGER,
                protocol  TEXT,
                host      TEXT,
                title     TEXT,
                banner    TEXT,
                icp       TEXT,
                country   TEXT,
                city      TEXT,
                framework TEXT,
                last_seen DATETIME,
                UNIQUE(ip, port)
            )
        """)
        self.conn.commit()

    def close_spider(self, spider):
        self.conn.close()

    def process_item(self, item, spider):
        adapter = ItemAdapter(item)
        text = (adapter.get("banner", "") + " " + adapter.get("server", "")).lower()
        framework = spider.extract_framework(text)
        self.cur.execute("""
            INSERT OR IGNORE INTO assets
            (ip, port, protocol, host, title, banner, icp, country, city, framework, last_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            adapter["ip"],
            int(adapter["port"]),
            adapter["protocol"],
            adapter.get("host"),
            adapter.get("title"),
            adapter.get("banner"),
            adapter.get("icp"),
            adapter.get("country"),
            adapter.get("city"),
            framework,
            datetime.datetime.utcnow().isoformat(timespec="seconds")
        ))
        self.conn.commit()
        return item