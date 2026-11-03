"""Database setup and inspection for the ThermoCAPTCHA server.

Usage (from the Application directory):
    python thermalCaptchaDatabase.py init                    # create all tables
    python thermalCaptchaDatabase.py add-website example.com # register a site, print its K_site once
    python thermalCaptchaDatabase.py seed-top100             # register the top-100 demo sites
    python thermalCaptchaDatabase.py show [Table]            # print a table (default: ServerVSWebsite)

Website secrets (K_site) are generated randomly per site and are NOT stored in
the database. Only SHA-256(K_site) is kept, for identification. Configure the
printed K_site in the environment:
    CAPTCHA server : THERMOCAPTCHA_SITE_SECRETS='{"<SiteKey>": "<K_site>", ...}'
    Website        : THERMOCAPTCHA_WEBSITE_SECRET='<K_site>'
"""
import hashlib
import os
import secrets
import sqlite3
import sys
import uuid

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(APP_DIR))          # repository root holds thermocaptcha_protocol.py
import thermocaptcha_protocol as tp  # noqa: E402

DB_PATH = os.path.join(APP_DIR, "thermal_captcha.db")

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS ServerVSWebsite (
    UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
    SiteKey TEXT UNIQUE NOT NULL,
    WebsiteName TEXT UNIQUE NOT NULL,
    SharedKey TEXT NOT NULL            -- SHA-256(K_site); the key itself lives only in the environment
);
CREATE TABLE IF NOT EXISTS Users (
    UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
    SiteKey TEXT NOT NULL,
    WebsiteName TEXT NOT NULL,
    UserIPAddress TEXT NOT NULL,
    FOREIGN KEY (SiteKey) REFERENCES ServerVSWebsite(SiteKey)
);
CREATE TABLE IF NOT EXISTS Detections (
    UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
    UserID INTEGER NOT NULL,
    Result INTEGER NOT NULL,
    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES Users(UniqueID)
);
"""

TOP_100_WEBSITES = [
    "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org", "amazon.com", "twitter.com",
    "instagram.com", "linkedin.com", "yahoo.com", "whatsapp.com", "tiktok.com", "tmall.com", "taobao.com",
    "qq.com", "sohu.com", "vk.com", "yandex.ru", "weibo.com", "sina.com.cn", "microsoft.com", "live.com",
    "netflix.com", "reddit.com", "office.com", "pinterest.com", "aliexpress.com", "apple.com", "blogspot.com",
    "wordpress.com", "github.com", "bing.com", "zoom.us", "ebay.com", "adobe.com", "stackoverflow.com", "tumblr.com",
    "imdb.com", "paypal.com", "fandom.com", "cnn.com", "bbc.com", "weather.com", "nytimes.com", "espn.com",
    "bilibili.com", "hao123.com", "walmart.com", "chase.com", "target.com", "roblox.com", "shopify.com",
    "salesforce.com", "forbes.com", "spotify.com", "twitch.tv", "nih.gov", "wellsfargo.com",
    "craigslist.org", "hulu.com", "foxnews.com", "msn.com", "cnbc.com", "indeed.com", "zillow.com", "intuit.com",
    "tripadvisor.com", "bestbuy.com", "airbnb.com", "homedepot.com", "bankofamerica.com", "costco.com",
    "lowes.com", "usps.com", "quora.com", "wayfair.com", "macys.com", "khanacademy.org", "britannica.com",
    "healthline.com", "etsy.com", "dropbox.com", "mapquest.com", "bbc.co.uk", "nasa.gov",
    "wikimedia.org", "glassdoor.com", "groupon.com", "npr.org", "goodreads.com",
    "realtor.com", "yahoo.co.jp", "ikea.com", "fortune.com", "buzzfeed.com",
    "example.com", "example.org", "example.net", "example.edu", "example.gov",
]


def connect(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.executescript(BASE_SCHEMA)
    conn.executescript(tp.ThermoCaptchaServer.SCHEMA)   # challenge, session, nonce tables
    conn.commit()
    return conn


def add_website(conn, website_name):
    """Register a website. Returns (SiteKey, K_site); K_site is shown once and never stored."""
    if conn.execute("SELECT 1 FROM ServerVSWebsite WHERE WebsiteName = ?", (website_name,)).fetchone():
        print(f"{website_name}: already registered.")
        return None
    site_key = uuid.uuid4().hex
    k_site = secrets.token_hex(32)
    conn.execute("INSERT INTO ServerVSWebsite (SiteKey, WebsiteName, SharedKey) VALUES (?, ?, ?)",
                 (site_key, website_name, hashlib.sha256(k_site.encode()).hexdigest()))
    conn.commit()
    return site_key, k_site


def show_table(conn, table):
    if table not in {"ServerVSWebsite", "Users", "Detections", "TokenNonce", "CaptchaChallenge",
                     "VerifiedSession", "WebsiteRequestNonce"}:
        raise SystemExit(f"unknown table {table}")
    print(f"{table}:")
    for row in conn.execute(f"SELECT * FROM {table}"):
        print(row)


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    conn = connect()
    cmd = argv[0]
    if cmd == "init":
        print(f"Tables ready in {DB_PATH}")
    elif cmd in ("add-website", "seed-top100"):
        names = argv[1:] if cmd == "add-website" else TOP_100_WEBSITES
        site_secrets = {}
        for name in names:
            created = add_website(conn, name)
            if created:
                site_key, k_site = created
                site_secrets[site_key] = k_site
                print(f"{name}: SiteKey={site_key}")
        if site_secrets:
            print("\nStore these K_site values securely; they are not saved anywhere else.")
            print("Server environment:\n  export THERMOCAPTCHA_SITE_SECRETS='" + __import__("json").dumps(site_secrets) + "'")
    elif cmd == "show":
        show_table(conn, argv[1] if len(argv) > 1 else "ServerVSWebsite")
    else:
        raise SystemExit(__doc__)
    conn.close()


if __name__ == "__main__":
    main(sys.argv[1:])
