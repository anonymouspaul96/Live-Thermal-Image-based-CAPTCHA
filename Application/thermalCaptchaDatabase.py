import sqlite3
import hashlib
import uuid
from datetime import datetime, timedelta

# Connect to the SQLite database
conn = sqlite3.connect('thermal_captcha.db')
cursor = conn.cursor()

# Create the ServerVSWebsite table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ServerVSWebsite (
        UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
        SiteKey TEXT UNIQUE NOT NULL,
        WebsiteName TEXT UNIQUE NOT NULL,
        SharedKey TEXT NOT NULL
    )
''')

# Create the Users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
        UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
        SiteKey TEXT NOT NULL,
        WebsiteName TEXT NOT NULL,
        UserIPAddress TEXT NOT NULL,
        FOREIGN KEY (SiteKey) REFERENCES ServerVSWebsite(SiteKey)
    )
''')

# Create the Detections table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS Detections (
        UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
        UserID INTEGER NOT NULL,
        Result INTEGER NOT NULL,
        Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (UserID) REFERENCES Users(UniqueID)
    )
''')

# Create the UserNonce table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS UserNonce (
        UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
        UserID INTEGER NOT NULL,
        Nonce TEXT NOT NULL UNIQUE,
        Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (UserID) REFERENCES Users(UniqueID)
    )
''')

# Create the TokenNonce table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS TokenNonce (
        UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
        Token TEXT NOT NULL,
        Nonce TEXT NOT NULL UNIQUE,
        Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')

# Commit the changes
conn.commit()

# Function to generate a 40-character alphanumeric key
def generate_key():
    return uuid.uuid4().hex[:40]

# Function to hash the shared key
def hash_shared_key(shared_key):
    return hashlib.sha256(shared_key.encode()).hexdigest()

# Function to add a new website to the ServerVSWebsite table
def add_website(website_name):
    # Check if the website name already exists
    cursor.execute('SELECT * FROM ServerVSWebsite WHERE WebsiteName = ?', (website_name,))
    if cursor.fetchone() is not None:
        print("Website name already exists.")
        return

    site_key = generate_key()
    shared_key = "548c8ffd856f4d74a518a63aa9a5d9d2" #for simplicity we giving common shared key instead of using generate_key()
    hashed_shared_key = hash_shared_key(shared_key)

    cursor.execute('''
        INSERT INTO ServerVSWebsite (SiteKey, WebsiteName, SharedKey)
        VALUES (?, ?, ?)
    ''', (site_key, website_name, hashed_shared_key))

    conn.commit()
    print(f"Website added successfully. Site Key: {site_key}, Shared Key (hashed value): {shared_key}")

# Function to add a new user to the Users table
def add_user(site_key, website_name, user_ip):
    # Check if the site key exists in the ServerVSWebsite table
    cursor.execute('SELECT * FROM ServerVSWebsite WHERE SiteKey = ?', (site_key,))
    if cursor.fetchone() is None:
        print("Site key does not exist.")
        return None

    cursor.execute('''
        INSERT INTO Users (SiteKey, WebsiteName, UserIPAddress)
        VALUES (?, ?, ?)
    ''', (site_key, website_name, user_ip))

    conn.commit()
    user_id = cursor.lastrowid
    print(f"User added successfully with UserID: {user_id}")
    return user_id

# Function to add a new detection result to the Detections table
def add_detection(user_id, result):
    if user_id is None:
        print("Invalid user_id: cannot add detection result.")
        return

    cursor.execute('''
        INSERT INTO Detections (UserID, Result)
        VALUES (?, ?)
    ''', (user_id, result))

    conn.commit()
    print("Detection result added successfully.")

# Function to add a nonce for a user
def add_user_nonce(user_id, nonce):
    cursor.execute('SELECT * FROM UserNonce WHERE Nonce = ?', (nonce,))
    if cursor.fetchone() is not None:
        print("Nonce already exists for a user.")
        return

    cursor.execute('''
        INSERT INTO UserNonce (UserID, Nonce)
        VALUES (?, ?)
    ''', (user_id, nonce))

    conn.commit()
    print("User nonce added successfully.")

# Function to add a nonce for a token
def add_token_nonce(token, nonce):
    cursor.execute('SELECT * FROM TokenNonce WHERE Nonce = ?', (nonce,))
    if cursor.fetchone() is not None:
        print("Nonce already exists for a token.")
        return

    cursor.execute('''
        INSERT INTO TokenNonce (Token, Nonce)
        VALUES (?, ?)
    ''', (token, nonce))

    conn.commit()
    print("Token nonce added successfully.")

# Function to check if a user nonce is present in the database
def is_user_nonce_present(nonce):
    cursor.execute('SELECT * FROM UserNonce WHERE Nonce = ?', (nonce,))
    row = cursor.fetchone()
    if row:
        print(f"User Nonce '{nonce}' is present in the database.")
        return True
    else:
        print(f"User Nonce '{nonce}' is not present in the database.")
        return False

# Function to check if a token nonce is present in the database
def is_token_nonce_present(nonce):
    cursor.execute('SELECT * FROM TokenNonce WHERE Nonce = ?', (nonce,))
    row = cursor.fetchone()
    if row:
        print(f"Token Nonce '{nonce}' is present in the database.")
        return True
    else:
        print(f"Token Nonce '{nonce}' is not present in the database.")
        return False

# Function to delete records older than 3 minutes from the Detections table
def delete_old_records():
    three_minutes_ago = datetime.utcnow() - timedelta(minutes=3)
    cursor.execute('DELETE FROM Detections WHERE Timestamp < ?', (three_minutes_ago,))
    conn.commit()
    print("Old records deleted successfully.")

# Function to show all entries in the ServerVSWebsite table
def show_all_websites():
    cursor.execute('SELECT * FROM ServerVSWebsite')
    rows = cursor.fetchall()
    print("ServerVSWebsite Table:")
    for row in rows:
        print(row)

# Function to show all entries in the Users table
def show_all_users():
    cursor.execute('SELECT * FROM Users')
    rows = cursor.fetchall()
    print("Users Table:")
    for row in rows:
        print(row)

# Function to show all entries in the UserNonce table
def show_all_user_nonces():
    cursor.execute('SELECT * FROM UserNonce')
    rows = cursor.fetchall()
    print("UserNonce Table:")
    for row in rows:
        print(row)

# Function to show all entries in the TokenNonce table
def show_all_token_nonces():
    cursor.execute('SELECT * FROM TokenNonce')
    rows = cursor.fetchall()
    print("TokenNonce Table:")
    for row in rows:
        print(row)

# Function to show all entries in the Detections table
def show_all_detections():
    cursor.execute('SELECT * FROM Detections')
    rows = cursor.fetchall()
    print("Detections Table:")
    for row in rows:
        print(row)

# Function to display the schema of the tables
def show_table_schema(table_name):
    cursor.execute(f'PRAGMA table_info({table_name})')
    schema = cursor.fetchall()
    print(f"Schema of {table_name}:")
    for column in schema:
        print(column)

def get_shared_key_by_sitekey(site_key):
    cursor.execute('SELECT SharedKey FROM ServerVSWebsite WHERE SiteKey = ?', (site_key,))
    row = cursor.fetchone()
    if row:
        print(f"Shared Key for Site Key {site_key}: {row[0]}")
        return row[0]
    else:
        print("Site key not found.")
        return None

# Function to fetch the result attribute from the Detections table using userID
def get_detection_results_by_user_id(user_id):
    cursor.execute('SELECT Result FROM Detections WHERE UserID = ?', (user_id,))
    results = cursor.fetchall()
    if results:
        print(f"Detection results for UserID {user_id}:")
        for result in results:
            print(result[0])
    else:
        print(f"No detection results found for UserID {user_id}")

top_100_websites = [
    "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org", "amazon.com", "twitter.com",
    "instagram.com", "linkedin.com", "yahoo.com", "whatsapp.com", "tiktok.com", "tmall.com", "taobao.com",
    "qq.com", "sohu.com", "vk.com", "yandex.ru", "weibo.com", "sina.com.cn", "microsoft.com", "live.com",
    "netflix.com", "reddit.com", "office.com", "pinterest.com", "aliexpress.com", "apple.com", "blogspot.com",
    "wordpress.com", "github.com", "bing.com", "zoom.us", "ebay.com", "adobe.com", "stackoverflow.com", "tumblr.com",
    "imdb.com", "paypal.com", "fandom.com", "cnn.com", "bbc.com", "weather.com", "nytimes.com", "espn.com",
    "bilibili.com", "hao123.com", "walmart.com", "chase.com", "target.com", "roblox.com", "shopify.com",
    "salesforce.com", "forbes.com", "spotify.com", "twitch.tv", "nih.gov", "linkedin.com", "wellsfargo.com",
    "craigslist.org", "hulu.com", "foxnews.com", "msn.com", "cnbc.com", "indeed.com", "zillow.com", "intuit.com",
    "tripadvisor.com", "bestbuy.com", "airbnb.com", "homedepot.com", "bankofamerica.com", "costco.com",
    "lowes.com", "usps.com", "quora.com", "wayfair.com", "macys.com", "khanacademy.org", "britannica.com",
    "healthline.com", "etsy.com", "dropbox.com", "mapquest.com", "baidu.com", "bbc.co.uk", "nasa.gov",
    "wikimedia.org", "glassdoor.com", "groupon.com", "npr.org", "reddit.com", "goodreads.com", "nih.gov",
    "homedepot.com", "lowes.com", "realtor.com", "yahoo.co.jp", "ikea.com", "fortune.com", "buzzfeed.com",
    "example.com", "example.org", "example.net", "example.edu", "example.gov"
]

# # Add top 100 websites to the database
# for website in top_100_websites:
#     add_website(website)


# Use the actual site key generated by add_website
site_key_example = "28024d2408754883a7eff1db9cea2b00"
user_id = add_user(site_key_example, "microsoft.com", "192.168.1.1")

if user_id is not None:
    add_detection(user_id, 85)
    # add_user_nonce(user_id, "nonce123456")
    # add_token_nonce("token123456", "nonce654321")


delete_old_records()

# Check if specific nonces are present in the database
is_user_nonce_present("nonce123456")
is_token_nonce_present("nonce654321")

# # Show all entries
#show_all_websites()
show_all_users()
show_all_detections()
show_all_user_nonces()
show_all_token_nonces()
get_shared_key_by_sitekey("28024d2408754883a7eff1db9cea2b00")
get_detection_results_by_user_id(18)

## Show table schemas
# show_table_schema('ServerVSWebsite')
# show_table_schema('Users')
# show_table_schema('Detections')
# show_table_schema('UserNonce')
# show_table_schema('TokenNonce')


# Close the connection
conn.close()
