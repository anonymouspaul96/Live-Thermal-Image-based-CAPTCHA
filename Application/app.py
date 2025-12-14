from flask import Flask, render_template, request, jsonify
from PIL import Image
import sys
import numpy as np
import cv2
from yolo_detection_images import runModel
import pygame
import pygame.camera
import time
import io
import os
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature
import requests
import base64
import sqlite3
from IPython.display import display
from thermalImageChecker import is_thermal_image
import hmac
import datetime
import jwt
from cryptography.fernet import Fernet
import jwt
import hmac
import datetime
from cryptography.fernet import Fernet
import json
import base64
import sqlite3
import jwt
import datetime
from cryptography.fernet import Fernet
import base64
import os
import hmac
import uuid
import platform

# img = os.path.join('static', 'Image')

app = Flask(__name__)

# Constants
# Ensure it's in bytes #Server own secret key
SERVER_SECRET_KEY = '9a61f13c92a04010b0f87a15734673c8'.encode()

# Camera selection preference
# IMPORTANT: On macOS, pygame camera names don't match actual cameras!
# Based on testing:
#   - Camera 0 = PureThermal (but pygame reports it as "FaceTime HD Camera")
#   - Camera 1 = iPhone (but pygame reports it as "PureThermal")
#   - Camera 2 = FaceTime (but pygame reports it as "iPhone")
# 
# Options: 
#   - Integer (0, 1, 2, etc.) - Use specific camera index
#   - "PureThermal", "iPhone", "FaceTime" - Search by name (may not work correctly on macOS)
#   - None - Use first available camera
PREFERRED_CAMERA_INDEX = 0  # Use Camera 0 for PureThermal (despite pygame reporting it as FaceTime)

# ************************************* CAPTCHA SERVER FUNCTIONS (5) starts ***************

# Function to add a nonce for a token


def add_token_nonce2(token, nonce, cursor, conn):
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

# Function to show all entries in the TokenNonce table


def show_all_token_nonces2(cursor):
    cursor.execute('SELECT * FROM TokenNonce')
    rows = cursor.fetchall()
    print("TokenNonce Table:")
    for row in rows:
        print(row)

# Function to check if a token nonce is present in the database


def is_token_nonce_present2(nonce, cursor):
    cursor.execute('SELECT * FROM TokenNonce WHERE Nonce = ?', (nonce,))
    row = cursor.fetchone()
    if row:
        print(f"Token Nonce '{nonce}' is present in the database.")
        return True
    else:
        print(f"Token Nonce '{nonce}' is not present in the database.")
        return False

# Function to fetch the result attribute from the Detections table using userID


def get_detection_results_by_user_id2(user_id, cursor):
    cursor.execute(
        'SELECT Result FROM Detections WHERE UserID = ?', (user_id,))
    results = cursor.fetchall()
    if results:
        print(f"Detection results for UserID {user_id}:")
        for result in results:
            risk_score = result[0]
            print(result[0])
            return risk_score
    else:
        print(f"No detection results found for UserID {user_id}")
        return None

# Function to show all entries in the Detections table


def show_all_detections2(cursor):
    cursor.execute('SELECT * FROM Detections')
    rows = cursor.fetchall()
    print("Detections Table:")
    for row in rows:
        print(row)

# Function to fetch the shared key from the ServerVSWebsite table using site key


def get_shared_key_by_sitekey2(site_key, cursor):
    cursor.execute(
        'SELECT SharedKey FROM ServerVSWebsite WHERE SiteKey = ?', (site_key,))
    row = cursor.fetchone()
    if row:
        return row[0]
    else:
        print("Site key not found.")
        return None


def derive_combined_key2(server_key, shared_key):
    """
    Derives a combined key using HMAC with SHA-256.
    """
    return base64.urlsafe_b64encode(hmac.new(server_key, shared_key, digestmod='sha256').digest())


def decrypt_token2(encrypted_token, received_shared_key):
    """
    Decrypts the token using a combined key derived from the server and shared keys.
    """
    combined_key = derive_combined_key2(SERVER_SECRET_KEY, received_shared_key)
    fernet_combined = Fernet(combined_key)
    decrypted_token = fernet_combined.decrypt(encrypted_token).decode()
    return decrypted_token


def get_session_tracking2(user_id, session_id, cursor):
    """
    Retrieve stored sessionID and device fingerprint for verification.
    """
    cursor.execute('''
        SELECT SessionID, DeviceFingerprint FROM SessionTracking 
        WHERE UserID = ? AND SessionID = ?
    ''', (user_id, session_id))
    row = cursor.fetchone()
    if row:
        return {'sessionID': row[0], 'device_fingerprint': row[1]}
    return None

def validate_token2(encrypted_token, received_shared_key, get_shared_key_by_sitekey_func, cursor, conn):
    """
    Validates the traceable token by:
    1. Decrypting it using dual-layered encryption
    2. Verifying JWT signature and expiration
    3. Checking nonce for replay attacks
    4. Verifying sessionID and device fingerprint integrity (traceable token mechanism)
    This prevents token reuse by CAPTCHA farms and detects tampering/relaying.
    """
    if not hmac.compare_digest(received_shared_key, get_shared_key_by_sitekey_func):
        return False, None, "Invalid shared key"

    try:
        token = decrypt_token2(encrypted_token, received_shared_key)
        decoded = jwt.decode(token, SERVER_SECRET_KEY, algorithms=['HS256'])

        # Check if the nonce has been used before
        received_token_nonce = decoded.get('nonce')
        if is_token_nonce_present2(received_token_nonce, cursor):
            return False, None, "Replay attack detected: nonce already used"
        
        # Extract sessionID and device fingerprint from token (traceable token mechanism)
        user_id = decoded.get('result_row_number')
        received_session_id = decoded.get('sessionID')
        received_device_fingerprint = decoded.get('device_fingerprint')
        
        if not received_session_id or not received_device_fingerprint:
            return False, None, "Traceable token validation failed: missing sessionID or device fingerprint"
        
        # Retrieve stored session tracking data
        stored_session = get_session_tracking2(user_id, received_session_id, cursor)
        
        if not stored_session:
            return False, None, "Traceable token validation failed: sessionID not found or token tampered with"
        
        # Verify device fingerprint matches (prevents token relaying)
        if stored_session['device_fingerprint'] != received_device_fingerprint:
            return False, None, "Traceable token validation failed: device fingerprint mismatch - token may be relayed or tampered with"
        
        # Verify sessionID matches
        if stored_session['sessionID'] != received_session_id:
            return False, None, "Traceable token validation failed: sessionID mismatch - token may be tampered with"
        
        print(f"Traceable token verified: SessionID={received_session_id[:8]}..., DeviceFingerprint={received_device_fingerprint[:16]}...")
        
        # Mark token nonce as used
        add_token_nonce2(user_id, received_token_nonce, cursor, conn)
        
        return True, user_id, decoded
    except jwt.ExpiredSignatureError:
        return False, None, "Token has expired"
    except jwt.InvalidTokenError:
        return False, None, "Invalid token"
    except Exception as e:
        return False, None, str(e)
# ************************************* CAPTCHA SERVER FUNCTIONS (5) Ends *************

# **********************************CAPTCHA SERVER FUNCTIONS (2) ************************


def derive_combined_key(server_key, shared_key):
    return base64.urlsafe_b64encode(hmac.new(server_key, shared_key.encode(), digestmod='sha256').digest())


def generate_token(user_id, site_key, session_id, device_fingerprint):
    """
    Generates a traceable JWT token with sessionID and device fingerprint.
    This makes the token tamper-proof and prevents token reuse by CAPTCHA farms.
    """
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=2)
    nonce = os.urandom(16).hex()
    token_payload = {
        'exp': expiration_time,
        'result_row_number': user_id,
        'SiteKey': site_key,
        'nonce': nonce,
        'sessionID': session_id,  # Unique session identifier
        'device_fingerprint': device_fingerprint  # Device fingerprint for integrity check
    }
    token = jwt.encode(token_payload, SERVER_SECRET_KEY, algorithm='HS256')
    return token


def encrypt_token(token, shared_key):
    combined_key = derive_combined_key(SERVER_SECRET_KEY, shared_key)
    fernet_combined = Fernet(combined_key)

    # Check if token is a string, if so, encode it
    if isinstance(token, str):
        token = token.encode()

    encrypted_token = fernet_combined.encrypt(token)
    return encrypted_token


def add_user(site_key, website_name, user_ip, cursor, conn):
    cursor.execute(
        'SELECT * FROM ServerVSWebsite WHERE SiteKey = ?', (site_key,))
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


def add_detection(user_id, result, cursor, conn):
    if user_id is None:
        print("Invalid user_id: cannot add detection result.")
        return

    cursor.execute('''
        INSERT INTO Detections (UserID, Result)
        VALUES (?, ?)
    ''', (user_id, result))

    conn.commit()
    print("Detection result added successfully.")


def add_user_nonce(user_id, nonce, cursor, conn):
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


def is_user_nonce_present(nonce, cursor):
    cursor.execute('SELECT * FROM UserNonce WHERE Nonce = ?', (nonce,))
    row = cursor.fetchone()
    if row:
        print(f"User Nonce '{nonce}' is present in the database.")
        return True
    else:
        print(f"User Nonce '{nonce}' is not present in the database.")
        return False


def show_all_websites(cursor):
    cursor.execute('SELECT * FROM ServerVSWebsite')
    rows = cursor.fetchall()
    print("ServerVSWebsite Table:")
    for row in rows:
        print(row)


def show_all_users(cursor):
    cursor.execute('SELECT * FROM Users')
    rows = cursor.fetchall()
    print("Users Table:")
    for row in rows:
        print(row)


def show_all_user_nonces(cursor):
    cursor.execute('SELECT * FROM UserNonce')
    rows = cursor.fetchall()
    print("UserNonce Table:")
    for row in rows:
        print(row)


def show_all_detections(cursor):
    cursor.execute('SELECT * FROM Detections')
    rows = cursor.fetchall()
    print("Detections Table:")
    for row in rows:
        print(row)


def show_table_schema(table_name, cursor):
    cursor.execute(f'PRAGMA table_info({table_name})')
    schema = cursor.fetchall()
    print(f"Schema of {table_name}:")
    for column in schema:
        print(column)


def get_shared_key_by_sitekey(site_key, cursor):
    cursor.execute(
        'SELECT SharedKey FROM ServerVSWebsite WHERE SiteKey = ?', (site_key,))
    row = cursor.fetchone()
    if row:
        return row[0]
    else:
        print("Site key not found.")
        return None

def add_session_tracking(user_id, session_id, device_fingerprint, cursor, conn):
    """
    Store sessionID and device fingerprint for later verification.
    This enables traceable token mechanism to detect token tampering or relaying.
    """
    # Check if table exists, if not create it
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS SessionTracking (
            UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
            UserID INTEGER NOT NULL,
            SessionID TEXT NOT NULL UNIQUE,
            DeviceFingerprint TEXT NOT NULL,
            Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (UserID) REFERENCES Users(UniqueID)
        )
    ''')
    
    cursor.execute('''
        INSERT INTO SessionTracking (UserID, SessionID, DeviceFingerprint)
        VALUES (?, ?, ?)
    ''', (user_id, session_id, device_fingerprint))
    
    conn.commit()
    print(f"Session tracking added: SessionID={session_id}, DeviceFingerprint={device_fingerprint[:16]}...")

# Function to delete records older than 3 minutes from the Detections table


def delete_old_records(cursor, conn):
    three_minutes_ago = datetime.datetime.utcnow() - datetime.timedelta(minutes=3)
    cursor.execute('DELETE FROM Detections WHERE Timestamp < ?',
                   (three_minutes_ago,))
    conn.commit()
    print("Old records deleted successfully.")


def process_payload(payload_json, cursor, conn):
    try:
        # Parse payload and check for required keys
        payload = json.loads(payload_json)
        required_keys = ["binary_with_metadata", "signature",
                         "public_key", "SiteKey", "WebsiteName", "user_IP", "device_fingerprint"]
        for key in required_keys:
            if key not in payload:
                raise KeyError(f"Missing required key in payload: {key}")

        binary_with_metadata_base64 = payload["binary_with_metadata"]
        signature_base64 = payload["signature"]
        public_key_base64 = payload["public_key"]
        site_key = payload["SiteKey"]
        website_name = payload["WebsiteName"]
        user_IP = payload["user_IP"]
        received_device_fingerprint = payload["device_fingerprint"]  # Extract device fingerprint from payload

        # Decode Base64 to binary
        received_binary_with_metadata = base64.b64decode(
            binary_with_metadata_base64)
        received_signature = base64.b64decode(signature_base64)
        public_key = serialization.load_pem_public_key(
            public_key_base64.encode())

        # Extract the metadata (timestamp, nonce, and device fingerprint)
        metadata_start = received_binary_with_metadata.rfind(b"Timestamp:")
        received_metadata = received_binary_with_metadata[metadata_start:].decode(
        )
        received_binary = received_binary_with_metadata[:metadata_start]

        # Extract timestamp, nonce, and device fingerprint from metadata
        received_timestamp = received_metadata.split(
            ", Nonce: ")[0].split("Timestamp: ")[1]
        nonce_part = received_metadata.split(", Nonce: ")[1]
        received_nonce = nonce_part.split(", DeviceFingerprint: ")[0]
        metadata_device_fingerprint = nonce_part.split(", DeviceFingerprint: ")[1] if ", DeviceFingerprint: " in nonce_part else None
        
        # Verify device fingerprint matches between payload and metadata
        if metadata_device_fingerprint and metadata_device_fingerprint != received_device_fingerprint:
            print("Warning: Device fingerprint mismatch between payload and metadata")
        
        # Use the device fingerprint from payload (more reliable)
        device_fingerprint = received_device_fingerprint

        # First check if the received image is a thermal image or not
        image = Image.open(io.BytesIO(received_binary))
        result = is_thermal_image(image)
        if result == "Thermal Image":
            print(f"Image is: {result}")
            # conn = sqlite3.connect('thermal_captcha.db')
            # cursor = conn.cursor()

            if is_user_nonce_present(received_nonce, cursor):
                print("Message rejected: nonce has been used before.")
            else:
                # Check if the timestamp is within the acceptable range (e.g., 2 minutes)
                current_time = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                current_time_obj = time.strptime(
                    current_time, "%Y-%m-%dT%H:%M:%SZ")
                received_time_obj = time.strptime(
                    received_timestamp, "%Y-%m-%dT%H:%M:%SZ")

                time_difference = abs(time.mktime(
                    current_time_obj) - time.mktime(received_time_obj))

                if time_difference > 120:
                    print(
                        f"Message rejected: timestamp is too old. | TimeStamp: {time_difference} seconds")
                else:
                    # Hash the received binary data with metadata
                    received_binary_hash = hashlib.sha256(
                        received_binary_with_metadata).digest()

                    # Verify the signature
                    try:
                        public_key.verify(
                            received_signature,
                            received_binary_hash,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            Prehashed(hashes.SHA256())
                        )
                        print(
                            f"Message verified and accepted. Received Nonce: {received_nonce} | TimeStamp: {time_difference} seconds")
                        # print(f"Received Binary Data: {received_binary}")

                        image = Image.open(io.BytesIO(received_binary))
                        # display(image)
                        # Get the application directory for saving the encoded image
                        app_dir = os.path.dirname(os.path.abspath(__file__))
                        encoded_image_path = os.path.join(app_dir, "encoded_image_only_timestamp_nonce.jpg")
                        image.save(encoded_image_path)
                        img = cv2.imread(encoded_image_path, -1)
                        # receiving img(image with bounaady box), foundLabel(detected lable from image), conf(confidence on detection)
                        # sending the image to the model for detction. No need for capturing the detection image. I wanted to show the detection result in the browser.
                        img, foundLabel, conf = runModel(img)

                        user_id = add_user(
                            site_key, website_name, user_IP, cursor, conn)
                        if user_id is not None:
                            add_detection(user_id, conf*100, cursor, conn)
                            add_user_nonce(
                                user_id, received_nonce, cursor, conn)
                            
                            # Generate unique sessionID for this challenge
                            session_id = str(uuid.uuid4())
                            print(f"Generated SessionID: {session_id}")
                            
                            # Store sessionID and device fingerprint for traceable token verification
                            add_session_tracking(user_id, session_id, device_fingerprint, cursor, conn)

                        show_all_detections(cursor)
                        # delete_old_records(cursor, conn) #Un-comment this line to delete all older ditection more then 3 minutes
                        SHARED_KEY = get_shared_key_by_sitekey(
                            site_key, cursor)
                        # show_all_user_nonces(cursor)

                        # Generate traceable token with sessionID and device fingerprint
                        token = generate_token(user_id, site_key, session_id, device_fingerprint)
                        encrypted_token = encrypt_token(token, SHARED_KEY)
                        # print(f"Generated Encrypted Token: {encrypted_token}")
                        encrypted_token_base64 = base64.b64encode(
                            encrypted_token).decode()

                        payload = {
                            "user_IP": user_IP,
                            "SiteKey": site_key,
                            "WebsiteName": website_name,
                            "token": encrypted_token_base64
                        }

                        payload_json_from_captchaServer_to_user = json.dumps(
                            payload)
                        print("2- Payload JSON:",
                              payload_json_from_captchaServer_to_user)
                        return img, foundLabel, conf*100, payload_json_from_captchaServer_to_user

                    except InvalidSignature:
                        print("Message rejected: invalid signature.")
        else:
            print(f"Rejected!!! Image is: {result}")
    except KeyError as e:
        print(e)

# ******************************************CAPTCHA SERVER function**********************************
# ******************************************UserSide functions starts***********************
# Function to generate device fingerprint
def generate_device_fingerprint(user_ip, user_agent=None):
    """
    Generates a unique device fingerprint based on device characteristics.
    In a real implementation, this would include more browser/system characteristics.
    """
    fingerprint_data = {
        'platform': platform.platform(),
        'system': platform.system(),
        'processor': platform.processor(),
        'ip': user_ip,
        'user_agent': user_agent or 'Unknown'
    }
    # Create a hash of the fingerprint data
    fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
    device_fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    return device_fingerprint

# Function to convert image to binary


def image_to_binary(image_path):
    with open(image_path, "rb") as image_file:
        return image_file.read()

# Function to add timestamp, nonce, and device fingerprint to the binary data


def add_metadata_to_binary(binary_data, timestamp, nonce, device_fingerprint):
    metadata = f"Timestamp: {timestamp}, Nonce: {nonce}, DeviceFingerprint: {device_fingerprint}"
    metadata_bytes = metadata.encode()
    return binary_data + metadata_bytes

# Responsible for capturing image using webcam


def userSide(SiteKey, WebsiteName):
    # Get the application directory
    app_dir = os.path.dirname(os.path.abspath(__file__))
    
    try:
        # initializing  the camera
        pygame.camera.init()
    except Exception as e:
        print(f"Error initializing pygame camera: {e}")
        print("Note: On macOS, you may need to grant camera permissions to Terminal/Python.")
        print("Go to System Preferences > Security & Privacy > Privacy > Camera")
        return None

    # make the list of all available cameras
    try:
        camlist = pygame.camera.list_cameras()
    except Exception as e:
        print(f"Error listing cameras: {e}")
        return None

    # if camera is detected or not
    if camlist and len(camlist) > 0:

        # Use the preferred camera index directly
        # Note: On macOS, pygame camera names don't match actual cameras
        # Camera 0 = PureThermal (despite pygame reporting it as "FaceTime HD Camera")
        if isinstance(PREFERRED_CAMERA_INDEX, int) and PREFERRED_CAMERA_INDEX < len(camlist):
            camera_index = PREFERRED_CAMERA_INDEX
            camera_name = str(camlist[camera_index])
            print(f"Using camera index {camera_index} (pygame reports: '{camera_name}')")
            print(f"Note: On macOS, actual camera may differ from reported name")
        else:
            # Fallback to first available camera
            camera_index = 0
            camera_name = str(camlist[0])
            print(f"Using first available camera: {camera_name} (index {camera_index})")
        
        print(f"Available cameras: {[f'{i}: {c}' for i, c in enumerate(camlist)]}")
        
        try:
            cam = pygame.camera.Camera(camlist[camera_index], (640, 480))
        except Exception as e:
            print(f"Error creating camera object: {e}")
            print("Camera may be in use by another application or permission denied.")
            return None

        # opening the camera
        try:
            cam.start()
            # Give camera a moment to initialize (especially important on macOS)
            # Camera 0 (PureThermal) may need more time
            wait_time = 1.5 if camera_index == 0 else 0.5
            time.sleep(wait_time)
        except Exception as e:
            print(f"Error starting camera {camera_index}: {e}")
            print("On macOS, ensure Terminal/Python has camera permissions in System Preferences.")
            if camera_index == 0:
                print("Note: Camera 0 (PureThermal) may need special permissions or be in use.")
                print("Try closing other applications that might be using the camera.")
            return None

        # capturing the single image
        try:
            image = cam.get_image()
        except Exception as e:
            print(f"Error capturing image: {e}")
            cam.stop()
            return None

        # saving the image
        # Use relative path that works on both Linux and macOS
        thermal_image_path = os.path.join(app_dir, "thermalImage.jpg")
        try:
            pygame.image.save(image, thermal_image_path)
        except Exception as e:
            print(f"Error saving image: {e}")
            cam.stop()
            return None
        
        cam.stop()

        # Generate keys (in practice, keys should be stored securely and reused)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Load image and convert to binary
        # Use the same path where we saved the image
        image_binary = image_to_binary(thermal_image_path)

        # Create timestamp and nonce
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # print(f"TimeStamp : {timestamp}")
        nonce = os.urandom(16).hex()
        # print(f"Nonce : {nonce}")

        # Generate device fingerprint
        user_IP = "127.0.0.1"
        device_fingerprint = generate_device_fingerprint(user_IP)
        # print(f"Device Fingerprint: {device_fingerprint}")

        # Add timestamp, nonce, and device fingerprint to the binary data
        binary_with_metadata = add_metadata_to_binary(
            image_binary, timestamp, nonce, device_fingerprint)

        # Hash the combined binary data with metadata
        binary_hash = hashlib.sha256(binary_with_metadata).digest()

        # Sign the hash
        signature = private_key.sign(
            binary_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            Prehashed(hashes.SHA256())
        )

        # Encode binary data and signature to Base64
        binary_with_metadata_base64 = base64.b64encode(
            binary_with_metadata).decode()
        signature_base64 = base64.b64encode(signature).decode()

        # # Print or send binary_with_metadata, signature, public_key (in a real scenario)
        # print("Binary with Metadata:", binary_with_metadata_base64)
        # print("Signature:", signature_base64)
        # print("Public Key:", public_key.public_bytes(encoding=serialization.Encoding.PEM,
        #       format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())

        # Prepare payload (including device fingerprint for server-side verification)
        payload = {
            "user_IP": user_IP,
            "SiteKey": SiteKey,
            "WebsiteName": WebsiteName,
            "binary_with_metadata": binary_with_metadata_base64,
            "signature": signature_base64,
            "public_key": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
            "device_fingerprint": device_fingerprint  # Include device fingerprint in payload
        }

        # Convert payload to JSON format
        payload_json_from_client_to_captchaServer = json.dumps(payload)

        # Simulate sending the payload (in real scenario, you would send it over a network)
        # print("1- Payload JSON:", payload_json_from_client_to_captchaServer)

        return payload_json_from_client_to_captchaServer
    # if camera is not detected the moving to else part
    else:
        print("No camera on current device")
# *************************************UserSide function ends****************************

############################################## THE REAL DEAL ###############################################

# after clicking the "button" in the index.html it will be routed tho this function.


@app.route('/shell', methods=["GET", "POST"])
def run_script():
    if request.method == "POST":
        # 1: UserSide
        # Received Site Key and WebsiteName from website
        SiteKey = "28024d2408754883a7eff1db9cea2b00"
        WebsiteName = "microsoft.com"
        payload_json_from_client_to_captchaServer = userSide(
            SiteKey, WebsiteName)
        
        # Check if camera access failed
        if payload_json_from_client_to_captchaServer is None:
            return jsonify({
                "error": "Camera access failed. Please ensure camera permissions are granted.",
                "message": "On macOS: System Preferences > Security & Privacy > Privacy > Camera > Enable Terminal/Python"
            }), 500

        # 2: Thermal Captcha SERVER side
        # Process the payload
        conn = sqlite3.connect('thermal_captcha.db')
        cursor = conn.cursor()
        # img, foundLabel, conf, payload_json_from_captchaServer_to_user = process_payload(
        #     payload_json_from_client_to_captchaServer, cursor, conn)
        result = process_payload(
            payload_json_from_client_to_captchaServer, cursor, conn)
        if result is not None:
            img, foundLabel, conf, payload_json_from_captchaServer_to_user = result
        else:
            # Handle the case where process_payload returns None
            conn.close()
            return jsonify({
                "error": "Failed to process payload. Image may not be a valid thermal image or processing failed."
            }), 500
        conn.close()

        # User
        # (User-side receives the token from Thermal-CAPTCHA-SERVER and forwards it to the website)
        if payload_json_from_captchaServer_to_user is None:
            return jsonify({
                "error": "Failed to generate token from server."
            }), 500
        
        payload = json.loads(payload_json_from_captchaServer_to_user)
        payload_json_from_user_to_website = json.dumps(payload)
        print("3- Payload JSON:", payload_json_from_user_to_website)

        # Website
        # Website received the payload with the token from user and add a additional field (its own shared key) and forward it to server
        # processing payload recived from user
        payload = json.loads(payload_json_from_user_to_website)
        # Secrete and only used with the server to comunicate
        shared_key = "548c8ffd856f4d74a518a63aa9a5d9d2"
        # Add another field to the payload
        payload["shared_key"] = hashlib.sha256(shared_key.encode()).hexdigest()
        # Convert payload to JSON format
        payload_json_from_website_to_captchaServer = json.dumps(payload)
        print("4- Payload JSON:", payload_json_from_website_to_captchaServer)

        # Captcha Serever
        # Processing payload received from website
        payload = json.loads(payload_json_from_website_to_captchaServer)
        encrypted_token_base64 = payload["token"]
        received_shared_key = payload["shared_key"]
        site_key = payload["SiteKey"]
        website_name = payload["WebsiteName"]
        user_IP = payload["user_IP"]
        # Decode Base64 to binary
        encrypted_token = base64.b64decode(encrypted_token_base64)
        conn = sqlite3.connect('thermal_captcha.db')
        cursor = conn.cursor()
        get_shared_key_by_sitekey_func = get_shared_key_by_sitekey2(
            site_key, cursor)
        # print(f"Shared Key for Site Key {site_key}: {get_shared_key_by_sitekey_func}")

        if get_shared_key_by_sitekey_func:
            is_valid, user_id, response = validate_token2(
                encrypted_token, received_shared_key.encode(), get_shared_key_by_sitekey_func.encode(), cursor, conn)
            if is_valid:
                print(f"User ID: {user_id}")
                risk_score = get_detection_results_by_user_id2(user_id, cursor)
                # Token result is sending back to website
                payload_json_from_captchaServer_to_website = {
                    "user_IP": user_IP,
                    "SiteKey": site_key,
                    "WebsiteName": website_name,
                    "Risk_score": risk_score
                }
                # Convert payload to JSON format
                payload_json_from_captchaServer_to_website = json.dumps(
                    payload_json_from_captchaServer_to_website)
                # Simulate sending the payload (in real scenario, you would send it over a network)
                print("5- Payload JSON:",
                      payload_json_from_captchaServer_to_website)
            else:
                print(f"Token validation failed: {response}")
        else:
            print("Failed to retrieve shared key for the site key.")
        conn.close()

        # Website
        payload = json.loads(payload_json_from_captchaServer_to_website)
        site_key = payload["SiteKey"]
        website_name = payload["WebsiteName"]
        user_IP = payload["user_IP"]
        risk_score = payload["Risk_score"]
        print("********************************")
        print("User Risk score of being bot:", risk_score)
        print("********************************")
        # img = cv2.imread('./thermalImage.jpg', -1)
        # # receiving img(image with bounaady box), foundLabel(detected lable from image), conf(confidence on detection)
        # # sending the image to the model for detction. No need for capturing the detection image. I wanted to show the detection result in the browser.
        # img, foundLabel, conf = runModel(img)
        # # cv2.imshow('After sending image to browser', img)
        # # cv2.waitKey(0)
        # Get the application directory and use relative path for macOS compatibility
        app_dir = os.path.dirname(os.path.abspath(__file__))
        detection_image_path = os.path.join(app_dir, "static", "Image", "detection.jpg")
        # Ensure the directory exists
        os.makedirs(os.path.dirname(detection_image_path), exist_ok=True)
        cv2.imwrite(detection_image_path, img)
        return render_template("show.html", label=foundLabel, conf=conf)
    return render_template("index.html")


# Didn't use in the final system.
@app.route('/test', methods=['GET', 'POST'])
def test():
    print("log: got at test", file=sys.stderr)
    return jsonify({'status': 'succces'})

# By default it will load index.html


@app.route('/')
def home():
    return render_template('./index.html')


@app.after_request
def after_request(response):
    print("log: setting cors", file=sys.stderr)
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers',
                         'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response


# for debugging "python3 app.py"
if __name__ == '__main__':
    app.run(debug=True)
