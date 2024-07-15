import jwt
import datetime
from cryptography.fernet import Fernet
import base64
import os
import hmac
import uuid

# Load keys from environment variables

# SERVER_SECRET_KEY = '9a61f13c92a04010b0f87a15734673c8'
# SHARED_KEY = '548c8ffd856f4d74a518a63aa9a5d9d2'

# Load keys from environment variables
SERVER_SECRET_KEY = '9a61f13c92a04010b0f87a15734673c8'.encode()  # Ensure it's in bytes
SHARED_KEY = '548c8ffd856f4d74a518a63aa9a5d9d2'.encode()  # Ensure it's in bytes

# In-memory store for used nonces
used_nonces = set()

def derive_combined_key(server_key, shared_key):
    """
    Derives a combined key using HMAC with SHA-256.
    """
    return base64.urlsafe_b64encode(hmac.new(server_key, shared_key, digestmod='sha256').digest())

def generate_token(user_id):
    """
    Generates a JWT with an expiration time, a custom claim, and a nonce.
    """
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=2)
    nonce = os.urandom(16).hex()
    token_payload = {
        'exp': expiration_time,
        'result_row_number': user_id,
        'nonce': nonce
    }
    token = jwt.encode(token_payload, SERVER_SECRET_KEY, algorithm='HS256')
    return token

def encrypt_token(token, shared_key):
    """
    Encrypts the JWT using a combined key derived from the server and shared keys.
    """
    combined_key = derive_combined_key(SERVER_SECRET_KEY, shared_key)
    fernet_combined = Fernet(combined_key)
    encrypted_token = fernet_combined.encrypt(token.encode())
    return encrypted_token

def decrypt_token(encrypted_token, shared_key):
    """
    Decrypts the token using a combined key derived from the server and shared keys.
    """
    combined_key = derive_combined_key(SERVER_SECRET_KEY, shared_key)
    fernet_combined = Fernet(combined_key)
    decrypted_token = fernet_combined.decrypt(encrypted_token).decode()
    return decrypted_token

def validate_token(encrypted_token, shared_key):
    """
    Validates the token by decrypting it, checking its validity, and ensuring the nonce has not been used before.
    """
    if not hmac.compare_digest(shared_key, SHARED_KEY):
        return False, "Invalid shared key"

    try:
        token = decrypt_token(encrypted_token, shared_key)
        decoded = jwt.decode(token, SERVER_SECRET_KEY, algorithms=['HS256'])

        # Check if the nonce has been used before
        nonce = decoded.get('nonce')
        if nonce in used_nonces:
            return False, "Replay attack detected: nonce already used"
        used_nonces.add(nonce)

        return True, decoded
    except jwt.ExpiredSignatureError:
        return False, "Token has expired"
    except jwt.InvalidTokenError:
        return False, "Invalid token"
    except Exception as e:
        return False, str(e)

# Simulate generating a token and sending it to the website
result_row_number = 123  # Example result row number
token = generate_token(result_row_number)
encrypted_token = encrypt_token(token, SHARED_KEY)#use database to get the shared key
print(f"Generated Encrypted Token: {encrypted_token}")

# Simulate the website sending the encrypted token back to the server with the shared key
is_valid, response = validate_token(encrypted_token, SHARED_KEY)
print(f"Token validation result: {is_valid}, Response: {response}")

# # Simulate a replay attack by validating the same token again
# is_valid, response = validate_token(encrypted_token, SHARED_KEY)
# print(f"Token validation result after replay attack: {is_valid}, Response: {response}")

# Simulate the token being expired
import time
# # Uncomment the line below to test token expiration
# time.sleep(121)  # Wait for 2 minutes and 1 second

# is_valid, response = validate_token(encrypted_token, SHARED_KEY)
# print(f"Token validation result after expiration: {is_valid}, Response: {response}")
