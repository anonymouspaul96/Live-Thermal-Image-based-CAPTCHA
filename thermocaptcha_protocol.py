"""ThermoCAPTCHA protocol (revised, context-bound tokens).

Single source of truth for the client, CAPTCHA-server and website roles used by
``Final_code.ipynb`` and the RQ2 security notebooks
(``security_attack_test.ipynb`` and ``captcha_farm_attack_simulation.ipynb``).

Protocol summary
----------------
1. Server -> client : fresh challenge C (challenge_id, nonce, SiteKey, issued_at,
                      ttl) and session id ``sid``. Both are stored server-side.
2. Client           : captures thermal image I and signs, with its persistent
                      RSA key pk_d / sk_d,
                          sigma = Sign_sk_d( H(C || sid || H(I) || pk_d) ).
                      The client does NOT send a device fingerprint.
3. Server           : checks C/sid against its own record (issued, unused,
                      fresh), verifies sigma, consumes the challenge, then runs
                      human-presence detection. It derives the fingerprint from
                      values it observes itself:
                          F_d = H(IP_obs || UA_obs || H(pk_d))
                      stores F_d with the verified session, and issues a
                      context-bound token
                          JWT_HS256{sessionID, device_fingerprint, nonce, exp,
                                    SiteKey}  wrapped with Fernet.
4. Client -> website: token + redemption proof
                          rho = Sign_sk(H("redeem" || H(token) || SiteKey || pk)).
5. Website -> server: token, observed user IP/UA, pk, rho, plus a fresh proof
                          HMAC_K_site(siteID || nonce || timestamp || H(body)).
6. Server           : rejects stale / replayed / forged website requests,
                      decrypts + verifies the token, checks SiteKey, expiry and
                      sessionID, verifies rho under pk_current, recomputes
                          F_current = H(IP_cur || UA_cur || H(pk_current))
                      and accepts only if F_current == F_token == F_session.
                      Finally the token nonce is consumed (single use).

Secrets are read from environment variables (never hard-coded):
    THERMOCAPTCHA_SERVER_SECRET   server JWT / token-wrapping secret
    THERMOCAPTCHA_SITE_SECRETS    JSON {SiteKey: K_site} held by the server
    THERMOCAPTCHA_WEBSITE_SECRET  K_site held by the (single) demo website
    THERMOCAPTCHA_DEVICE_KEY_PASSPHRASE  optional passphrase for the client key

The client key is a persistent, software-held RSA-2048 key. It is NOT hardware
bound; see ``load_or_create_device_key`` for details.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import stat
import time
import uuid
import warnings
from dataclasses import dataclass
from typing import Callable, Optional

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
PROTOCOL_VERSION = "thermocaptcha-v2"
CHALLENGE_TTL_SECONDS = 120          # challenge validity window
TOKEN_TTL_SECONDS = 120              # JWT exp
WEBSITE_REQUEST_MAX_SKEW_SECONDS = 60  # accepted |now - website timestamp|
RSA_KEY_SIZE = 2048

ENV_SERVER_SECRET = "THERMOCAPTCHA_SERVER_SECRET"
ENV_SITE_SECRETS = "THERMOCAPTCHA_SITE_SECRETS"
ENV_WEBSITE_SECRET = "THERMOCAPTCHA_WEBSITE_SECRET"
ENV_DEVICE_KEY_PASSPHRASE = "THERMOCAPTCHA_DEVICE_KEY_PASSPHRASE"

REQUIRED_TOKEN_CLAIMS = ("exp", "nonce", "sessionID", "device_fingerprint", "SiteKey")

# Server checks that ablation.ipynb can switch off one at a time (never in normal use).
ABLATION_CHECKS = {
    "challenge_record": "C and sid must match the server-issued challenge record",
    "challenge_single_use": "each challenge can be verified only once",
    "challenge_freshness": "challenge must be younger than its TTL (server clock)",
    "capture_signature": "client signature over H(C || sid || H(I) || pk_d)",
    "website_freshness": "website request timestamp within the allowed skew",
    "website_mac": "HMAC_K_site proof on the website request",
    "website_nonce": "website request nonce is single use",
    "session_binding": "sessionID must exist in VerifiedSession for this SiteKey",
    "key_possession": "redemption proof signed by the presented public key",
    "context_binding": "F_current = F_token = F_session",
    "token_single_use": "token nonce is consumed on redemption",
}

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #
def H(data: bytes) -> bytes:
    """SHA-256."""
    return hashlib.sha256(data).digest()


def concat(*parts) -> bytes:
    """Unambiguous ``a || b || ...``: each part is 4-byte length-prefixed."""
    out = bytearray()
    for p in parts:
        if isinstance(p, str):
            p = p.encode("utf-8")
        out += len(p).to_bytes(4, "big") + p
    return bytes(out)


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def public_key_der(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def load_public_key(pem: str):
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < RSA_KEY_SIZE:
        raise ValueError("public key must be RSA >= 2048 bits")
    return key


def compute_device_fingerprint(ip: str, user_agent: str, public_key) -> str:
    """F_d = H(IP || UA || H(pk_d)); always computed by the server."""
    return H(concat(ip or "", user_agent or "", H(public_key_der(public_key)))).hex()


def capture_digest(challenge: dict, session_id: str, image_bytes: bytes, public_key) -> bytes:
    """H(C || sid || H(I) || pk_d) -- the value the client signs."""
    return H(concat(canonical_json(challenge), session_id, H(image_bytes), public_key_der(public_key)))


def redemption_digest(token_b64: str, site_key: str, public_key) -> bytes:
    """H("redeem" || H(token) || SiteKey || pk) -- client proof of key possession at redemption."""
    return H(concat(PROTOCOL_VERSION + "/redeem", H(token_b64.encode()), site_key, public_key_der(public_key)))


def _sign(private_key, digest: bytes) -> str:
    return base64.b64encode(private_key.sign(digest, _PSS, Prehashed(hashes.SHA256()))).decode()


def _verify(public_key, signature_b64: str, digest: bytes) -> bool:
    try:
        public_key.verify(base64.b64decode(signature_b64), digest, _PSS, Prehashed(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# Secrets (environment only)
# --------------------------------------------------------------------------- #
def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing secret: set environment variable {name}")
    return value


def load_server_secret() -> bytes:
    return _require_env(ENV_SERVER_SECRET).encode()


def load_site_secrets() -> dict:
    """Server-side map SiteKey -> K_site (bytes)."""
    raw = json.loads(_require_env(ENV_SITE_SECRETS))
    return {k: v.encode() for k, v in raw.items()}


def load_website_secret() -> bytes:
    return _require_env(ENV_WEBSITE_SECRET).encode()


def ensure_demo_secrets(site_key: str) -> None:
    """For notebooks/experiments only: if secrets are not configured, generate
    random per-process values so the demo runs. Nothing is ever hard-coded and
    the generated values are not printed."""
    generated = []
    if not os.environ.get(ENV_SERVER_SECRET):
        os.environ[ENV_SERVER_SECRET] = secrets.token_hex(32)
        generated.append(ENV_SERVER_SECRET)
    if not os.environ.get(ENV_WEBSITE_SECRET):
        os.environ[ENV_WEBSITE_SECRET] = secrets.token_hex(32)
        generated.append(ENV_WEBSITE_SECRET)
    site_map = json.loads(os.environ.get(ENV_SITE_SECRETS) or "{}")
    if site_key not in site_map:
        site_map[site_key] = os.environ[ENV_WEBSITE_SECRET]
        os.environ[ENV_SITE_SECRETS] = json.dumps(site_map)
        generated.append(f"{ENV_SITE_SECRETS}[{site_key}]")
    if generated:
        print("NOTE: generated ephemeral demo secrets for: " + ", ".join(generated)
              + " (set them in the environment for a real deployment).")


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
def load_or_create_device_key(path: str, passphrase: Optional[bytes] = None):
    """Persistent client RSA key pair.

    The key is created once and reused for every challenge from this device.
    It is a *software* key: stored as PKCS#8 PEM with file mode 0600, and
    encrypted at rest if a passphrase is supplied (argument or
    THERMOCAPTCHA_DEVICE_KEY_PASSPHRASE). Python offers no non-exportable key
    store, so this is NOT hardware-bound. In a browser deployment the same role
    is played by a WebCrypto key generated with ``extractable: false`` and kept
    in IndexedDB; TPM/WebAuthn-backed keys are optional deployment hardening.
    """
    if passphrase is None and os.environ.get(ENV_DEVICE_KEY_PASSPHRASE):
        passphrase = os.environ[ENV_DEVICE_KEY_PASSPHRASE].encode()
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=passphrase)
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    enc = (serialization.BestAvailableEncryption(passphrase) if passphrase
           else serialization.NoEncryption())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


class ThermoCaptchaClient:
    """User device. Holds the persistent key; never computes the fingerprint."""

    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.public_key_pem = public_key_pem(self.public_key)

    def build_capture_payload(self, challenge_response_json: str, image_bytes: bytes) -> str:
        resp = json.loads(challenge_response_json)
        challenge, sid = resp["challenge"], resp["sessionID"]
        signature = _sign(self.private_key, capture_digest(challenge, sid, image_bytes, self.public_key))
        return json.dumps({
            "challenge": challenge,
            "sessionID": sid,
            "thermal_image": base64.b64encode(image_bytes).decode(),
            "public_key": self.public_key_pem,
            "signature": signature,
        })

    def build_redemption_payload(self, token_response_json: str) -> str:
        """Message the client sends to the website with its token."""
        resp = json.loads(token_response_json)
        token, site_key = resp["token"], resp["SiteKey"]
        return json.dumps({
            "SiteKey": site_key,
            "WebsiteName": resp["WebsiteName"],
            "token": token,
            "public_key": self.public_key_pem,
            "redemption_signature": _sign(self.private_key, redemption_digest(token, site_key, self.public_key)),
        })


# --------------------------------------------------------------------------- #
# Website
# --------------------------------------------------------------------------- #
WEBSITE_BODY_FIELDS = ("token", "user_ip", "user_agent", "public_key", "redemption_signature")


def website_mac(k_site: bytes, site_key: str, nonce: str, timestamp: int, body: dict) -> str:
    """HMAC_K_site(siteID || nonce || timestamp || H(body))."""
    body_hash = H(canonical_json({k: body[k] for k in WEBSITE_BODY_FIELDS}))
    return hmac.new(k_site, concat(site_key, nonce, str(int(timestamp)), body_hash), hashlib.sha256).hexdigest()


class Website:
    """Relying website. Observes the user's connection and authenticates each
    redemption request to the CAPTCHA server with a fresh HMAC proof."""

    def __init__(self, site_key: str, website_name: str, k_site: bytes,
                 clock: Callable[[], float] = time.time):
        self.site_key, self.website_name, self._k_site, self.clock = site_key, website_name, k_site, clock

    def build_server_request(self, user_payload_json: str, observed_ip: str, observed_user_agent: str) -> str:
        user = json.loads(user_payload_json)
        body = {
            "token": user["token"],
            "user_ip": observed_ip,              # taken from the user's connection, not from the user payload
            "user_agent": observed_user_agent,   # taken from the request header seen by the website
            "public_key": user["public_key"],
            "redemption_signature": user["redemption_signature"],
        }
        nonce, ts = secrets.token_hex(16), int(self.clock())
        return json.dumps({
            "SiteKey": self.site_key,
            "WebsiteName": self.website_name,
            **body,
            "website_nonce": nonce,
            "timestamp": ts,
            "website_mac": website_mac(self._k_site, self.site_key, nonce, ts, body),
        })


# --------------------------------------------------------------------------- #
# CAPTCHA server
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    ok: bool
    reason: str
    data: Optional[dict] = None


def _default_detector(image):
    from thermalImageChecker import is_thermal_image
    return is_thermal_image(image)


class ThermoCaptchaServer:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS CaptchaChallenge (
        ChallengeID TEXT PRIMARY KEY,
        SessionID   TEXT NOT NULL UNIQUE,
        Nonce       TEXT NOT NULL UNIQUE,
        SiteKey     TEXT NOT NULL,
        ChallengeJSON TEXT NOT NULL,
        IssuedAt    REAL NOT NULL,
        ExpiresAt   REAL NOT NULL,
        Status      TEXT NOT NULL DEFAULT 'issued'
    );
    CREATE TABLE IF NOT EXISTS VerifiedSession (
        SessionID   TEXT PRIMARY KEY,
        ChallengeID TEXT NOT NULL UNIQUE,
        UserID      INTEGER NOT NULL,
        SiteKey     TEXT NOT NULL,
        DeviceFingerprint TEXT NOT NULL,
        PublicKeySHA256   TEXT NOT NULL,
        CreatedAt   REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS WebsiteRequestNonce (
        Nonce     TEXT PRIMARY KEY,
        SiteKey   TEXT NOT NULL,
        Timestamp REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS TokenNonce (
        UniqueID INTEGER PRIMARY KEY AUTOINCREMENT,
        Token TEXT NOT NULL,
        Nonce TEXT NOT NULL UNIQUE,
        Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """

    def __init__(self, db_path: str, server_secret: Optional[bytes] = None,
                 site_secrets: Optional[dict] = None,
                 detector: Callable = _default_detector,
                 clock: Callable[[], float] = time.time,
                 risk_score_on_pass: int = 85, verbose: bool = False,
                 scorer: Optional[Callable] = None,
                 disabled_checks=()):
        """``scorer(image) -> number`` optionally replaces the fixed risk score
        (e.g. the YOLO confidence used by the Flask app).

        ``disabled_checks`` exists ONLY for the ablation study
        (``ablation.ipynb``); it must stay empty in every other use. Valid
        names are listed in ``ABLATION_CHECKS``."""
        unknown = set(disabled_checks) - set(ABLATION_CHECKS)
        if unknown:
            raise ValueError(f"unknown ablation checks: {sorted(unknown)}")
        self.disabled = frozenset(disabled_checks)
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(self.SCHEMA)
        self.conn.commit()
        self._secret = server_secret if server_secret is not None else load_server_secret()
        self._site_secrets = site_secrets if site_secrets is not None else load_site_secrets()
        self.detector, self.clock, self.scorer = detector, clock, scorer
        self.risk_score_on_pass, self.verbose = risk_score_on_pass, verbose
        self.last_image = None

    def close(self):
        self.conn.close()

    def _on(self, check: str) -> bool:
        return check not in self.disabled

    def _log(self, msg):
        if self.verbose:
            print(msg)

    # ---------------- Phase 1: issue challenge / session ----------------- #
    def issue_challenge(self, site_key: str, now: Optional[float] = None) -> str:
        if self._website_name(site_key) is None or site_key not in self._site_secrets:
            raise ValueError("unknown SiteKey or no K_site configured for it")
        now = self.clock() if now is None else now
        challenge = {
            "challenge_id": str(uuid.uuid4()),
            "nonce": secrets.token_hex(16),
            "SiteKey": site_key,
            "issued_at": int(now),
            "expires_in_seconds": CHALLENGE_TTL_SECONDS,
        }
        sid = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO CaptchaChallenge (ChallengeID, SessionID, Nonce, SiteKey, ChallengeJSON, IssuedAt, ExpiresAt)"
            " VALUES (?,?,?,?,?,?,?)",
            (challenge["challenge_id"], sid, challenge["nonce"], site_key,
             canonical_json(challenge).decode(), now, now + CHALLENGE_TTL_SECONDS))
        self.conn.commit()
        self._log(f"Issued challenge {challenge['challenge_id']} / sessionID {sid}")
        return json.dumps({"challenge": challenge, "sessionID": sid})

    # ---------------- Phase 3: verify capture, issue token --------------- #
    def verify_capture(self, payload_json: str, observed_ip: str, observed_user_agent: str) -> Result:
        """``observed_ip``/``observed_user_agent`` are what the server sees on the
        incoming connection (e.g. request.remote_addr / User-Agent header)."""
        try:
            p = json.loads(payload_json)
            challenge, sid = p["challenge"], p["sessionID"]
            image_bytes = base64.b64decode(p["thermal_image"], validate=True)
            pk = load_public_key(p["public_key"])
            signature = p["signature"]
            cid = challenge["challenge_id"]
        except Exception as e:  # malformed input
            return Result(False, f"malformed payload: {type(e).__name__}")

        row = self.conn.execute(
            "SELECT SessionID, SiteKey, ChallengeJSON, ExpiresAt, Status FROM CaptchaChallenge WHERE ChallengeID=?",
            (cid,)).fetchone()
        if row is None:
            return Result(False, "unknown challenge (not issued by server)")
        stored_sid, site_key, stored_json, expires_at, status = row
        if self._on("challenge_record"):
            if canonical_json(challenge).decode() != stored_json:
                return Result(False, "challenge does not match server record")
            if not hmac.compare_digest(sid, stored_sid):
                return Result(False, "sessionID does not match challenge")
        if self._on("challenge_single_use") and status != "issued":
            return Result(False, "challenge already used (replay)")
        if self._on("challenge_freshness") and self.clock() > expires_at:
            return Result(False, "challenge expired")

        if self._on("capture_signature") and not _verify(
                pk, signature, capture_digest(challenge, sid, image_bytes, pk)):
            return Result(False, "invalid signature")

        # One verification attempt per challenge: consume atomically before inference.
        cur = self.conn.execute(
            "UPDATE CaptchaChallenge SET Status='consumed' WHERE ChallengeID=? AND Status='issued'", (cid,))
        self.conn.commit()
        if self._on("challenge_single_use") and cur.rowcount != 1:
            return Result(False, "challenge already used (replay)")
        self._log(f"Signature verified for challenge {cid}")

        # Human-presence detection only after all cryptographic checks.
        try:
            from PIL import Image
            image = Image.open(io.BytesIO(image_bytes))
            image.load()
            detection = self.detector(image)
        except Exception as e:
            return Result(False, f"image processing error: {type(e).__name__}")
        if detection != "Thermal Image":
            return Result(False, f"human-presence check failed: {detection}")
        self.last_image = image

        # Server-derived fingerprint from observed context + public key.
        fingerprint = compute_device_fingerprint(observed_ip, observed_user_agent, pk)
        website_name = self._website_name(site_key)
        cur = self.conn.execute("INSERT INTO Users (SiteKey, WebsiteName, UserIPAddress) VALUES (?,?,?)",
                                (site_key, website_name, observed_ip))
        user_id = cur.lastrowid
        score = self.scorer(image) if self.scorer is not None else self.risk_score_on_pass
        self.conn.execute("INSERT INTO Detections (UserID, Result) VALUES (?,?)", (user_id, score))
        # (OR REPLACE is reachable only in the challenge_single_use ablation, where a replayed
        #  challenge re-creates its session.)
        self.conn.execute(
            ("INSERT INTO" if self._on("challenge_single_use") else "INSERT OR REPLACE INTO") +
            " VerifiedSession (SessionID, ChallengeID, UserID, SiteKey, DeviceFingerprint, PublicKeySHA256, CreatedAt)"
            " VALUES (?,?,?,?,?,?,?)",
            (sid, cid, user_id, site_key, fingerprint, H(public_key_der(pk)).hex(), self.clock()))
        self.conn.commit()
        self._log(f"Human presence: {detection}; F_session={fingerprint[:16]}... stored for sessionID {sid}")

        token_b64 = self._issue_token(user_id, site_key, sid, fingerprint)
        return Result(True, "accepted", {
            "response_json": json.dumps({"SiteKey": site_key, "WebsiteName": website_name, "token": token_b64}),
            "sessionID": sid, "device_fingerprint": fingerprint, "user_id": user_id,
        })

    # ---------------- Token construction (HS256 JWT + Fernet) ------------ #
    def _fernet(self, site_key: str) -> Fernet:
        k_site = self._site_secrets[site_key]
        return Fernet(base64.urlsafe_b64encode(hmac.new(self._secret, k_site, hashlib.sha256).digest()))

    def _issue_token(self, user_id: int, site_key: str, sid: str, fingerprint: str) -> str:
        now = _dt.datetime.fromtimestamp(self.clock(), _dt.timezone.utc)
        claims = {
            "sessionID": sid,
            "device_fingerprint": fingerprint,
            "nonce": secrets.token_hex(16),
            "iat": now,
            "exp": now + _dt.timedelta(seconds=TOKEN_TTL_SECONDS),
            "SiteKey": site_key,
            "result_row_number": user_id,
        }
        jwt_token = jwt.encode(claims, self._secret, algorithm="HS256")
        if isinstance(jwt_token, str):  # PyJWT >= 2 returns str, 1.x returns bytes
            jwt_token = jwt_token.encode()
        return base64.b64encode(self._fernet(site_key).encrypt(jwt_token)).decode()

    # ---------------- Phase 6: redeem token ------------------------------ #
    def redeem_token(self, request_json: str) -> Result:
        try:
            r = json.loads(request_json)
            site_key, nonce, ts, mac = r["SiteKey"], r["website_nonce"], int(r["timestamp"]), r["website_mac"]
            body = {k: r[k] for k in WEBSITE_BODY_FIELDS}
        except Exception as e:
            return Result(False, f"malformed request: {type(e).__name__}")

        # (1) Website authentication: fresh HMAC proof, no replays.
        k_site = self._site_secrets.get(site_key)
        if k_site is None:
            return Result(False, "unknown SiteKey")
        if self._on("website_freshness") and abs(self.clock() - ts) > WEBSITE_REQUEST_MAX_SKEW_SECONDS:
            return Result(False, "website request expired")
        if self._on("website_mac") and not hmac.compare_digest(
                str(mac), website_mac(k_site, site_key, nonce, ts, body)):
            return Result(False, "invalid website proof")
        if self._on("website_nonce"):
            try:
                self.conn.execute("INSERT INTO WebsiteRequestNonce (Nonce, SiteKey, Timestamp) VALUES (?,?,?)",
                                  (nonce, site_key, ts))
                self.conn.commit()
            except sqlite3.IntegrityError:
                return Result(False, "website request replayed")

        # (2) Token integrity, expiry and SiteKey.
        try:
            jwt_token = self._fernet(site_key).decrypt(base64.b64decode(body["token"])).decode()
            claims = jwt.decode(jwt_token, self._secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return Result(False, "token expired")
        except (InvalidToken, jwt.InvalidTokenError, ValueError) as e:
            return Result(False, f"invalid token: {type(e).__name__}")
        missing = [c for c in REQUIRED_TOKEN_CLAIMS if claims.get(c) is None]
        if missing:
            return Result(False, f"invalid token: missing claims {missing}")
        if claims["SiteKey"] != site_key:
            return Result(False, "token SiteKey mismatch")
        f_token = claims["device_fingerprint"]

        # (3) Session lookup.
        if self._on("session_binding"):
            row = self.conn.execute(
                "SELECT UserID, SiteKey, DeviceFingerprint FROM VerifiedSession WHERE SessionID=?",
                (claims["sessionID"],)).fetchone()
            if row is None:
                return Result(False, "unknown sessionID")
            user_id, session_site, f_session = row
            if session_site != site_key:
                return Result(False, "session SiteKey mismatch")
        else:
            user_id, f_session = claims.get("result_row_number"), f_token

        # (4) Proof of possession of pk_current, then server-side F_current.
        try:
            pk_current = load_public_key(body["public_key"])
        except Exception:
            return Result(False, "invalid public key")
        if self._on("key_possession") and not _verify(
                pk_current, body["redemption_signature"],
                redemption_digest(body["token"], site_key, pk_current)):
            return Result(False, "invalid redemption proof (key possession)")
        f_current = compute_device_fingerprint(body["user_ip"], body["user_agent"], pk_current)
        if self._on("context_binding") and not (
                hmac.compare_digest(f_current, f_token) and hmac.compare_digest(f_token, f_session)):
            return Result(False, "context mismatch: F_current != F_token or F_token != F_session")

        # (5) Single use: atomically consume the token nonce.
        if self._on("token_single_use"):
            try:
                self.conn.execute("INSERT INTO TokenNonce (Token, Nonce) VALUES (?,?)",
                                  (claims["sessionID"], claims["nonce"]))
                self.conn.commit()
            except sqlite3.IntegrityError:
                return Result(False, "token replayed (nonce already consumed)")

        risk = self.conn.execute("SELECT Result FROM Detections WHERE UserID=? ORDER BY UniqueID LIMIT 1",
                                 (user_id,)).fetchone()
        self._log(f"Token accepted: sessionID={claims['sessionID'][:8]}..., F={f_current[:16]}...")
        return Result(True, "accepted", {
            "response_json": json.dumps({
                "SiteKey": site_key, "WebsiteName": r.get("WebsiteName"),
                "user_IP": body["user_ip"], "Risk_score": risk[0] if risk else None}),
            "sessionID": claims["sessionID"], "user_id": user_id,
        })

    # ---------------- helpers -------------------------------------------- #
    def _website_name(self, site_key: str):
        row = self.conn.execute("SELECT WebsiteName FROM ServerVSWebsite WHERE SiteKey=?", (site_key,)).fetchone()
        return row[0] if row else None
