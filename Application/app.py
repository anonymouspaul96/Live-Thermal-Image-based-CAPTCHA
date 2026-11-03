"""ThermoCAPTCHA Flask demo.

All three roles (user device, CAPTCHA server, website) run in this one process
for the demo, but each step uses the shared protocol implementation in
``../thermocaptcha_protocol.py``. That is the same code used by
``Final_code.ipynb`` and the RQ2 / ablation notebooks.

Secrets come from environment variables (see the repository README):
    THERMOCAPTCHA_SERVER_SECRET, THERMOCAPTCHA_SITE_SECRETS,
    THERMOCAPTCHA_WEBSITE_SECRET, [THERMOCAPTCHA_DEVICE_KEY_PASSPHRASE]
If they are unset, random per-process demo values are generated.
"""
import json
import os
import sys
import time

import cv2
import pygame
import pygame.camera
from flask import Flask, jsonify, render_template, request

from thermalImageChecker import is_thermal_image
from yolo_detection_images import runModel

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(APP_DIR))          # repository root holds thermocaptcha_protocol.py
import thermocaptcha_protocol as tp  # noqa: E402

app = Flask(__name__)

# Public identifiers (not secrets).
SITE_KEY = os.environ.get("THERMOCAPTCHA_SITE_KEY", "28024d2408754883a7eff1db9cea2b00")
WEBSITE_NAME = os.environ.get("THERMOCAPTCHA_WEBSITE_NAME", "microsoft.com")
DB_PATH = os.path.join(APP_DIR, "thermal_captcha.db")
DEVICE_KEY_PATH = os.path.join(APP_DIR, "device_keys", "client_device_key.pem")

# Camera selection preference
# IMPORTANT: On macOS, pygame camera names don't match actual cameras!
# Based on testing:
#   - Camera 0 = PureThermal (but pygame reports it as "FaceTime HD Camera")
#   - Camera 1 = iPhone (but pygame reports it as "PureThermal")
#   - Camera 2 = FaceTime (but pygame reports it as "iPhone")
# Options: integer index, or None for the first available camera.
PREFERRED_CAMERA_INDEX = 0

tp.ensure_demo_secrets(SITE_KEY)
website = tp.Website(SITE_KEY, WEBSITE_NAME, tp.load_website_secret())
# Persistent client key (created once, reused). Software key, not hardware-bound.
client = tp.ThermoCaptchaClient(tp.load_or_create_device_key(DEVICE_KEY_PATH))


# ****************************** User side: thermal capture ******************************
def capture_thermal_frame():
    """Capture one frame from the thermal camera and return it as JPEG bytes (or None)."""
    try:
        pygame.camera.init()
    except Exception as e:
        print(f"Error initializing pygame camera: {e}")
        print("On macOS, grant camera permission to Terminal/Python "
              "(System Settings > Privacy & Security > Camera).")
        return None

    try:
        camlist = pygame.camera.list_cameras()
    except Exception as e:
        print(f"Error listing cameras: {e}")
        return None
    if not camlist:
        print("No camera on current device")
        return None

    if isinstance(PREFERRED_CAMERA_INDEX, int) and PREFERRED_CAMERA_INDEX < len(camlist):
        camera_index = PREFERRED_CAMERA_INDEX
    else:
        camera_index = 0
    print(f"Using camera index {camera_index} (pygame reports: '{camlist[camera_index]}'); "
          f"available: {[f'{i}: {c}' for i, c in enumerate(camlist)]}")

    try:
        cam = pygame.camera.Camera(camlist[camera_index], (640, 480))
        cam.start()
        time.sleep(1.5 if camera_index == 0 else 0.5)   # PureThermal needs longer to warm up
    except Exception as e:
        print(f"Error starting camera {camera_index}: {e}")
        return None

    try:
        image = cam.get_image()
        thermal_image_path = os.path.join(APP_DIR, "thermalImage.jpg")
        pygame.image.save(image, thermal_image_path)
    except Exception as e:
        print(f"Error capturing/saving image: {e}")
        return None
    finally:
        cam.stop()

    with open(thermal_image_path, "rb") as f:
        return f.read()


# ****************************** CAPTCHA server: YOLO risk score **************************
def make_yolo_scorer(store):
    """Risk score = YOLOv4-tiny person confidence x 100. It runs only after the
    protocol's cryptographic checks and the thermal-image check pass."""
    def scorer(image):
        path = os.path.join(APP_DIR, "encoded_image_only_timestamp_nonce.jpg")
        image.convert("RGB").save(path)
        img, found_label, conf = runModel(cv2.imread(path, -1))
        store.update(img=img, label=found_label, conf=conf * 100)
        return conf * 100
    return scorer


def error(message, status, reason=None):
    body = {"error": message}
    if reason:
        body["reason"] = reason
    return jsonify(body), status


# ************************************* Flask routes ***************************************
@app.route('/shell', methods=["GET", "POST"])
def run_script():
    if request.method != "POST":
        return render_template("index.html")

    # Context the server observes on the incoming connection (not supplied by the client).
    observed_ip = request.remote_addr or "unknown"
    observed_ua = request.headers.get("User-Agent", "Unknown")

    detection = {}
    server = tp.ThermoCaptchaServer(DB_PATH, detector=is_thermal_image,
                                    scorer=make_yolo_scorer(detection), verbose=True)
    try:
        # Phase 1 (server): fresh challenge + session.
        challenge_json = server.issue_challenge(SITE_KEY)

        # Phase 2 (user): capture and sign H(C || sid || H(I) || pk_d).
        image_bytes = capture_thermal_frame()
        if image_bytes is None:
            return error("Camera access failed. Please ensure camera permissions are granted.", 500)
        capture_payload = client.build_capture_payload(challenge_json, image_bytes)

        # Phase 3 (server): verify, detect human presence, derive F_d, issue context-bound token.
        capture = server.verify_capture(capture_payload, observed_ip, observed_ua)
        if not capture.ok:
            return error("Verification failed.", 403, capture.reason)
        print("Token issued for sessionID", capture.data["sessionID"])

        # Phase 4 (user): forward token + proof of key possession to the website.
        user_payload = client.build_redemption_payload(capture.data["response_json"])

        # Phase 5 (website): attach observed context and a fresh HMAC proof.
        website_request = website.build_server_request(user_payload, observed_ip, observed_ua)

        # Phase 6 (server): F_current = F_token = F_session, single use, etc.
        redemption = server.redeem_token(website_request)
        if not redemption.ok:
            return error("Token validation failed.", 403, redemption.reason)
        risk_score = json.loads(redemption.data["response_json"])["Risk_score"]
    finally:
        server.close()

    # Phase 7 (website): apply policy using the risk score.
    print("********************************")
    print("User Risk score of being bot:", risk_score)
    print("********************************")

    detection_image_path = os.path.join(APP_DIR, "static", "Image", "detection.jpg")
    os.makedirs(os.path.dirname(detection_image_path), exist_ok=True)
    cv2.imwrite(detection_image_path, detection["img"])
    return render_template("show.html", label=detection["label"], conf=detection["conf"])


# Not used by the final system.
@app.route('/test', methods=['GET', 'POST'])
def test():
    print("log: got at test", file=sys.stderr)
    return jsonify({'status': 'success'})


@app.route('/')
def home():
    return render_template('./index.html')


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response


# for debugging: "python3 app.py"
if __name__ == '__main__':
    app.run(debug=True)
