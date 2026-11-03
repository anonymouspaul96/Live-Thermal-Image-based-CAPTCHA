"""Standalone demo of the context-bound, single-use ThermoCAPTCHA token.

Runs the token part of the protocol (``../thermocaptcha_protocol.py``) against a
temporary copy of the database. It shows one legitimate redemption, then a
replay, a relay from another device, and a forged website proof, all rejected.
Secrets come from the environment (random demo values are generated if unset).

    python tokenizer.py [path/to/thermal_image.bmp]
"""
import json
import os
import shutil
import sys
import tempfile

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(APP_DIR))
import thermocaptcha_protocol as tp  # noqa: E402
from thermalImageChecker import is_thermal_image  # noqa: E402

SITE_KEY, WEBSITE_NAME = "28024d2408754883a7eff1db9cea2b00", "microsoft.com"
USER_IP, USER_UA = "127.0.0.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def main(image_path):
    tp.ensure_demo_secrets(SITE_KEY)
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "demo.db")
        shutil.copy(os.path.join(APP_DIR, "thermal_captcha.db"), db)
        server = tp.ThermoCaptchaServer(db, detector=is_thermal_image)
        website = tp.Website(SITE_KEY, WEBSITE_NAME, tp.load_website_secret())
        user = tp.ThermoCaptchaClient(tp.load_or_create_device_key(os.path.join(tmp, "device.pem")))
        other = tp.ThermoCaptchaClient(tp.rsa.generate_private_key(public_exponent=65537, key_size=2048))

        with open(image_path, "rb") as f:
            image = f.read()
        capture = server.verify_capture(
            user.build_capture_payload(server.issue_challenge(SITE_KEY), image), USER_IP, USER_UA)
        print("token issued:", capture.ok, capture.reason)
        if not capture.ok:
            return
        token = capture.data["response_json"]

        user_payload = user.build_redemption_payload(token)
        relay = server.redeem_token(website.build_server_request(
            other.build_redemption_payload(token), "10.0.0.7", "curl/8.0"))
        forged = server.redeem_token(tp.Website(SITE_KEY, WEBSITE_NAME, b"wrong-key").build_server_request(
            user_payload, USER_IP, USER_UA))
        legit = server.redeem_token(website.build_server_request(user_payload, USER_IP, USER_UA))
        replay = server.redeem_token(website.build_server_request(user_payload, USER_IP, USER_UA))
        for name, res in [("relay from other device", relay), ("forged website proof", forged),
                          ("legitimate redemption", legit), ("replay of redeemed token", replay)]:
            print(f"{name:<26} accepted={res.ok!s:<5} {res.reason}")
        if legit.ok:
            print("risk score:", json.loads(legit.data["response_json"])["Risk_score"])
        server.close()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(APP_DIR), "25.bmp"))
