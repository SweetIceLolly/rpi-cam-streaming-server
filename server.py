"""
server.py
WebSocket FPV server
Copyright (C) 2023  Aiden Bohlander
Copyright (C) 2025  Hanson Liang

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import socket
import ssl
import subprocess
import time
from datetime import datetime
from email.message import EmailMessage

import cv2
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from picamera2 import Picamera2


# Global settings
JPEG_QUALITY = 70
WIDTH = 640
HEIGHT = 480

# Motion detection settings. A low-resolution luminance stream keeps CPU use
# modest enough for a Raspberry Pi 3 B+.
MOTION_MAX_WIDTH = 320
MOTION_MAX_HEIGHT = 240


def load_bounded_number(name, default, minimum, maximum, number_type=float):
    """Load a numeric environment setting and reject unsafe values."""
    value = number_type(os.environ.get(name, default))
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


MOTION_CLEAR_SECONDS = load_bounded_number(
    "MOTION_CLEAR_SECONDS", 60, 1, 86_400
)
MOTION_SAMPLE_INTERVAL_SECONDS = load_bounded_number(
    "MOTION_SAMPLE_INTERVAL_SECONDS", 0.5, 0.2, 10
)
MOTION_PIXEL_THRESHOLD = load_bounded_number(
    "MOTION_PIXEL_THRESHOLD", 25, 1, 255, int
)
MOTION_MIN_AREA_RATIO = load_bounded_number(
    "MOTION_MIN_AREA_RATIO", 0.012, 0.0001, 1
)
MOTION_BACKGROUND_ALPHA = load_bounded_number(
    "MOTION_BACKGROUND_ALPHA", 0.05, 0.001, 1
)
MOTION_WARMUP_FRAMES = load_bounded_number(
    "MOTION_WARMUP_FRAMES", 6, 1, 1000, int
)
MOTION_REQUIRED_FRAMES = load_bounded_number(
    "MOTION_REQUIRED_FRAMES", 2, 1, 100, int
)
MOTION_CAPTURE_DELAY_SECONDS = 5

# Command protocol settings
COMMAND_AAD = b"rpi-camera-command-v1"
RESPONSE_AAD_PREFIX = b"rpi-camera-response-v1:"
PASSWORD_KDF_ITERATIONS = 600_000
MAX_COMMAND_CLOCK_SKEW_SECONDS = 30
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
RESOLUTION_PATTERN = re.compile(r"\b(\d{2,5})x(\d{2,5})\s+\[")


def load_password(password_file, env_var, default_value):
    """Load a password from a file, or fall back to an environment variable."""
    if password_file and os.path.exists(password_file):
        print(f"Loading {env_var} from file.")
        with open(password_file, "r", encoding="utf-8") as password_handle:
            return password_handle.read().strip()
    print(f"{password_file} file not found, using environment/default password.")
    return os.environ.get(env_var, default_value)


def load_optional_secret(value_env_var, file_env_var):
    """Load an optional secret from a named file or environment variable."""
    secret_file = os.environ.get(file_env_var)
    if secret_file:
        with open(secret_file, "r", encoding="utf-8") as secret_handle:
            return secret_handle.read().strip()
    return os.environ.get(value_env_var, "").strip()


def load_or_create_command_private_key(key_path):
    """Load the command RSA key, creating a mode-0600 PKCS8 key if needed."""
    try:
        with open(key_path, "rb") as key_handle:
            private_key = serialization.load_pem_private_key(
                key_handle.read(), password=None
            )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError(f"Command key at {key_path} is not an RSA private key")
        return private_key
    except FileNotFoundError:
        pass

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    try:
        file_descriptor = os.open(
            key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except FileExistsError:
        # Another server process created it while this process generated a key.
        return load_or_create_command_private_key(key_path)

    with os.fdopen(file_descriptor, "wb") as key_handle:
        key_handle.write(private_key_pem)
    print(f"Created command private key at {key_path}")
    return private_key


def discover_camera_resolutions():
    """Return unique camera mode resolutions reported by rpicam-hello."""
    try:
        result = subprocess.run(
            ["rpicam-hello", "--list-cameras"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )
    except (
        FileNotFoundError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"Unable to discover camera resolutions: {error}")
        return []

    resolutions = []
    seen = set()
    for width_text, height_text in RESOLUTION_PATTERN.findall(result.stdout):
        resolution = (int(width_text), int(height_text))
        if resolution not in seen:
            seen.add(resolution)
            resolutions.append(resolution)
    return resolutions


class MotionDetector:
    """Adaptive-background motion detector operating on small grayscale frames."""

    def __init__(self):
        self.background = None
        self.frames_seen = 0

    def reset(self):
        self.background = None
        self.frames_seen = 0

    def detects_motion(self, luminance_frame):
        blurred = cv2.GaussianBlur(luminance_frame, (7, 7), 0)
        if self.background is None:
            self.background = blurred.astype("float32")
            self.frames_seen = 1
            return False

        background_frame = cv2.convertScaleAbs(self.background)
        frame_delta = cv2.absdiff(blurred, background_frame)
        cv2.accumulateWeighted(
            blurred, self.background, MOTION_BACKGROUND_ALPHA
        )
        self.frames_seen += 1
        if self.frames_seen <= MOTION_WARMUP_FRAMES:
            return False

        thresholded = cv2.threshold(
            frame_delta, MOTION_PIXEL_THRESHOLD, 255, cv2.THRESH_BINARY
        )[1]
        thresholded = cv2.dilate(thresholded, None, iterations=2)
        contours = cv2.findContours(
            thresholded, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
        )[-2]
        minimum_area = luminance_frame.size * MOTION_MIN_AREA_RATIO
        return any(cv2.contourArea(contour) >= minimum_area for contour in contours)


def encode_base64(data):
    return base64.b64encode(data).decode("ascii")


def decode_base64(value, field_name, max_decoded_length):
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f"{field_name} is not valid base64") from error
    if len(decoded) > max_decoded_length:
        raise ValueError(f"{field_name} is too large")
    return decoded


# Video encryption settings
encryption_password = load_password("STREAM_PASSWORD", "STREAM_PASSWORD", "changeme")
access_password = load_password("ACCESS_PASSWORD", "ACCESS_PASSWORD", "accessme")
ENCRYPTION_KEY = hashlib.sha256(encryption_password.encode("utf-8")).digest()
AESGCM_CIPHER = AESGCM(ENCRYPTION_KEY)

# Gmail SMTP settings. Prefer GMAIL_APP_PASSWORD_FILE so the app password does
# not appear in shell history or process configuration output.
GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS", "").strip()
GMAIL_APP_PASSWORD = load_optional_secret(
    "GMAIL_APP_PASSWORD", "GMAIL_APP_PASSWORD_FILE"
).replace(" ", "")
MOTION_EMAIL_TO = os.environ.get("MOTION_EMAIL_TO", GMAIL_ADDRESS).strip()
MOTION_EMAIL_SUBJECT = os.environ.get(
    "MOTION_EMAIL_SUBJECT", "Raspberry Pi camera motion detected"
).strip()
MOTION_EMAIL_CONFIGURED = bool(
    GMAIL_ADDRESS and GMAIL_APP_PASSWORD and MOTION_EMAIL_TO
)

# The persistent key allows clients to pin the server identity between restarts.
DEFAULT_COMMAND_KEY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "command_private_key.pem"
)
COMMAND_KEY_PATH = os.environ.get(
    "COMMAND_PRIVATE_KEY_FILE", DEFAULT_COMMAND_KEY_PATH
)
COMMAND_PRIVATE_KEY = load_or_create_command_private_key(COMMAND_KEY_PATH)
COMMAND_PUBLIC_KEY_DER = COMMAND_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
COMMAND_PUBLIC_KEY_PEM = COMMAND_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("ascii")
COMMAND_PUBLIC_KEY_FINGERPRINT = hashlib.sha256(COMMAND_PUBLIC_KEY_DER).hexdigest()
print(f"Command public key fingerprint: {COMMAND_PUBLIC_KEY_FINGERPRINT}")

# The public salt is tied to the persistent server key. Only the PBKDF2 verifier,
# never the user's access password, is sent to the server.
ACCESS_PASSWORD_SALT = hashlib.sha256(
    COMMAND_PUBLIC_KEY_DER + b"rpi-camera-access-password-v1"
).digest()[:16]
ACCESS_PASSWORD_HASH = hashlib.pbkdf2_hmac(
    "sha256",
    access_password.encode("utf-8"),
    ACCESS_PASSWORD_SALT,
    PASSWORD_KDF_ITERATIONS,
    dklen=32,
)
del encryption_password, access_password

AVAILABLE_RESOLUTIONS = discover_camera_resolutions()

# Start video capture with Raspberry Pi camera
camera = Picamera2()


def get_motion_stream_size(width, height):
    """Return an even low-resolution size no larger than the main stream."""
    motion_width = min(MOTION_MAX_WIDTH, width)
    motion_height = min(MOTION_MAX_HEIGHT, height)
    return motion_width - (motion_width % 2), motion_height - (motion_height % 2)


def create_camera_configuration(width, height):
    motion_size = get_motion_stream_size(width, height)
    configuration = camera.create_preview_configuration(
        main={"format": "RGB888", "size": (width, height)},
        lores={"format": "YUV420", "size": motion_size},
    )
    return configuration, motion_size


camera_configuration, motion_stream_size = create_camera_configuration(WIDTH, HEIGHT)
camera.configure(camera_configuration)
camera.start()
camera_lock = asyncio.Lock()

# Motion state is server-wide. The detector task sleeps on this event while
# disarmed and therefore performs no captures or image processing.
motion_armed = False
motion_period_active = False
motion_last_detected_at = None
motion_consecutive_frames = 0
motion_detector = MotionDetector()
motion_armed_event = asyncio.Event()
motion_email_tasks = set()

# Active connections tracking
active_connections = {}  # websocket -> connection_info dict
connection_id_counter = 0

# Access log for authentication attempts
access_log = []  # List of {timestamp, remote_address, success, error}
MAX_ACCESS_LOG_ENTRIES = 100


def log_access_attempt(websocket, success, error=None):
    remote_address = (
        str(websocket.remote_address) if websocket.remote_address else "unknown"
    )
    access_log.append(
        {
            "timestamp": datetime.now().isoformat(),
            "remote_address": remote_address,
            "success": success,
            "error": error,
        }
    )
    while len(access_log) > MAX_ACCESS_LOG_ENTRIES:
        access_log.pop(0)


def decrypt_command_envelope(message):
    """Hybrid-decrypt a command and return its payload, AES key, and request id."""
    if not isinstance(message, str) or len(message) > 100_000:
        raise ValueError("Encrypted command must be bounded JSON text")

    envelope = json.loads(message)
    if not isinstance(envelope, dict) or envelope.get("type") != "encrypted_command":
        raise ValueError("Expected an encrypted command envelope")

    encrypted_key = decode_base64(
        envelope.get("encrypted_key"), "encrypted_key", 1024
    )
    nonce = decode_base64(envelope.get("nonce"), "nonce", 12)
    ciphertext = decode_base64(envelope.get("ciphertext"), "ciphertext", 65_536)
    if len(nonce) != 12:
        raise ValueError("Command nonce must be 12 bytes")

    aes_key = COMMAND_PRIVATE_KEY.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=COMMAND_AAD,
        ),
    )
    if len(aes_key) != 32:
        raise ValueError("Command AES key must be 256 bits")

    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, COMMAND_AAD)
    payload = json.loads(plaintext.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Command payload must be an object")

    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
        raise ValueError("Invalid request id")
    return payload, aes_key, request_id


def validate_authenticated_command(payload, session):
    """Validate password proof, connection binding, freshness, and replay nonce."""
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not hmac.compare_digest(
        session_id, session["id"]
    ):
        raise ValueError("Command belongs to a different connection")

    timestamp = payload.get("timestamp")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ValueError("Invalid command timestamp")
    now = int(time.time())
    if abs(now - timestamp) > MAX_COMMAND_CLOCK_SKEW_SECONDS:
        raise ValueError("Command timestamp is outside the allowed window")

    request_nonce = payload.get("request_nonce")
    if not isinstance(request_nonce, str) or not REQUEST_ID_PATTERN.fullmatch(
        request_nonce
    ):
        raise ValueError("Invalid request nonce")

    supplied_hash = decode_base64(
        payload.get("access_password_hash"), "access_password_hash", 32
    )
    if len(supplied_hash) != 32 or not hmac.compare_digest(
        supplied_hash, ACCESS_PASSWORD_HASH
    ):
        raise ValueError("Invalid access password")

    # A timestamp bounds replays; retaining slightly more than that window catches
    # duplicates without allowing this set to grow for the life of the connection.
    expired_before = now - (MAX_COMMAND_CLOCK_SKEW_SECONDS * 2)
    session["used_nonces"] = {
        nonce: used_at
        for nonce, used_at in session["used_nonces"].items()
        if used_at >= expired_before
    }
    if request_nonce in session["used_nonces"]:
        raise ValueError("Command nonce has already been used")
    session["used_nonces"][request_nonce] = now


async def send_encrypted_response(websocket, aes_key, request_id, payload):
    """Encrypt a response with the one-time AES key from its request."""
    nonce = os.urandom(12)
    aad = RESPONSE_AAD_PREFIX + request_id.encode("ascii")
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
    await websocket.send(
        json.dumps(
            {
                "type": "encrypted_response",
                "request_id": request_id,
                "nonce": encode_base64(nonce),
                "ciphertext": encode_base64(ciphertext),
            },
            separators=(",", ":"),
        )
    )


def motion_status_payload():
    return {
        "motion_armed": motion_armed,
        "motion_email_configured": MOTION_EMAIL_CONFIGURED,
        "motion_clear_seconds": MOTION_CLEAR_SECONDS,
    }


def arm_motion_detection():
    global motion_armed, motion_period_active
    global motion_last_detected_at, motion_consecutive_frames

    if motion_armed:
        return
    motion_detector.reset()
    motion_period_active = False
    motion_last_detected_at = None
    motion_consecutive_frames = 0
    motion_armed = True
    motion_armed_event.set()
    print("Motion detection armed")


def disarm_motion_detection():
    global motion_armed, motion_period_active
    global motion_last_detected_at, motion_consecutive_frames

    motion_armed = False
    motion_armed_event.clear()
    motion_detector.reset()
    motion_period_active = False
    motion_last_detected_at = None
    motion_consecutive_frames = 0
    print("Motion detection disarmed")


def send_motion_email(detected_at, capture):
    """Send one motion alert through Gmail's TLS-protected SMTP endpoint."""
    message = EmailMessage()
    message["From"] = GMAIL_ADDRESS
    message["To"] = MOTION_EMAIL_TO
    message["Subject"] = MOTION_EMAIL_SUBJECT
    message.set_content(
        "Motion was detected by the Raspberry Pi camera.\n\n"
        f"Detected at: {detected_at.isoformat()}\n"
        f"Camera host: {socket.gethostname()}\n\n"
        "Another alert will be eligible only after the configured quiet period."
    )
    message.add_attachment(
        capture,
        maintype="image",
        subtype="jpeg",
        filename=detected_at.strftime("motion-%Y%m%d-%H%M%S.jpg"),
    )

    tls_context = ssl.create_default_context()
    with smtplib.SMTP_SSL(
        "smtp.gmail.com", 465, timeout=20, context=tls_context
    ) as smtp:
        smtp.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        smtp.send_message(message)


async def deliver_motion_email(detected_at, capture):
    try:
        await asyncio.to_thread(send_motion_email, detected_at, capture)
        print(f"Motion notification sent to {MOTION_EMAIL_TO}")
    except Exception as error:
        # This event remains consumed even if delivery fails, which prevents a
        # broken SMTP configuration from creating a rapid retry/spam loop.
        print(f"Unable to send motion notification: {error}")


async def capture_motion_jpeg():
    """Capture and encode the current full-resolution main camera frame."""
    async with camera_lock:
        frame = camera.capture_array("main")
    encode_params = [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY]
    encoded, buffer = cv2.imencode(".jpg", frame, encode_params)
    if not encoded:
        raise RuntimeError("OpenCV could not encode the motion capture")
    return bytes(buffer)


async def capture_and_deliver_motion_email(detected_at):
    """Capture five seconds after detection, then deliver the motion alert."""
    await asyncio.sleep(MOTION_CAPTURE_DELAY_SECONDS)
    try:
        capture = await capture_motion_jpeg()
    except Exception as error:
        # Do not send an incomplete alert: the next motion period can try again
        # after the configured quiet interval.
        print(f"Unable to capture motion notification image: {error}")
        return
    await deliver_motion_email(detected_at, capture)


def schedule_motion_email(detected_at):
    task = asyncio.create_task(capture_and_deliver_motion_email(detected_at))
    motion_email_tasks.add(task)
    task.add_done_callback(motion_email_tasks.discard)


def extract_luminance_frame(frame, stream_size):
    """Extract the Y plane from Picamera2's YUV420 low-resolution array."""
    width, height = stream_size
    if frame.ndim == 2:
        return frame[:height, :width]
    return cv2.cvtColor(frame, cv2.COLOR_RGB2GRAY)


async def motion_detection_loop():
    global motion_period_active, motion_last_detected_at
    global motion_consecutive_frames

    while True:
        await motion_armed_event.wait()
        if not motion_armed:
            continue

        iteration_started_at = time.monotonic()
        try:
            async with camera_lock:
                frame = camera.capture_array("lores")
                current_stream_size = motion_stream_size
        except Exception as error:
            print(f"Unable to capture motion-detection frame: {error}")
            await asyncio.sleep(MOTION_SAMPLE_INTERVAL_SECONDS)
            continue

        # Disarm may have been requested while this task was waiting for the
        # camera lock. Do not process a frame after that state change.
        if not motion_armed:
            continue

        try:
            luminance_frame = extract_luminance_frame(frame, current_stream_size)
            detected = motion_detector.detects_motion(luminance_frame)
        except Exception as error:
            motion_detector.reset()
            print(f"Unable to process motion-detection frame: {error}")
            await asyncio.sleep(MOTION_SAMPLE_INTERVAL_SECONDS)
            continue
        now = time.monotonic()

        if detected:
            if (
                motion_period_active
                and motion_last_detected_at is not None
                and now - motion_last_detected_at >= MOTION_CLEAR_SECONDS
            ):
                motion_period_active = False
                motion_consecutive_frames = 0
            motion_last_detected_at = now
            motion_consecutive_frames += 1
            if (
                not motion_period_active
                and motion_consecutive_frames >= MOTION_REQUIRED_FRAMES
            ):
                motion_period_active = True
                detected_at = datetime.now().astimezone()
                print(f"Motion detected at {detected_at.isoformat()}")
                schedule_motion_email(detected_at)
        else:
            motion_consecutive_frames = 0
            if (
                motion_period_active
                and motion_last_detected_at is not None
                and now - motion_last_detected_at >= MOTION_CLEAR_SECONDS
            ):
                motion_period_active = False
                motion_last_detected_at = None
                print("Motion period ended; notification is eligible again")

        elapsed = time.monotonic() - iteration_started_at
        await asyncio.sleep(max(0, MOTION_SAMPLE_INTERVAL_SECONDS - elapsed))


async def send_frames(websocket):
    global JPEG_QUALITY
    while True:
        async with camera_lock:
            frame = camera.capture_array("main")
        encode_params = [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY]
        _, buffer = cv2.imencode(".jpg", frame, encode_params)
        try:
            nonce = os.urandom(12)
            encrypted_data = AESGCM_CIPHER.encrypt(nonce, bytes(buffer), None)
            await websocket.send(nonce + encrypted_data)
            await asyncio.sleep(0.001)
        except websockets.ConnectionClosed:
            break


async def receive_commands(websocket, session):
    global JPEG_QUALITY, WIDTH, HEIGHT, motion_stream_size
    async for message in websocket:
        aes_key = None
        request_id = None
        try:
            data, aes_key, request_id = decrypt_command_envelope(message)
            validate_authenticated_command(data, session)
            command = data.get("command")

            if command == "update_settings":
                new_quality = int(data["quality"])
                new_width = int(data["width"])
                new_height = int(data["height"])
                if not 1 <= new_quality <= 100:
                    raise ValueError("JPEG quality must be between 1 and 100")
                if (
                    not 2 <= new_width <= 16_384
                    or not 2 <= new_height <= 16_384
                ):
                    raise ValueError("Resolution dimensions are outside the allowed range")

                if new_width != WIDTH or new_height != HEIGHT:
                    new_configuration, new_motion_stream_size = (
                        create_camera_configuration(new_width, new_height)
                    )
                    async with camera_lock:
                        camera.stop()
                        camera.configure(new_configuration)
                        camera.start()
                        motion_stream_size = new_motion_stream_size
                    WIDTH = new_width
                    HEIGHT = new_height
                    motion_detector.reset()
                JPEG_QUALITY = new_quality
                response = {
                    "settings_updated": True,
                    "width": WIDTH,
                    "height": HEIGHT,
                    "quality": JPEG_QUALITY,
                }
            elif command == "get_viewers":
                response = {
                    "viewers": [
                        {
                            "id": info["id"],
                            "connected_at": info["connected_at"],
                            "remote_address": info["remote_address"],
                        }
                        for info in active_connections.values()
                    ]
                }
            elif command == "get_access_log":
                response = {"access_log": access_log}
            elif command == "arm_motion_detection":
                if not MOTION_EMAIL_CONFIGURED:
                    response = {
                        **motion_status_payload(),
                        "motion_error": (
                            "Gmail is not configured on the server; motion "
                            "detection was not armed"
                        ),
                    }
                else:
                    arm_motion_detection()
                    response = motion_status_payload()
            elif command == "disarm_motion_detection":
                disarm_motion_detection()
                response = motion_status_payload()
            else:
                raise ValueError("Unknown command")

            await send_encrypted_response(websocket, aes_key, request_id, response)
        except Exception as error:
            print(f"Error processing command: {error}")
            if aes_key is not None and request_id is not None:
                await send_encrypted_response(
                    websocket,
                    aes_key,
                    request_id,
                    {"command_error": "Command rejected"},
                )


async def begin_handshake(websocket):
    """Handle the only plaintext client request: fetching server key material."""
    message = await asyncio.wait_for(websocket.recv(), timeout=30.0)
    if not isinstance(message, str) or len(message) > 4096:
        raise ValueError("Invalid public-key request")
    request = json.loads(message)
    if not isinstance(request, dict) or request.get("type") != "get_public_key":
        raise ValueError("The first request must fetch the public key")

    session = {"id": secrets.token_urlsafe(24), "used_nonces": {}}
    await websocket.send(
        json.dumps(
            {
                "type": "server_hello",
                "protocol": 1,
                "server_time": int(time.time()),
                "public_key": COMMAND_PUBLIC_KEY_PEM,
                "public_key_fingerprint": COMMAND_PUBLIC_KEY_FINGERPRINT,
                "session_id": session["id"],
                "password_kdf": {
                    "name": "PBKDF2",
                    "hash": "SHA-256",
                    "iterations": PASSWORD_KDF_ITERATIONS,
                    "salt": encode_base64(ACCESS_PASSWORD_SALT),
                },
                "available_resolutions": [
                    {"width": width, "height": height}
                    for width, height in AVAILABLE_RESOLUTIONS
                ],
            },
            separators=(",", ":"),
        )
    )
    return session


async def authenticate(websocket, session):
    """Require an encrypted, fresh access-password proof before streaming."""
    aes_key = None
    request_id = None
    try:
        message = await asyncio.wait_for(websocket.recv(), timeout=30.0)
        data, aes_key, request_id = decrypt_command_envelope(message)
        validate_authenticated_command(data, session)
        if data.get("command") != "authenticate":
            raise ValueError("Expected authenticate command")

        log_access_attempt(websocket, True)
        await send_encrypted_response(
            websocket,
            aes_key,
            request_id,
            {"authenticated": True, **motion_status_payload()},
        )
        return True
    except asyncio.TimeoutError:
        log_access_attempt(websocket, False, "Authentication timeout")
        await websocket.send(
            json.dumps(
                {"type": "handshake_error", "error": "Authentication timeout"}
            )
        )
    except Exception as error:
        log_access_attempt(websocket, False, "Authentication failed")
        print(f"Authentication error: {error}")
        if aes_key is not None and request_id is not None:
            await send_encrypted_response(
                websocket,
                aes_key,
                request_id,
                {"authenticated": False, "error": "Authentication failed"},
            )
        else:
            await websocket.send(
                json.dumps(
                    {"type": "handshake_error", "error": "Authentication failed"}
                )
            )
    return False


async def handle_connection(websocket):
    """Negotiate keys, authenticate, then stream frames and receive commands."""
    global connection_id_counter

    try:
        session = await begin_handshake(websocket)
    except Exception as error:
        print(f"Handshake error: {error}")
        return

    if not await authenticate(websocket, session):
        return

    connection_id_counter += 1
    connection_info = {
        "id": connection_id_counter,
        "connected_at": datetime.now().isoformat(),
        "remote_address": str(websocket.remote_address)
        if websocket.remote_address
        else "unknown",
    }
    active_connections[websocket] = connection_info
    print(
        f"Client {connection_info['id']} connected from "
        f"{connection_info['remote_address']}"
    )

    try:
        sender = asyncio.create_task(send_frames(websocket))
        receiver = asyncio.create_task(receive_commands(websocket, session))
        _, pending = await asyncio.wait(
            [sender, receiver],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
    finally:
        if websocket in active_connections:
            print(f"Client {active_connections[websocket]['id']} disconnected")
            del active_connections[websocket]


async def main():
    """Start the WebSocket server."""
    detector_task = asyncio.create_task(motion_detection_loop())
    try:
        async with websockets.serve(handle_connection, "localhost", 8000):
            await asyncio.Future()
    finally:
        detector_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await detector_task


if __name__ == "__main__":
    asyncio.run(main())
