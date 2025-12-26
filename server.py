"""
server.py
WebSocket FPV server
Copyright (C) 2023  Aiden Bohlander

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
import cv2
import asyncio
import websockets
import json
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from picamera2 import Picamera2


# Global settings
JPEG_QUALITY = 70
WIDTH = 640
HEIGHT = 480

# Encryption settings
def load_password():
    """Load password from file or environment variable."""
    password_file = 'STREAM_PASSWORD'
    if password_file and os.path.exists(password_file):
        with open(password_file, 'r') as f:
            return f.read().strip()
    print("STREAM_PASSWORD file not found, using default password.")
    return os.environ.get("STREAM_PASSWORD", "changeme")

ENCRYPTION_PASSWORD = load_password()
# Derive a 256-bit key from the password using SHA-256
ENCRYPTION_KEY = hashlib.sha256(ENCRYPTION_PASSWORD.encode()).digest()
AESGCM_CIPHER = AESGCM(ENCRYPTION_KEY)

# Start video capture with Raspberry Pi camera
camera = Picamera2()
camera.configure(camera.create_preview_configuration(main={"format": "RGB888", "size": (WIDTH, HEIGHT)}))
camera.start()


async def send_frames(websocket):
    global JPEG_QUALITY
    while True:
        frame = camera.capture_array()
        encode_params = [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY]
        _, buffer = cv2.imencode('.jpg', frame, encode_params)
        try:
            # Encrypt the frame data
            nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
            encrypted_data = AESGCM_CIPHER.encrypt(nonce, bytes(buffer), None)
            # Send nonce + encrypted data
            await websocket.send(nonce + encrypted_data)
            await asyncio.sleep(0.001)
        except websockets.ConnectionClosed:
            break


async def receive_commands(websocket):
    global JPEG_QUALITY, WIDTH, HEIGHT
    async for message in websocket:
        try:
            data = json.loads(message)
            if 'quality' in data:
                JPEG_QUALITY = int(data['quality'])
            if 'width' in data and 'height' in data:
                new_w = int(data['width'])
                new_h = int(data['height'])
                if new_w != WIDTH or new_h != HEIGHT:
                    WIDTH = new_w
                    HEIGHT = new_h
                    camera.stop()
                    camera.configure(camera.create_preview_configuration(main={"format": "RGB888", "size": (WIDTH, HEIGHT)}))
                    camera.start()
        except Exception as e:
            print(f"Error processing command: {e}")


async def handle_connection(websocket):
    """
    Websocket connection handler
    :param websocket: Connected websocket
    :return: None
    """
    sender = asyncio.create_task(send_frames(websocket))
    receiver = asyncio.create_task(receive_commands(websocket))
    done, pending = await asyncio.wait(
        [sender, receiver],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()


async def main():
    """Start the WebSocket server."""
    async with websockets.serve(handle_connection, "0.0.0.0", 8000):
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    asyncio.run(main())
