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
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from picamera2 import Picamera2


# Global settings
JPEG_QUALITY = 70
WIDTH = 640
HEIGHT = 480

# Encryption settings
def load_password(password_file, env_var, default_value):
    """Load password from file or environment variable."""
    if password_file and os.path.exists(password_file):
        print(f"Loading {env_var} from file.")
        with open(password_file, 'r') as f:
            return f.read().strip()
    print(f"{password_file} file not found, using default password.")
    return os.environ.get(env_var, default_value)

ENCRYPTION_PASSWORD = load_password('STREAM_PASSWORD', 'STREAM_PASSWORD', 'changeme')
ACCESS_PASSWORD = load_password('ACCESS_PASSWORD', 'ACCESS_PASSWORD', 'accessme')
# Derive a 256-bit key from the password using SHA-256
ENCRYPTION_KEY = hashlib.sha256(ENCRYPTION_PASSWORD.encode()).digest()
AESGCM_CIPHER = AESGCM(ENCRYPTION_KEY)

# Start video capture with Raspberry Pi camera
camera = Picamera2()
camera.configure(camera.create_preview_configuration(main={"format": "RGB888", "size": (WIDTH, HEIGHT)}))
camera.start()

# Active connections tracking
active_connections = {}  # websocket -> connection_info dict
connection_id_counter = 0


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
            if data.get('get_viewers'):
                # Send list of active viewers
                viewers = []
                for ws, info in active_connections.items():
                    viewers.append({
                        'id': info['id'],
                        'connected_at': info['connected_at'],
                        'remote_address': info['remote_address']
                    })
                await websocket.send(json.dumps({'viewers': viewers}))
        except Exception as e:
            print(f"Error processing command: {e}")


async def authenticate(websocket):
    """
    Wait for the client to send the correct access password.
    :param websocket: Connected websocket
    :return: True if authenticated, False otherwise
    """
    try:
        message = await asyncio.wait_for(websocket.recv(), timeout=30.0)
        data = json.loads(message)
        if data.get('access_password') == ACCESS_PASSWORD:
            await websocket.send(json.dumps({'authenticated': True}))
            return True
        else:
            await websocket.send(json.dumps({'authenticated': False, 'error': 'Invalid access password'}))
            return False
    except asyncio.TimeoutError:
        await websocket.send(json.dumps({'authenticated': False, 'error': 'Authentication timeout'}))
        return False
    except Exception as e:
        print(f"Authentication error: {e}")
        return False


async def handle_connection(websocket):
    """
    Websocket connection handler
    :param websocket: Connected websocket
    :return: None
    """
    global connection_id_counter
    
    # Wait for authentication before sending frames
    if not await authenticate(websocket):
        return
    
    # Register this connection
    connection_id_counter += 1
    connection_info = {
        'id': connection_id_counter,
        'connected_at': datetime.now().isoformat(),
        'remote_address': str(websocket.remote_address) if websocket.remote_address else 'unknown'
    }
    active_connections[websocket] = connection_info
    print(f"Client {connection_info['id']} connected from {connection_info['remote_address']}")
    
    try:
        sender = asyncio.create_task(send_frames(websocket))
        receiver = asyncio.create_task(receive_commands(websocket))
        done, pending = await asyncio.wait(
            [sender, receiver],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
    finally:
        # Unregister this connection
        if websocket in active_connections:
            print(f"Client {active_connections[websocket]['id']} disconnected")
            del active_connections[websocket]


async def main():
    """Start the WebSocket server."""
    async with websockets.serve(handle_connection, "localhost", 8000):
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    asyncio.run(main())
