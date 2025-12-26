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
from picamera2 import Picamera2


async def handle_connection(websocket):
    """
    Websocket connection handler
    :param websocket: Connected websocket
    :return: None
    """
    for frame in get_frames():
        await websocket.send(frame)


# JPEG encoding parameters for performance
JPEG_QUALITY = 70  # Adjust 1-100: lower = smaller/faster, higher = better quality


def get_frames():
    """
    Generator function that uses picamera2 to stream frames to a websocket,
    yielding byte-encoded frames.
    :return: None
    """
    encode_params = [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY]
    while True:
        frame = camera.capture_array()
        _, buffer = cv2.imencode('.jpg', frame, encode_params)
        yield bytes(buffer)


# Start video capture with Raspberry Pi camera
camera = Picamera2()
camera.configure(camera.create_preview_configuration(main={"format": "RGB888", "size": (640, 480)}))
camera.start()


async def main():
    """Start the WebSocket server."""
    async with websockets.serve(handle_connection, "0.0.0.0", 8000):
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    asyncio.run(main())
