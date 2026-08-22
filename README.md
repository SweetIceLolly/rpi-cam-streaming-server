# opencv-fpv-server
WebSockets-based Python FPV server for Raspberry Pi.

The browser UI supports camera-mode resolution presets, custom resolutions,
clockwise/counterclockwise display rotation, encrypted video frames, and an
encrypted command channel.

**Usage:**
```
python3 server.py
```

Open `index.html` in a browser and connect to the WebSocket server.

## Passwords and command key

Set `STREAM_PASSWORD` and `ACCESS_PASSWORD` in the environment, or create files
with those exact names in the working directory. Do not use the built-in default
passwords outside a trusted test setup.

On first startup, the server generates `command_private_key.pem` with mode 0600.
Back up this file and do not share or commit it. Its public-key fingerprint is
printed at startup. The browser pins that fingerprint on first connection; use
**Forget Server Key** only after independently verifying that a key change was
intentional. Set `COMMAND_PRIVATE_KEY_FILE` to store the private key elsewhere.

Commands use RSA-OAEP to wrap a one-time AES-256-GCM key. Each encrypted command
contains a PBKDF2-SHA-256 access-password verifier, a connection identifier, a
timestamp, and a one-time nonce. Command responses are encrypted with the same
one-time key. The access password itself is not transmitted or saved in browser
local storage.

The application-layer encryption protects against passive packet capture, but a
first connection over an unauthenticated network is still vulnerable to active
public-key substitution. Use WSS with a trusted certificate, or verify the
printed fingerprint through a separate trusted channel before relying on the
pinned key.
