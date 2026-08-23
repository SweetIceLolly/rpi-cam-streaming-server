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

## Motion detection email alerts

Motion detection is disarmed at startup. After an authenticated browser presses
**Arm Motion Detection**, the server samples a low-resolution luminance stream
and sends one email for the resulting motion period. It becomes eligible to send
another email only after a full quiet interval has elapsed. Pressing **Disarm
Motion Detection** stops motion-frame capture and processing and resets the
current period.

Configure Gmail before starting the server:

```sh
export GMAIL_ADDRESS="sender@gmail.com"
export GMAIL_APP_PASSWORD_FILE="/home/pi/.config/rpi-camera/gmail-app-password"
export MOTION_EMAIL_TO="recipient@example.com"
export MOTION_CLEAR_SECONDS="60"
```

The app-password file should contain only the Gmail app password and should be
readable only by the server account. `GMAIL_APP_PASSWORD` can be used instead,
but a secret file avoids placing the credential in shell history. Gmail app
passwords require 2-Step Verification. Mail is submitted to `smtp.gmail.com`
over implicit TLS on port 465.

Optional tuning settings and defaults:

- `MOTION_SAMPLE_INTERVAL_SECONDS=0.5`
- `MOTION_PIXEL_THRESHOLD=25`
- `MOTION_MIN_AREA_RATIO=0.012`
- `MOTION_BACKGROUND_ALPHA=0.05`
- `MOTION_WARMUP_FRAMES=6`
- `MOTION_REQUIRED_FRAMES=2`
- `MOTION_EMAIL_SUBJECT="Raspberry Pi camera motion detected"`

This is scene-motion detection optimized for limited Raspberry Pi 3 B+ CPU
capacity. It detects sufficiently large moving regions, but does not classify a
person or distinguish humans from animals, moving foliage, or lighting changes.
