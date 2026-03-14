import time
import os
import socketio as sio_module

SERVER_URL = "http://127.0.0.1:2000"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keylog.txt")

last_position = 0

sio = sio_module.Client(reconnection=True)
try:
    sio.connect(SERVER_URL)
except Exception as e:
    print(f"Failed to connect to server: {e}")

while True:
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            f.seek(last_position)
            new_lines = f.readlines()
            last_position = f.tell()

        if new_lines and sio.connected:
            for line in new_lines:
                sio.emit('raw_keystroke', {
                    'char': line.strip(),
                    'app_name': 'keylog_replay'
                })

            print("Sent:", len(new_lines), "lines")

    except Exception as e:
        print("Error:", e)

    time.sleep(1)