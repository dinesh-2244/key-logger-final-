import time
import json
import subprocess
from datetime import datetime
import socketio as sio_module

# Configuration
SERVER_URL = "http://127.0.0.1:2000"
CHECK_INTERVAL_SECONDS = 5  # How often to check the active window
SYNC_INTERVAL_SECONDS = 60  # How often to send data to the server
RECONNECT_DELAY = 3
MAX_RECONNECT_DELAY = 30

class ActivityMonitor:
    def __init__(self):
        self.activities = {}  # Store accumulated times: {"AppName|WindowTitle": duration}
        self.last_sync_time = time.time()
        self.current_app = None
        self.current_start_time = None
        self.running = True
        self._reconnect_delay = RECONNECT_DELAY
        self.sio = sio_module.Client(reconnection=True)
        try:
            self.sio.connect(SERVER_URL)
            self.sio.emit('agent_hello', {'agent': 'activity_monitor', 'version': '1.0'})
            self._reconnect_delay = RECONNECT_DELAY  # Reset on success
        except Exception as e:
            print(f"Failed to connect to server: {e}")

    def get_active_window(self):
        """Retrieve the currently active application name using AppleScript."""
        try:
            script = 'tell application "System Events" to get name of first application process whose frontmost is true'
            result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return "Unknown", "Unknown"
            app_name = result.stdout.strip()
            return app_name, "Main Window"
        except Exception as e:
            print(f"Error getting active window: {e}")
            return "Unknown", "Unknown"

    def record_activity(self):
        """Check the active window and update durations."""
        app_name, window_title = self.get_active_window()
        key = f"{app_name}|{window_title}"

        # Initialize or update
        if key not in self.activities:
            self.activities[key] = {
                "app_name": app_name,
                "window_title": window_title,
                "duration": 0
            }

        self.activities[key]["duration"] += CHECK_INTERVAL_SECONDS
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Active: {app_name}")

    def sync_with_server(self):
        """Send accumulated data to the server via WebSocket."""
        if not self.activities:
            return

        payload = {"activities": list(self.activities.values())}

        try:
            if self.sio.connected:
                self.sio.emit('telemetry_stream', payload)
                print(f"Successfully synced {len(self.activities)} activities.")
                self.activities = {}
                self._reconnect_delay = RECONNECT_DELAY  # Reset on success
            else:
                print(f"Not connected to server, retrying in {self._reconnect_delay}s...")
                time.sleep(self._reconnect_delay)
                self._reconnect_delay = min(self._reconnect_delay * 2, MAX_RECONNECT_DELAY)
                self.sio.connect(SERVER_URL)
        except Exception as e:
            print(f"Error syncing with server: {e}")

    def run(self):
        print("Starting Activity Monitor...")
        print(f"Tracking interval: {CHECK_INTERVAL_SECONDS}s, Sync interval: {SYNC_INTERVAL_SECONDS}s")

        while self.running:
            self.record_activity()

            # Check if it's time to sync
            if time.time() - self.last_sync_time > SYNC_INTERVAL_SECONDS:
                self.sync_with_server()
                self.last_sync_time = time.time()

            time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == "__main__":
    monitor = ActivityMonitor()
    try:
        monitor.run()
    except KeyboardInterrupt:
        print("\nStopping Activity Monitor. Performing final sync...")
        monitor.running = False
        monitor.sync_with_server()
        if monitor.sio.connected:
            monitor.sio.disconnect()
