import time
import json
import requests
import subprocess
from datetime import datetime

# Configuration
SERVER_URL = "http://127.0.0.1:2000/api/telemetry"
CHECK_INTERVAL_SECONDS = 5  # How often to check the active window
SYNC_INTERVAL_SECONDS = 60  # How often to send data to the server

class ActivityMonitor:
    def __init__(self):
        self.activities = {}  # Store accumulated times: {"AppName|WindowTitle": duration}
        self.last_sync_time = time.time()
        self.current_app = None
        self.current_start_time = None

    def get_active_window(self):
        """Retrieve the currently active application name using AppleScript."""
        try:
            # Tell macOS to return the name of the first process whose frontmost is true
            script = 'tell application "System Events" to get name of first application process whose frontmost is true'
            result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True, check=True)
            app_name = result.stdout.strip()
            
            # Note: Getting the specific window title cross-application via AppleScript 
            # is highly restrictive due to macOS Accessibility permissions. 
            # We will rely just on the App Name for this project to ensure it works smoothly.
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
        """Send accumulated data to the backend API."""
        if not self.activities:
            return

        payload = {"activities": list(self.activities.values())}
        
        try:
            response = requests.post(SERVER_URL, json=payload, timeout=5)
            if response.status_code == 200:
                print(f"Successfully synced {len(self.activities)} activities.")
                # Clear local cache after successful sync
                self.activities = {}
            else:
                print(f"Failed to sync: Server returned {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error syncing with server: {e}")

    def run(self):
        print("Starting Activity Monitor...")
        print(f"Tracking interval: {CHECK_INTERVAL_SECONDS}s, Sync interval: {SYNC_INTERVAL_SECONDS}s")
        
        while True:
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
        monitor.sync_with_server()
