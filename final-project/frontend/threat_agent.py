import time
import socketio
import subprocess
import threading
import logging
import signal
import sys
import platform
from pynput import keyboard
from datetime import datetime

# --- Configuration ---
SERVER_URL = "http://127.0.0.1:2000"
THREAT_KEYWORDS = ["hack", "bypass", "suicide", "credit card", "password", "exploit"]
ADULT_KEYWORDS = ["porn", "sex", "nsfw", "onlyfans", "xvideos", "pornhub", "xhamster", "rule34", "hentai", "nude", "cam", "adult"]
THREAT_KEYWORDS.extend(ADULT_KEYWORDS)

import json
import os

CHECK_INTERVAL_SECONDS = 5
KEYLOG_FILE = "keylog.txt"
RECONNECT_DELAY = 3
MAX_RECONNECT_DELAY = 30

# Domain DB for Smart Filtering
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, relative_path)

DOMAINS_DB_PATH = resource_path("domains.json")

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('ThreatAgent')

# Platform detection
CURRENT_OS = platform.system()  # "Darwin" (macOS), "Windows", "Linux"
logger.info(f"Platform detected: {CURRENT_OS}")

# Windows-specific imports (only loaded on Windows)
if CURRENT_OS == "Windows":
    try:
        import ctypes
        from ctypes import wintypes
        import winreg
        logger.info("Windows modules loaded successfully.")
    except ImportError as e:
        logger.warning(f"Windows module import failed: {e}. Some features may be limited.")


class ThreatAgent:
    def __init__(self):
        self.sio = socketio.Client(reconnection=True, reconnection_attempts=0, reconnection_delay=RECONNECT_DELAY)
        self.current_app = "Unknown"
        self.key_buffer = ""
        self.activities = {}
        self.app_start_times = {}
        self.url_start_times = {}
        self.last_urls = {}
        self.running = True

        # Rules from server
        self.blocked_apps = []
        self.max_daily_minutes = 120
        self.rules_active = True
        self.screen_time_exceeded = False

        # Smart Filtering Data
        self.domains_db = {}
        self._load_domains_db()

        # Setup event handlers
        self.sio.on('rules_update', self._on_rules_update)
        self.sio.on('enforce_limit', self._on_enforce_limit)
        self.sio.on('connect', self._on_connect)
        self.sio.on('disconnect', self._on_disconnect)

        self._connect()

    def _connect(self):
        """Connect to server with retry logic."""
        delay = RECONNECT_DELAY
        while self.running:
            try:
                self.sio.connect(SERVER_URL)
                logger.info("Connected to Security Server via WebSockets.")
                return
            except Exception as e:
                logger.warning(f"Connection failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)
                delay = min(delay * 2, MAX_RECONNECT_DELAY)

    def _on_connect(self):
        logger.info("WebSocket connected. Sending agent_hello...")
        self.sio.emit('agent_hello', {'agent': 'threat_agent', 'version': '2.0', 'platform': CURRENT_OS})

    def _on_disconnect(self):
        logger.warning("Disconnected from server.")

    def _load_domains_db(self):
        """Load the categorized domain database from JSON."""
        try:
            if os.path.exists(DOMAINS_DB_PATH):
                with open(DOMAINS_DB_PATH, "r") as f:
                    self.domains_db = json.load(f)
                logger.info(f"Smart filtering DB loaded: {len(self.domains_db.get('educational', []))} edu, {len(self.domains_db.get('entertainment', []))} ent domains.")
            else:
                logger.warning("domains.json not found. Smart filtering will rely on NLP only.")
        except Exception as e:
            logger.error(f"Failed to load domains.json: {e}")

    def _get_url_category(self, url, window_title):
        """Determine categories based on DB lookup and text analysis (NLP-lite)."""
        if not url:
            return self._analyze_text(window_title)

        # 1. Precise DB Lookup
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            
            for category, domains in self.domains_db.items():
                if domain in domains:
                    return category.capitalize()
        except:
            pass

        # 2. Keyword/NLP-lite Fallback
        return self._analyze_text(window_title + " " + url)

    def _analyze_text(self, text):
        """Simple keyword-density analysis to guess category."""
        text = text.lower()
        
        # Educational hints
        edu_keywords = ["course", "learn", "study", "code", "tutorial", "science", "math", "university", "college", "research", "documentation"]
        # Entertainment hints
        ent_keywords = ["game", "play", "stream", "video", "watch", "music", "song", "movie", "show", "series"]
        # Social hints
        social_keywords = ["chat", "status", "profile", "post", "friend", "messaging", "social"]

        edu_score = sum(1 for k in edu_keywords if k in text)
        ent_score = sum(1 for k in ent_keywords if k in text)
        social_score = sum(1 for k in social_keywords if k in text)

        if edu_score > 0 and edu_score >= ent_score and edu_score >= social_score:
            return "Educational"
        if ent_score > 0 and ent_score >= edu_score and ent_score >= social_score:
            return "Entertainment"
        if social_score > 0:
            return "Social Media"
        
        return "Neutral"

    def _on_rules_update(self, data):
        """Handle rules pushed from the server dashboard."""
        self.blocked_apps = data.get('blocked_apps', [])
        self.max_daily_minutes = data.get('max_daily_minutes', 120)
        self.rules_active = data.get('is_active', True)
        logger.info(f"Rules updated: limit={self.max_daily_minutes}m, blocked={self.blocked_apps}, active={self.rules_active}")

        if self.rules_active:
            for app_name in self.blocked_apps:
                self._force_quit_app(app_name)

    def _on_enforce_limit(self, data):
        """Handle screen time limit enforcement from server."""
        self.screen_time_exceeded = True
        used = data.get('used_minutes', 0)
        max_min = data.get('max_minutes', 120)
        logger.warning(f"SCREEN TIME LIMIT EXCEEDED: {used}/{max_min} minutes")
        self._show_notification(
            "GuardianLens",
            f"Screen time limit reached: {used}/{max_min} minutes used",
            "Time's Up!"
        )

    # =============================================
    #  CROSS-PLATFORM: Notifications
    # =============================================
    def _show_notification(self, title, message, subtitle=""):
        """Show a system notification — works on macOS and Windows."""
        try:
            if CURRENT_OS == "Darwin":
                script = f'display notification "{message}" with title "{title}"'
                if subtitle:
                    script = f'display notification "{message}" with title "{title}" subtitle "{subtitle}" sound name "Glass"'
                subprocess.run(['osascript', '-e', script], timeout=5)
            elif CURRENT_OS == "Windows":
                # Use PowerShell toast notification
                ps_script = f'''
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
                $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
                $text = $xml.GetElementsByTagName("text")
                $text[0].AppendChild($xml.CreateTextNode("{title}")) | Out-Null
                $text[1].AppendChild($xml.CreateTextNode("{message}")) | Out-Null
                $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
                [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("GuardianLens").Show($toast)
                '''
                subprocess.run(['powershell', '-Command', ps_script], timeout=10,
                             capture_output=True, creationflags=0x08000000 if CURRENT_OS == "Windows" else 0)
            else:
                # Linux fallback
                subprocess.run(['notify-send', title, message], timeout=5)
        except Exception as e:
            logger.error(f"Notification failed: {e}")

    # =============================================
    #  CROSS-PLATFORM: Force Quit / Kill Apps
    # =============================================
    def _force_quit_app(self, app_name):
        """Force-quit a blocked application — works on macOS and Windows."""
        try:
            if CURRENT_OS == "Darwin":
                is_running = self._run_applescript(
                    f'tell application "System Events" to (name of processes) contains "{app_name}"'
                )
                if is_running == "true":
                    logger.warning(f"BLOCKING APP: Force-quitting {app_name}")
                    self._run_applescript(f'tell application "{app_name}" to quit')
                    self._show_notification("GuardianLens", f"{app_name} has been blocked by your parent", "App Blocked")

            elif CURRENT_OS == "Windows":
                # Map display names to process names
                process_name = self._get_windows_process_name(app_name)
                result = subprocess.run(
                    ['tasklist', '/FI', f'IMAGENAME eq {process_name}'],
                    capture_output=True, text=True, timeout=5,
                    creationflags=0x08000000
                )
                if process_name.lower() in result.stdout.lower():
                    logger.warning(f"BLOCKING APP: Killing {app_name} ({process_name})")
                    subprocess.run(
                        ['taskkill', '/F', '/IM', process_name],
                        capture_output=True, timeout=5,
                        creationflags=0x08000000
                    )
                    self._show_notification("GuardianLens", f"{app_name} has been blocked by your parent", "App Blocked")

        except Exception as e:
            logger.error(f"Failed to force-quit {app_name}: {e}")

    def _get_windows_process_name(self, app_name):
        """Map common app display names to Windows process names."""
        mapping = {
            "Google Chrome": "chrome.exe",
            "Chrome": "chrome.exe",
            "Brave Browser": "brave.exe",
            "Microsoft Edge": "msedge.exe",
            "Firefox": "firefox.exe",
            "Safari": "safari.exe",
            "Discord": "Discord.exe",
            "Minecraft": "Minecraft.exe",
            "Roblox": "RobloxPlayerBeta.exe",
            "Steam": "steam.exe",
            "Spotify": "Spotify.exe",
            "Netflix": "ApplicationFrameHost.exe",  # UWP app
        }
        return mapping.get(app_name, f"{app_name}.exe")

    # =============================================
    #  CROSS-PLATFORM: Content Blocking
    # =============================================
    def block_adult_content(self, app_name):
        """Close the offending browser tab/window."""
        try:
            if CURRENT_OS == "Darwin":
                if app_name in ["Google Chrome", "Chrome", "Brave Browser"]:
                    self._run_applescript(
                        f'tell application "{app_name}"',
                        'if (count every window) > 0 then',
                        'close active tab of front window',
                        'end if',
                        'end tell'
                    )
                    logger.info(f"[RESTRICT] Closed adult tab in {app_name}")
                elif app_name == "Safari":
                    self._run_applescript(
                        'tell application "Safari"',
                        'if (count every document) > 0 then',
                        'close current tab of front window',
                        'end if',
                        'end tell'
                    )
                    logger.info("[RESTRICT] Closed adult tab in Safari")
            elif CURRENT_OS == "Windows":
                # Send Ctrl+W to close the active tab
                import ctypes
                user32 = ctypes.windll.user32
                VK_CONTROL = 0x11
                VK_W = 0x57
                KEYEVENTF_KEYUP = 0x0002
                user32.keybd_event(VK_CONTROL, 0, 0, 0)
                user32.keybd_event(VK_W, 0, 0, 0)
                time.sleep(0.05)
                user32.keybd_event(VK_W, 0, KEYEVENTF_KEYUP, 0)
                user32.keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0)
                logger.info(f"[RESTRICT] Sent Ctrl+W to close tab in {app_name}")
        except Exception as e:
            logger.error(f"Failed to close tab: {e}")

    # =============================================
    #  1. Keystroke & Threat Detection
    # =============================================
    def on_press(self, key):
        try:
            # Debounce: skip duplicate events for the same key within 100ms
            # macOS Quartz event taps can fire multiple times per physical keystroke
            now = time.time()
            key_id = str(key)
            if hasattr(self, '_last_key_id') and self._last_key_id == key_id \
               and hasattr(self, '_last_key_time') and (now - self._last_key_time) < 0.1:
                return  # Skip duplicate
            self._last_key_id = key_id
            self._last_key_time = now

            char_to_log = ""
            if hasattr(key, 'char') and key.char is not None:
                self.key_buffer += key.char
                char_to_log = key.char
            elif key == keyboard.Key.space:
                self.key_buffer += " "
                char_to_log = " "
            elif key == keyboard.Key.backspace:
                self.key_buffer = self.key_buffer[:-1]
                char_to_log = "[BACKSPACE]"
            elif key == keyboard.Key.enter:
                self.evaluate_buffer()
                self.key_buffer = ""
                char_to_log = "\n"
            else:
                char_to_log = f"[{key.name.upper()}]"

            with open(KEYLOG_FILE, "a", encoding="utf-8") as f:
                f.write(char_to_log)

            if self.sio.connected:
                self.sio.emit('raw_keystroke', {
                    'char': char_to_log,
                    'app_name': self.current_app
                })

            self.evaluate_buffer()

        except Exception:
            pass


    def evaluate_buffer(self):
        """Check the current typed buffer against threat keywords."""
        buffer_lower = self.key_buffer.lower()
        for keyword in THREAT_KEYWORDS:
            if keyword in buffer_lower:
                logger.warning(f"THREAT DETECTED: Typed '{keyword}' in {self.current_app}")
                if self.sio.connected:
                    self.sio.emit('threat_alert', {
                        'timestamp': datetime.now().isoformat(),
                        'keyword': keyword,
                        'app_name': self.current_app,
                        'full_buffer': self.key_buffer,
                        'category': 'Threat'
                    })
                self.key_buffer = ""
                if keyword in ADULT_KEYWORDS:
                    self.block_adult_content(self.current_app)
                break

    # =============================================
    #  2. Window Tracking & URL Extraction
    # =============================================

    # --- macOS Helpers ---
    def _run_applescript(self, *lines):
        """Run a multi-line AppleScript (macOS only)."""
        if CURRENT_OS != "Darwin":
            return ""
        cmd = ['osascript']
        for line in lines:
            cmd.extend(['-e', line])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except Exception:
            return ""

    # --- Windows Helpers ---
    def _get_active_window_windows(self):
        """Get the active window info on Windows using ctypes."""
        app_name = "Unknown"
        window_title = "Main Window"
        url = ""

        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            # Get foreground window handle
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return app_name, window_title, url

            # Get window title
            length = user32.GetWindowTextLengthW(hwnd) + 1
            buffer = ctypes.create_unicode_buffer(length)
            user32.GetWindowTextW(hwnd, buffer, length)
            window_title = buffer.value or "Main Window"

            # Get process ID and name
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid.value)
            if handle:
                try:
                    exe_buf = ctypes.create_unicode_buffer(512)
                    size = wintypes.DWORD(512)
                    # QueryFullProcessImageNameW
                    kernel32.QueryFullProcessImageNameW(handle, 0, exe_buf, ctypes.byref(size))
                    exe_path = exe_buf.value
                    if exe_path:
                        import os
                        exe_name = os.path.basename(exe_path)
                        # Map exe to friendly name
                        app_name = self._exe_to_display_name(exe_name)
                finally:
                    kernel32.CloseHandle(handle)

            # Extract URL from browser window title
            browsers_with_url_in_title = {
                "Google Chrome": " - Google Chrome",
                "Brave Browser": " - Brave",
                "Microsoft Edge": " - Microsoft Edge",
                "Firefox": " — Mozilla Firefox",
                "Safari": "",
            }
            if app_name in browsers_with_url_in_title:
                suffix = browsers_with_url_in_title[app_name]
                if suffix and window_title.endswith(suffix):
                    page_title = window_title[:-len(suffix)]
                else:
                    page_title = window_title
                window_title = page_title

                # Try to get URL from browser history for Chrome-based browsers
                url = self._get_browser_url_windows(app_name)

        except Exception as e:
            logger.error(f"Windows window tracking error: {e}")

        return app_name, window_title, url

    def _exe_to_display_name(self, exe_name):
        """Map Windows executable names to friendly display names."""
        mapping = {
            "chrome.exe": "Google Chrome",
            "brave.exe": "Brave Browser",
            "msedge.exe": "Microsoft Edge",
            "firefox.exe": "Firefox",
            "Code.exe": "Visual Studio Code",
            "code.exe": "Visual Studio Code",
            "WindowsTerminal.exe": "Terminal",
            "cmd.exe": "Command Prompt",
            "powershell.exe": "PowerShell",
            "explorer.exe": "File Explorer",
            "Spotify.exe": "Spotify",
            "Discord.exe": "Discord",
            "Minecraft.Windows.exe": "Minecraft",
            "steam.exe": "Steam",
        }
        return mapping.get(exe_name, exe_name.replace(".exe", ""))

    def _get_browser_url_windows(self, browser_name):
        """Try to extract the current URL from a browser on Windows via History DB."""
        try:
            import sqlite3, shutil, os, glob
            home = os.path.expanduser("~")
            history_paths = []

            if browser_name in ["Google Chrome", "Chrome"]:
                history_paths = glob.glob(f"{home}\\AppData\\Local\\Google\\Chrome\\User Data\\*\\History")
            elif browser_name == "Brave Browser":
                history_paths = glob.glob(f"{home}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\*\\History")
            elif browser_name == "Microsoft Edge":
                history_paths = glob.glob(f"{home}\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\History")
            elif browser_name == "Firefox":
                history_paths = glob.glob(f"{home}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite")

            latest_url = ""
            latest_time = 0

            for hist_path in history_paths:
                tmp_copy = os.path.join(os.environ.get('TEMP', '/tmp'), '_guardian_hist_copy.db')
                try:
                    shutil.copy2(hist_path, tmp_copy)
                    conn = sqlite3.connect(tmp_copy)
                    if "Firefox" in browser_name:
                        cursor = conn.execute(
                            "SELECT url, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 1"
                        )
                    else:
                        cursor = conn.execute(
                            "SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1"
                        )
                    row = cursor.fetchone()
                    conn.close()
                    if row and row[1] and row[1] > latest_time:
                        latest_url = row[0]
                        latest_time = row[1]
                except Exception:
                    pass

            if latest_url and latest_url.startswith("http"):
                # Filter: only return if visited in the last 30 seconds
                return latest_url

        except Exception as e:
            logger.error(f"Windows browser URL extraction error: {e}")

        return ""

    # --- Unified Interface ---
    def get_active_window(self):
        """Gets active app name, window title, and URL — cross-platform."""
        if CURRENT_OS == "Darwin":
            return self._get_active_window_macos()
        elif CURRENT_OS == "Windows":
            return self._get_active_window_windows()
        else:
            return self._get_active_window_linux()

    def _get_active_window_macos(self):
        """macOS: Get active window using AppleScript."""
        app_name = "Unknown"
        window_title = "Main Window"
        url = ""

        try:
            app_name = self._run_applescript(
                'tell application "System Events" to get name of first application process whose frontmost is true'
            )
            if not app_name:
                app_name = "Unknown"

            if app_name in ["Google Chrome", "Chrome", "Brave Browser"]:
                result = self._run_applescript(
                    f'tell application "{app_name}"',
                    'if (count every window) > 0 then',
                    'set theURL to URL of active tab of front window',
                    'set theTitle to title of active tab of front window',
                    'return theTitle & "|URL|" & theURL',
                    'end if',
                    'end tell'
                )
                if result and "|URL|" in result:
                    parts = result.split("|URL|", 1)
                    window_title = parts[0].strip()
                    url = parts[1].strip()
                elif result:
                    window_title = result

            elif app_name == "Safari":
                result = self._run_applescript(
                    'tell application "Safari"',
                    'if (count every document) > 0 then',
                    'set theURL to URL of front document',
                    'set theTitle to name of front document',
                    'return theTitle & "|URL|" & theURL',
                    'end if',
                    'end tell'
                )
                if result and "|URL|" in result:
                    parts = result.split("|URL|", 1)
                    window_title = parts[0].strip()
                    url = parts[1].strip()
                elif result:
                    window_title = result

            else:
                result = self._run_applescript(
                    f'tell application "System Events" to tell process "{app_name}" to get name of front window'
                )
                if result:
                    window_title = result

        except Exception:
            pass

        if url:
            logger.info(f"URL Captured: [{app_name}] {url}")

        return app_name, window_title, url

    def _get_active_window_linux(self):
        """Linux: Get active window using xdotool."""
        app_name = "Unknown"
        window_title = "Main Window"
        url = ""
        try:
            wid = subprocess.run(['xdotool', 'getactivewindow'], capture_output=True, text=True, timeout=3)
            if wid.stdout.strip():
                win_id = wid.stdout.strip()
                name_result = subprocess.run(['xdotool', 'getactivewindow', 'getwindowname'],
                                           capture_output=True, text=True, timeout=3)
                window_title = name_result.stdout.strip() or "Main Window"

                pid_result = subprocess.run(['xdotool', 'getactivewindow', 'getwindowpid'],
                                          capture_output=True, text=True, timeout=3)
                if pid_result.stdout.strip():
                    pid = pid_result.stdout.strip()
                    ps_result = subprocess.run(['ps', '-p', pid, '-o', 'comm='],
                                            capture_output=True, text=True, timeout=3)
                    app_name = ps_result.stdout.strip() or "Unknown"
        except Exception:
            pass
        return app_name, window_title, url

    # =============================================
    #  3. Background Browser Scanning
    # =============================================
    def _get_chromium_url(self, app_name):
        """Try to get URL from a Chromium-based browser with fallbacks (macOS)."""
        result = self._run_applescript(
            f'tell application "{app_name}"',
            'if (count every window) > 0 then',
            'set theURL to URL of active tab of front window',
            'set theTitle to title of active tab of front window',
            'return theTitle & "|URL|" & theURL',
            'end if',
            'end tell'
        )
        if result and "|URL|" in result:
            return result

        window_title = self._run_applescript(
            'tell application "System Events"',
            f'tell process "{app_name}"',
            'if (count every window) > 0 then',
            'return name of front window',
            'end if',
            'end tell',
            'end tell'
        )

        # Read Chrome's History SQLite DB if AppleScript fails
        if app_name in ["Google Chrome", "Chrome"]:
            has_windows = self._run_applescript(
                'tell application "System Events"',
                f'tell process "{app_name}"',
                'return (count every window) > 0',
                'end tell',
                'end tell'
            )
            if has_windows != "true":
                return ""
            try:
                import sqlite3, shutil, glob, os
                sudo_user = os.environ.get("SUDO_USER", "")
                if sudo_user:
                    home = f"/Users/{sudo_user}"
                else:
                    home = os.path.expanduser("~")
                history_paths = glob.glob(f"{home}/Library/Application Support/Google/Chrome/*/History")

                latest_url = ""
                latest_title = ""
                latest_time = 0

                for hist_path in history_paths:
                    tmp_copy = "/tmp/_chrome_hist_copy.db"
                    try:
                        shutil.copy2(hist_path, tmp_copy)
                        conn = sqlite3.connect(tmp_copy)
                        cursor = conn.execute(
                            "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1"
                        )
                        row = cursor.fetchone()
                        conn.close()
                        if row and row[2] > latest_time:
                            latest_url = row[0]
                            latest_title = row[1]
                            latest_time = row[2]
                    except Exception as e:
                        logger.error(f"Error reading Chrome history: {e}")

                if latest_url and latest_url.startswith("http"):
                    title = latest_title or window_title or latest_url
                    title = title.replace(" – Google Chrome", "").replace(" - Google Chrome", "").strip()
                    return f"{title}|URL|{latest_url}"
            except Exception as e:
                logger.error(f"Error in Chrome fallback: {e}")

        if window_title:
            return window_title
        return ""

    def scan_all_browsers(self):
        """Scan ALL running browsers for URLs — cross-platform."""
        now = time.time()

        if CURRENT_OS == "Darwin":
            self._scan_browsers_macos(now)
        elif CURRENT_OS == "Windows":
            self._scan_browsers_windows(now)

    def _scan_browsers_macos(self, now):
        """macOS: Scan browsers using AppleScript."""
        chromium_browsers = ["Google Chrome", "Brave Browser", "Microsoft Edge", "Arc"]
        all_browsers = chromium_browsers + ["Safari", "Firefox"]

        for browser_name in all_browsers:
            is_running = self._run_applescript(
                f'tell application "System Events" to (name of processes) contains "{browser_name}"'
            )
            if is_running != "true":
                if browser_name in self.last_urls:
                    old_key = self.last_urls.pop(browser_name, None)
                    if old_key:
                        self.url_start_times.pop(old_key, None)
                continue

            result = ""
            if browser_name in chromium_browsers:
                result = self._get_chromium_url(browser_name)
            elif browser_name == "Safari":
                result = self._run_applescript(
                    'tell application "Safari"',
                    'if (count every document) > 0 then',
                    'set theURL to URL of front document',
                    'set theTitle to name of front document',
                    'return theTitle & "|URL|" & theURL',
                    'end if',
                    'end tell'
                )
            elif browser_name == "Firefox":
                result = self._run_applescript(
                    'tell application "System Events"',
                    'tell process "Firefox"',
                    'if (count every window) > 0 then',
                    'return name of front window',
                    'end if',
                    'end tell',
                    'end tell'
                )

            self._process_browser_result(browser_name, result, now)

    def _scan_browsers_windows(self, now):
        """Windows: Scan browsers by checking running processes and reading history DBs."""
        browser_processes = {
            "Google Chrome": "chrome.exe",
            "Brave Browser": "brave.exe",
            "Microsoft Edge": "msedge.exe",
            "Firefox": "firefox.exe",
        }

        try:
            tasklist = subprocess.run(
                ['tasklist', '/FO', 'CSV', '/NH'],
                capture_output=True, text=True, timeout=5,
                creationflags=0x08000000
            )
            running_procs = tasklist.stdout.lower()
        except Exception:
            return

        for browser_name, proc_name in browser_processes.items():
            if proc_name.lower() not in running_procs:
                if browser_name in self.last_urls:
                    old_key = self.last_urls.pop(browser_name, None)
                    if old_key:
                        self.url_start_times.pop(old_key, None)
                continue

            url = self._get_browser_url_windows(browser_name)
            if url:
                result = f"Page|URL|{url}"
            else:
                result = ""

            self._process_browser_result(browser_name, result, now)

    def _process_browser_result(self, browser_name, result, now):
        """Process a browser scan result — shared logic for all platforms."""
        if not result:
            self.last_urls.pop(browser_name, None)
            return

        page_title = result
        url = ""

        if "|URL|" in result:
            parts = result.split("|URL|", 1)
            page_title = parts[0].strip()
            url = parts[1].strip()

        if not url and not page_title:
            return

        if url in ["favorites://", "missing value"]:
            return

        display_title = f"{page_title} ({url})" if url else page_title
        url_key = f"{browser_name}|{url or page_title}"

        # Initialize tracking for this browser if new
        if browser_name not in self.last_urls:
            self.last_urls[browser_name] = url_key
            self.url_start_times[browser_name] = now
            logger.info(f"URL Captured: [{browser_name}] {url or page_title}")

        prev_url = self.last_urls.get(browser_name)
        
        # Calculate delta time spent since the last poll
        last_poll_time = self.url_start_times.get(browser_name, now)
        delta_duration = int(now - last_poll_time)
        
        # Only emit if at least 1 second has passed
        if delta_duration >= 1 and self.sio.connected:
            category = self._get_url_category(url, page_title)
            self.sio.emit('telemetry_stream', {"activities": [{
                "app_name": browser_name,
                "window_title": display_title,
                "duration": delta_duration,
                "category": category
            }]})
            self.url_start_times[browser_name] = now # Reset timer for next delta

        if prev_url != url_key:
            self.last_urls[browser_name] = url_key
            logger.info(f"URL Navigated: [{browser_name}] {url or page_title}")

        # Check adult content
        if url:
            url_lower = url.lower()
            for keyword in ADULT_KEYWORDS:
                if keyword in url_lower:
                    logger.warning(f"ADULT URL BLOCKED: {url}")
                    self.block_adult_content(browser_name)
                    if self.sio.connected:
                        self.sio.emit('threat_alert', {
                            'timestamp': datetime.now().isoformat(),
                            'keyword': keyword,
                            'app_name': f"{browser_name} URL Navigation",
                            'full_buffer': url,
                            'category': 'Threat'
                        })
                    break

    # =============================================
    #  4. Main Activity Loop
    # =============================================
    def track_activity(self):
        """Loop to track application focus, URLs, and send telemetry updates."""
        # Browsers are handled exclusively by scan_all_browsers to avoid double-counting
        browser_apps = {"Google Chrome", "Brave Browser", "Microsoft Edge", "Arc",
                        "Safari", "Firefox", "chrome", "brave", "msedge", "firefox"}
        
        last_poll_time = time.time()
        
        while self.running:
            try:
                now = time.time()
                app_name, window_title, url = self.get_active_window()
                self.current_app = app_name

                # Check if current app is blocked
                if self.rules_active and app_name in self.blocked_apps:
                    self._force_quit_app(app_name)

                delta_duration = int(now - last_poll_time)
                
                # Skip browser apps — they are tracked by scan_all_browsers
                is_browser = app_name in browser_apps
                if not is_browser and delta_duration >= 1 and self.sio.connected:
                    category = self._get_url_category("", window_title)
                    display_title = window_title
                    self.sio.emit('telemetry_stream', {"activities": [{
                        "app_name": app_name,
                        "window_title": display_title,
                        "duration": delta_duration,
                        "category": category
                    }]})

                last_poll_time = now

                # Let scan_all_browsers handle browser URL tracking
                self.scan_all_browsers()

            except Exception as e:
                logger.error(f"Error in track_activity: {e}")

            time.sleep(CHECK_INTERVAL_SECONDS)




    def run(self):
        # Graceful shutdown
        def signal_handler(sig, frame):
            logger.info("Shutting down...")
            self.running = False
            if self.sio.connected:
                self.sio.disconnect()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Start Window Tracker Thread
        tracker_thread = threading.Thread(target=self.track_activity, daemon=True)
        tracker_thread.start()

        # Start Keylogger
        logger.info(f"Starting Edge Threat Engine & Keylogger on {CURRENT_OS}...")
        with keyboard.Listener(on_press=self.on_press) as listener:
            listener.join()

if __name__ == "__main__":
    agent = ThreatAgent()
    try:
        agent.run()
    except KeyboardInterrupt:
        logger.info("Agent Terminated.")
        agent.running = False
        if agent.sio.connected:
            agent.sio.disconnect()
