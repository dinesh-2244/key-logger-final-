import subprocess
import time
import webbrowser
import os
import sys
import urllib.request

def get_python_executable():
    """Find the project virtual environment python, or fallback to current sys.executable."""
    # Check for .venv in common locations
    venv_paths = [
        os.path.join(os.getcwd(), ".venv", "bin", "python"), # macOS/Linux
        os.path.join(os.getcwd(), ".venv", "Scripts", "python.exe"), # Windows
        os.path.join(os.getcwd(), "..", ".venv", "bin", "python"), # If run from a subfolder
        os.path.join(os.getcwd(), "..", ".venv", "Scripts", "python.exe")
    ]
    for path in venv_paths:
        if os.path.exists(path):
            return path
    return sys.executable

def wait_for_server(url, timeout=30):
    """Poll until the server responds or timeout is reached."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False

def launch():
    print("Starting GuardianLens v3.0...")

    python_exe = get_python_executable()
    print(f"--- Using Python: {python_exe}")

    # Resolve paths relative to this script's directory (final-project/)
    project_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Start Backend Server
    print("--- Starting Backend Server...")
    server_process = subprocess.Popen(
        [python_exe, os.path.join(project_dir, "backend", "server.py")],
        cwd=project_dir
    )

    # 2. Start Monitoring Agent
    print("--- Starting Monitoring Agent...")
    bundled_agent = os.path.join(project_dir, "dist", "GuardianLensAgent")
    if sys.platform == "win32":
        bundled_agent += ".exe"
    elif sys.platform == "darwin":
        bundled_agent += ".app/Contents/MacOS/GuardianLensAgent"

    if os.path.exists(bundled_agent):
        print(f"    (Using bundled binary: {bundled_agent})")
        agent_process = subprocess.Popen([bundled_agent], cwd=project_dir)
    else:
        print("    (Bundled binary not found. Falling back to Python script...)")
        agent_process = subprocess.Popen(
            [python_exe, os.path.join(project_dir, "frontend", "threat_agent.py")],
            cwd=project_dir
        )

    # 3. Open Dashboard — wait until server is actually ready
    print("--- Waiting for server to be ready...")
    if wait_for_server("http://127.0.0.1:2000/login"):
        print("--- Opening Parent Dashboard...")
        webbrowser.open("http://127.0.0.1:2000")
    else:
        print("--- WARNING: Server did not respond within 30s. Opening anyway...")
        webbrowser.open("http://127.0.0.1:2000")
    
    print("\n✅ GuardianLens is now running!")
    print("Close this window to stop both services.")
    
    try:
        # Keep the script running while services are active
        while True:
            if server_process.poll() is not None: break
            if agent_process.poll() is not None: break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down GuardianLens...")
        server_process.terminate()
        agent_process.terminate()

if __name__ == "__main__":
    launch()
