import subprocess
import time
import webbrowser
import os
import sys

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

def launch():
    print("🚀 Starting GuardianLens v3.0...")
    
    python_exe = get_python_executable()
    print(f"--- Using Python: {python_exe}")
    
    # 1. Start Backend Server
    print("--- Starting Backend Server...")
    server_process = subprocess.Popen(
        [python_exe, "backend/server.py"],
        cwd=os.getcwd()
    )
    
    # 2. Start Monitoring Agent
    print("--- Starting Monitoring Agent...")
    # Check for bundled binary first
    bundled_agent = "dist/GuardianLensAgent"
    if sys.platform == "win32": bundled_agent += ".exe"
    elif sys.platform == "darwin": bundled_agent += ".app/Contents/MacOS/GuardianLensAgent"

    if os.path.exists(bundled_agent):
        print(f"    (Using bundled binary: {bundled_agent})")
        agent_process = subprocess.Popen([bundled_agent], cwd=os.getcwd())
    else:
        print("    (Bundled binary not found. Falling back to Python script...)")
        agent_process = subprocess.Popen(
            [python_exe, "frontend/threat_agent.py"],
            cwd=os.getcwd()
        )
    
    # 3. Open Dashboard
    time.sleep(2) # Wait for server to boot
    print("--- Opening Parent Dashboard...")
    webbrowser.open("http://127.0.0.1:2000")
    
    print("\n✅ GuardianLens is now running!")
    print("Close this window to stop both services.")
    
    try:
        # Keep the script running while services are active
        while True:
            if server_process.poll() is not None:
                print("\n⚠️ Backend server exited unexpectedly.")
                break
            if agent_process.poll() is not None:
                print("\n⚠️ Monitoring agent exited unexpectedly.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n🛑 Shutting down GuardianLens...")
        if server_process.poll() is None:
            server_process.terminate()
        if agent_process.poll() is None:
            agent_process.terminate()

if __name__ == "__main__":
    launch()
