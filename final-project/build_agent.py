import os
import subprocess
import sys

def build():
    # Paths
    icon_path = "/Users/dineshkanisetti/.gemini/antigravity/brain/73b0e433-525d-40dc-86b6-90c487cf1b51/guardian_lens_icon_1773463863539.png"
    agent_path = "frontend/threat_agent.py"
    domains_path = "frontend/domains.json"
    
    if not os.path.exists(agent_path):
        print(f"Error: {agent_path} not found.")
        return

    # Build command
    cmd = [
        "../.venv/bin/pyinstaller",
        "--noconfirm",
        "--onefile",
        "--windowed", # No terminal on macOS/Windows
        f"--icon={icon_path}",
        f"--add-data={domains_path}:.", # Bundle domains.json in root of temp _MEIPASS
        "--name=GuardianLensAgent",
        agent_path
    ]
    
    print("Building GuardianLens Agent binary...")
    try:
        subprocess.run(cmd, check=True)
        print("\nBuild Successful! Binary located in 'dist/' folder.")
    except subprocess.CalledProcessError as e:
        print(f"\nBuild Failed: {e}")

if __name__ == "__main__":
    build()
