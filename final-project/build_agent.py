import os
import subprocess
import sys
import shutil

def build():
    # Paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    agent_path = os.path.join(script_dir, "frontend", "threat_agent.py")
    domains_path = os.path.join(script_dir, "frontend", "domains.json")
    icon_path = os.path.join(script_dir, "guardian_lens_icon.png")

    if not os.path.exists(agent_path):
        print(f"Error: {agent_path} not found.")
        return

    if not os.path.exists(domains_path):
        print(f"Error: {domains_path} not found. Smart filtering will not work.")
        return

    # Find pyinstaller
    pyinstaller = shutil.which("pyinstaller")
    if not pyinstaller:
        # Try common venv locations
        venv_paths = [
            os.path.join(script_dir, "..", ".venv", "bin", "pyinstaller"),
            os.path.join(script_dir, "..", ".venv", "Scripts", "pyinstaller.exe"),
        ]
        for path in venv_paths:
            if os.path.exists(path):
                pyinstaller = path
                break

    if not pyinstaller:
        print("Error: pyinstaller not found. Install it with: pip install pyinstaller")
        return

    # Build command
    cmd = [
        pyinstaller,
        "--noconfirm",
        "--onefile",
        "--windowed",
        f"--add-data={domains_path}{os.pathsep}.",
        "--name=GuardianLensAgent",
        agent_path
    ]

    # Add icon only if it exists
    if os.path.exists(icon_path):
        cmd.insert(-1, f"--icon={icon_path}")
    else:
        print("Warning: Icon file not found, building without custom icon.")

    print("Building GuardianLens Agent binary...")
    try:
        subprocess.run(cmd, check=True)
        print("\nBuild Successful! Binary located in 'dist/' folder.")
    except subprocess.CalledProcessError as e:
        print(f"\nBuild Failed: {e}")

if __name__ == "__main__":
    build()
