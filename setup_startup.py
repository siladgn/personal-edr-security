import os
import sys

def setup():
    # Directories
    workspace_dir = r"C:\Users\sıla\Documents\antigravity\keen-newton"
    startup_dir = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    
    # 1. Create Startup Batch Script
    startup_bat_path = os.path.join(startup_dir, "edr_startup.bat")
    
    bat_content = f"""@echo off
cd /d "{workspace_dir}"

:: Start Flask app in background using pythonw (if not already running)
netstat -o -n -a | findstr :5000 > nul
if %errorlevel% neq 0 (
    start "" pythonw app.py
)

:: Start Cookie Shield in background using pythonw
tasklist /fi "imagename eq pythonw.exe" /v | findstr /i "cookie_shield.py" > nul
if %errorlevel% neq 0 (
    start "" pythonw cookie_shield.py
)

:: Wait for 2 seconds for server initialization
timeout /t 2 /nobreak > nul

:: Launch Chrome in dedicated App Mode
start "" chrome --app="http://localhost:5000"
"""
    
    try:
        with open(startup_bat_path, "w", encoding="utf-8") as f:
            f.write(bat_content)
        print(f"[+] Startup script created successfully at: {startup_bat_path}")
    except Exception as e:
        print(f"[-] Failed to create startup script: {e}")
        
    # 2. Create Desktop Shortcut Batch Script
    desktop_bat_path = os.path.join(desktop_dir, "EDR Kontrol Paneli.bat")
    
    desktop_bat_content = f"""@echo off
cd /d "{workspace_dir}"

:: Start Flask app in background if not running
netstat -o -n -a | findstr :5000 > nul
if %errorlevel% neq 0 (
    start "" pythonw app.py
)

:: Start Cookie Shield in background if not running
tasklist /fi "imagename eq pythonw.exe" /v | findstr /i "cookie_shield.py" > nul
if %errorlevel% neq 0 (
    start "" pythonw cookie_shield.py
)

:: Wait for API
timeout /t 1 /nobreak > nul

:: Open EDR Panel in Chrome App Mode
start "" chrome --app="http://localhost:5000"
"""
    
    try:
        with open(desktop_bat_path, "w", encoding="utf-8") as f:
            f.write(desktop_bat_content)
        print(f"[+] Desktop shortcut created successfully at: {desktop_bat_path}")
    except Exception as e:
        print(f"[-] Failed to create desktop shortcut: {e}")

if __name__ == "__main__":
    setup()
