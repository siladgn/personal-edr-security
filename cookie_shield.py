import os
import sys
import time
import logging
import psutil
import urllib.request
import json
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("cookie_shield.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("CookieShield")

# Configuration
DRY_RUN = False  # Set to True to only log and not kill the unauthorized processes
SCAN_INTERVAL_SEC = 2.0  # Periodic background scan interval
WHITELIST_PROCESS_NAMES = {
    "chrome.exe", "msedge.exe", "brave.exe", "python.exe", "pythonw.exe", 
    "explorer.exe", "taskmgr.exe"
}

API_LOGS_URL = "http://localhost:5000/api/logs"

def send_alert_to_dashboard(process_name, pid, file_path):
    """Sends a warning log to the central Flask API dashboard."""
    try:
        payload = {
            "module": "Çerez Kalkanı",
            "message": f"İzinsiz erişim engellendi! '{process_name}' (PID: {pid}) -> {Path(file_path).name}",
            "level": "warning"
        }
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            API_LOGS_URL, 
            data=data, 
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            pass
    except Exception as e:
        logger.debug(f"Failed to send alert to dashboard: {e}")

def get_chrome_cookies_paths():
    """Resolves standard Chrome Cookies database locations for all profiles."""
    local_app_data = os.getenv("LOCALAPPDATA")
    if not local_app_data:
        logger.error("LOCALAPPDATA environment variable not found. Cannot determine Chrome path.")
        return []
    
    chrome_user_data = Path(local_app_data) / "Google" / "Chrome" / "User Data"
    if not chrome_user_data.exists():
        logger.warning(f"Chrome User Data directory does not exist: {chrome_user_data}")
        return []
    
    # We will search for 'Cookies' files under Default or Profile X directories
    cookie_paths = []
    for path in chrome_user_data.glob("**/Network/Cookies"):
        cookie_paths.append(path.resolve())
    
    for path in chrome_user_data.glob("**/Cookies"):
        if path.resolve() not in cookie_paths and "Network" not in path.parts:
            cookie_paths.append(path.resolve())
            
    return cookie_paths

def check_and_terminate_unauthorized_access(file_path):
    """Scans active processes to see if any unauthorized process has opened the Chrome Cookies file."""
    target_path_str = str(file_path).lower()
    my_pid = os.getpid()
    
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            proc_info = proc.info
            pid = proc_info['pid']
            proc_name = proc_info['name']
            
            if pid == my_pid:
                continue
                
            if proc_name and proc_name.lower() in WHITELIST_PROCESS_NAMES:
                continue
                
            # Iterate through the files this process has open
            for open_file in proc.open_files():
                if open_file.path and target_path_str in open_file.path.lower():
                    logger.warning(
                        f"UNAUTHORIZED ACCESS DETECTED! "
                        f"Process '{proc_name}' (PID: {pid}) has an open handle to: {file_path}"
                    )
                    
                    # Notify Central Dashboard
                    send_alert_to_dashboard(proc_name, pid, file_path)
                    
                    if DRY_RUN:
                        logger.info(f"[DRY-RUN] Would have terminated process '{proc_name}' (PID: {pid}).")
                    else:
                        logger.info(f"Terminating unauthorized process '{proc_name}' (PID: {pid})...")
                        proc.terminate()
                        gone, alive = psutil.wait_procs([proc], timeout=2)
                        if alive:
                            logger.warning(f"Process {pid} did not exit. Killing aggressively...")
                            proc.kill()
                        logger.info(f"Process '{proc_name}' (PID: {pid}) successfully terminated.")
                        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            logger.debug(f"Error checking process: {e}")

class CookiesFileHandler(FileSystemEventHandler):
    """Watches for changes/access to the Cookies SQLite database."""
    def __init__(self, target_files):
        super().__init__()
        self.target_files = {str(p).lower(): p for p in target_files}
        
    def handle_event(self, event_path):
        event_path_lower = str(event_path).lower()
        for target_path_str, target_path in self.target_files.items():
            if target_path_str in event_path_lower:
                logger.info(f"File event triggered on Chrome Cookies: {event_path}")
                check_and_terminate_unauthorized_access(target_path)
                
    def on_modified(self, event):
        if not event.is_directory:
            self.handle_event(event.src_path)

    def on_accessed(self, event):
        if not event.is_directory:
            self.handle_event(event.src_path)

def run_periodic_scanner(cookie_paths):
    """Runs a parallel scan at regular intervals to capture transient access handles."""
    logger.info("Starting periodic background handle scanner...")
    while True:
        try:
            # First, check if Cookie Shield is enabled in Flask API to conform to dashboard toggle
            try:
                with urllib.request.urlopen("http://localhost:5000/api/status", timeout=2) as r:
                    status_data = json.loads(r.read().decode('utf-8'))
                    is_enabled = status_data["modules"]["cookie_shield"]
            except Exception:
                is_enabled = True # Fallback to active if server offline
                
            if is_enabled:
                for path in cookie_paths:
                    if path.exists():
                        check_and_terminate_unauthorized_access(path)
            time.sleep(SCAN_INTERVAL_SEC)
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Error in periodic scanner: {e}")
            time.sleep(5)

def main():
    logger.info("Initializing Cookie Shield Module...")
    
    cookie_paths = get_chrome_cookies_paths()
    if not cookie_paths:
        logger.error("No Chrome Cookies files found.")
        logger.info("Creating a mock monitoring dir for demonstration...")
        mock_dir = Path("./mock_chrome_profile/Network")
        mock_dir.mkdir(parents=True, exist_ok=True)
        mock_cookies = mock_dir / "Cookies"
        if not mock_cookies.exists():
            mock_cookies.write_text("Mock cookies database content for EDR testing.")
        cookie_paths = [mock_cookies.resolve()]
        logger.info(f"Monitoring mock cookie file at: {cookie_paths[0]}")
    
    logger.info(f"Targeting files for monitoring:")
    for path in cookie_paths:
        logger.info(f" - {path}")
        
    event_handler = CookiesFileHandler(cookie_paths)
    observer = Observer()
    
    monitored_dirs = set()
    for path in cookie_paths:
        parent_dir = path.parent
        if parent_dir.exists():
            monitored_dirs.add(parent_dir)
            
    for directory in monitored_dirs:
        observer.schedule(event_handler, path=str(directory), recursive=False)
        logger.info(f"Started monitoring directory: {directory}")
        
    observer.start()
    
    import threading
    scanner_thread = threading.Thread(
        target=run_periodic_scanner, 
        args=(cookie_paths,), 
        daemon=True
    )
    scanner_thread.start()
    
    logger.info("Cookie Shield is actively running. Press Ctrl+C to terminate.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping Cookie Shield...")
        observer.stop()
    observer.join()
    logger.info("Cookie Shield stopped.")

if __name__ == "__main__":
    main()
