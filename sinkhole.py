import os
import sys
import ctypes
import urllib.request
import shutil
from datetime import datetime

# Windows Hosts File Path
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
BACKUP_PATH = r"C:\Windows\System32\drivers\etc\hosts.bak"

# Threat Intelligence Source (URLHaus Hosts format is ready-to-use)
THREAT_FEED_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"

START_TAG = "# === PERSONAL EDR SINKHOLE START ==="
END_TAG = "# === PERSONAL EDR SINKHOLE END ==="

def is_admin():
    """Checks if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Fallback for non-Windows systems if running in a hybrid env
        return os.getuid() == 0

def fetch_malicious_domains():
    """Fetches the latest blocklist of malicious domains from Threat Intelligence source."""
    print(f"[*] Fetching blocklist from: {THREAT_FEED_URL}")
    try:
        req = urllib.request.Request(
            THREAT_FEED_URL, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PersonalEDR/1.0'}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8')
            
        lines = content.splitlines()
        malicious_entries = []
        
        for line in lines:
            line = line.strip()
            # Ignore comments and empty lines
            if not line or line.startswith("#"):
                continue
            
            # URLHaus hosts file is formatted as: 127.0.0.1   domain.com
            parts = line.split()
            if len(parts) >= 2:
                ip, domain = parts[0], parts[1]
                # Validate it's a sinkhole record mapping to localhost
                if ip in ("127.0.0.1", "0.0.0.0"):
                    malicious_entries.append(f"127.0.0.1 {domain}")
                    
        print(f"[+] Successfully fetched {len(malicious_entries)} malicious entries.")
        return malicious_entries
    except Exception as e:
        print(f"[-] Error fetching threat intelligence feed: {e}")
        return []

def backup_hosts_file():
    """Creates a backup of the current hosts file."""
    if not os.path.exists(HOSTS_PATH):
        print("[-] Hosts file not found! A new one will be created.")
        return
        
    try:
        shutil.copy2(HOSTS_PATH, BACKUP_PATH)
        print(f"[+] Backup created successfully at: {BACKUP_PATH}")
    except Exception as e:
        print(f"[-] Failed to create backup: {e}")
        sys.exit(1)

def update_hosts_file(new_entries):
    """Updates the Windows hosts file with the fetched malicious entries inside tagged boundaries."""
    if not new_entries:
        print("[-] No entries to update. Aborting hosts update.")
        return

    # Read current hosts file content
    current_content = []
    if os.path.exists(HOSTS_PATH):
        try:
            with open(HOSTS_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                current_content = f.readlines()
        except Exception as e:
            print(f"[-] Error reading hosts file: {e}")
            sys.exit(1)

    # Filter out any existing personal EDR block
    cleaned_content = []
    inside_block = False
    for line in current_content:
        if START_TAG in line:
            inside_block = True
            continue
        if END_TAG in line:
            inside_block = False
            continue
        if not inside_block:
            cleaned_content.append(line)

    # Prepare the new block to insert
    new_block = [f"\n{START_TAG}\n"]
    new_block.append(f"# Updated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    new_block.append(f"# Source: {THREAT_FEED_URL}\n")
    for entry in new_entries:
        new_block.append(f"{entry}\n")
    new_block.append(f"{END_TAG}\n")

    # Merge content
    updated_content = cleaned_content + new_block

    # Write back to hosts file
    try:
        # Remove read-only attribute if set (some antivirus softwares lock hosts file)
        if os.path.exists(HOSTS_PATH):
            os.chmod(HOSTS_PATH, 0o666)
            
        with open(HOSTS_PATH, 'w', encoding='utf-8') as f:
            f.writelines(updated_content)
        print("[+] DNS Sinkhole successfully updated hosts file!")
    except PermissionError:
        print("[-] Permission Denied. You must run this script with administrator/root privileges.")
    except Exception as e:
        print(f"[-] Error writing to hosts file: {e}")

def restore_backup():
    """Restores the hosts file from the backup."""
    if not os.path.exists(BACKUP_PATH):
        print("[-] Backup file hosts.bak not found. Cannot restore.")
        return
        
    try:
        shutil.copy2(BACKUP_PATH, HOSTS_PATH)
        print("[+] Successfully restored hosts file from backup.")
    except Exception as e:
        print(f"[-] Failed to restore backup: {e}")

def clean_sinkhole():
    """Removes only the Personal EDR block from the hosts file without restoring full backup."""
    if not os.path.exists(HOSTS_PATH):
        print("[-] Hosts file not found.")
        return
        
    try:
        with open(HOSTS_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        cleaned_lines = []
        inside_block = False
        for line in lines:
            if START_TAG in line:
                inside_block = True
                continue
            if END_TAG in line:
                inside_block = False
                continue
            if not inside_block:
                cleaned_lines.append(line)
                
        with open(HOSTS_PATH, 'w', encoding='utf-8') as f:
            f.writelines(cleaned_lines)
        print("[+] Successfully removed all DNS Sinkhole entries from hosts file.")
    except Exception as e:
        print(f"[-] Failed to clean hosts file: {e}")

def main():
    if not is_admin():
        print("=========================================================================")
        print("[!] ERROR: Administrator privileges required.")
        print("[!] Please run your command line (PowerShell/CMD) as Administrator.")
        print("=========================================================================")
        sys.exit(1)
        
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "--restore":
            restore_backup()
            return
        elif arg == "--clean":
            clean_sinkhole()
            return
        else:
            print("Usage: python sinkhole.py [--restore | --clean]")
            return

    print("=== Personal EDR DNS Sinkhole Modülü ===")
    backup_hosts_file()
    entries = fetch_malicious_domains()
    # Limit entries for safety/performance in demonstration (e.g. top 500 entries)
    # This prevents the hosts file from swelling excessively on slow machines.
    if len(entries) > 1000:
        print("[*] Limiting to top 1000 entries for optimal system resolution speed.")
        entries = entries[:1000]
        
    update_hosts_file(entries)

if __name__ == "__main__":
    main()
