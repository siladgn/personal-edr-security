import os
import re
import urllib.parse
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    import joblib
except ImportError:
    print("=========================================================================")
    print("[!] CRITICAL ERROR: Missing required ML packages.")
    print("[!] Please run the following command to install dependencies:")
    print("[!] pip install flask numpy scikit-learn joblib")
    print("=========================================================================")
    import sys
    sys.exit(1)

# Initialize Flask to serve static files from static directory
app = Flask(__name__, static_folder='static', static_url_path='')

# Model File Path
MODEL_PATH = "phishing_model.joblib"
classifier = None

# Centralized State for EDR Dashboard
edr_state = {
    "modules": {
        "cookie_shield": True,
        "sinkhole": True,
        "phishing_detector": True
    },
    "stats": {
        "blocked_threats": 0,
        "checked_urls": 0
    },
    "logs": [
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "module": "Sistem",
            "message": "Kişisel EDR Kontrol Paneli sunucusu başlatıldı.",
            "level": "info"
        }
    ]
}

def add_log(module, message, level="info"):
    """Adds a log entry with a timestamp."""
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "module": module,
        "message": message,
        "level": level
    }
    edr_state["logs"].append(log_entry)
    if len(edr_state["logs"]) > 100:
        edr_state["logs"].pop(0)

# List of suspicious keywords frequently found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'bank', 'update', 'account', 'support', 
    'paypal', 'ebay', 'amazon', 'netflix', 'microsoft', 'google', 'apple', 'office',
    'webscr', 'cmd', 'recovery', 'billing', 'confirm', 'validation', 'alert'
]

# Suspicions signatures for Virus Scanner (Heuristics)
SUSPICIOUS_SIGNATURES = [
    (re.compile(r'powershell.*-executionpolicy.*bypass', re.IGNORECASE), "PowerShell Execution Policy Bypass tespit edildi."),
    (re.compile(r'downloadstring|downloadfile', re.IGNORECASE), "Dosya indirme fonksiyonu (DownloadString/DownloadFile) algılandı."),
    (re.compile(r'invoke-expression|iex', re.IGNORECASE), "Dinamik kod yürütme ifadesi (IEX/Invoke-Expression) tespit edildi."),
    (re.compile(r'base64.*b64decode|frombase64string', re.IGNORECASE), "Base64 kodlanmış payload çözme işlemi algılandı."),
    (re.compile(r'os\.system\(|subprocess\.', re.IGNORECASE), "Sistem komutu yürütme kodu (os.system/subprocess) tespit edildi."),
    (re.compile(r'eval\(|exec\(', re.IGNORECASE), "Dinamik kod eval/exec kullanımı algılandı."),
    (re.compile(r'tempfile.*\.exe|environ.*\.exe', re.IGNORECASE), "Geçici dizine çalıştırılabilir dosya yazma deseni algılandı.")
]

def extract_features(url):
    """Extracts numerical features from a given URL for machine learning classification."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc.lower()
    path = parsed_url.path.lower()
    domain_clean = domain.replace("www.", "")
    
    # Feature 1: URL Length
    url_len = len(url)
    # Feature 2: Domain Length
    domain_len = len(domain)
    # Feature 3: Count of Dots
    dot_count = url.count('.')
    # Feature 4: Count of Hyphens
    hyphen_count = url.count('-')
    # Feature 5: Count of Slashes
    slash_count = url.count('/')
    # Feature 6: Count of Subdomains (dots in clean domain)
    subdomain_count = max(0, domain_clean.count('.') - 1)
    # Feature 7: Presence of '@' symbol
    has_at = 1 if '@' in url else 0
    # Feature 8: Presence of IP Address in domain
    has_ip = 1 if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', domain) else 0
    # Feature 9: Count of suspicious keywords
    sus_keyword_count = 0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain or keyword in path:
            sus_keyword_count += 1
    # Feature 10: Digit-to-character ratio
    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = digit_count / url_len if url_len > 0 else 0
    
    return [
        url_len, domain_len, dot_count, hyphen_count, slash_count,
        subdomain_count, has_at, has_ip, sus_keyword_count, digit_ratio
    ]

def train_and_save_model():
    """Generates a dataset of benign and phishing URLs and trains a Random Forest Classifier."""
    print("[*] Generating seed dataset and training ML model...")
    
    # Benign URLs seed
    benign_urls = [
        "https://www.google.com", "https://www.github.com", "https://www.wikipedia.org",
        "https://www.amazon.com", "https://www.netflix.com", "https://www.microsoft.com",
        "https://www.youtube.com", "https://www.reddit.com", "https://www.linkedin.com",
        "https://www.twitter.com", "https://www.nytimes.com", "https://www.medium.com",
        "https://www.stackoverflow.com", "https://www.apple.com", "https://www.spotify.com",
        "https://www.zoom.us", "https://www.slack.com", "https://www.dropbox.com",
        "https://www.trello.com", "https://www.canva.com", "https://www.pinterest.com",
        "https://www.ebay.com", "https://www.salesforce.com", "https://www.python.org",
        "https://www.w3schools.com", "https://www.cloudflare.com", "https://www.digitalocean.com",
        "https://www.gitlab.com", "https://www.bitbucket.org", "https://www.docker.com"
    ]
    
    # Phishing/Malicious URLs seed
    phishing_urls = [
        "http://secure-login-paypal.com-webscr-cmd.info",
        "http://paypal-signin-verification-update.support",
        "https://netflix-account-billing-alert.com",
        "http://microsoft-office365-login-verify.net",
        "http://appleid-support-recovery-validation.info",
        "http://signin.amazon-update-billing.security-zone.net",
        "http://ebay-member-active-login.xyz",
        "http://google-drive-doc-viewer-auth.org",
        "http://192.168.1.105/login.html",
        "http://secure-banking-access-alert.com",
        "http://verification-required-confirm-now.net",
        "http://myaccount-update-profile.support",
        "http://bankofamerica-auth-confirm-details.xyz",
        "http://chase-security-restore-access.com",
        "http://wells-fargo-active-alert.net",
        "http://auth-secure-login-service.info",
        "http://verify-identity-profile-update.xyz",
        "http://gmail-security-alert-protect.org",
        "http://outlook-mail-login-session.com",
        "http://adobe-pdf-share-viewer-download.xyz"
    ]
    
    X = []
    y = []
    
    # Benign dataset expansion
    for url in benign_urls:
        X.append(extract_features(url))
        y.append(0)
        X.append(extract_features(url + "/about"))
        y.append(0)
        X.append(extract_features(url + "/contact/us"))
        y.append(0)
        X.append(extract_features(url + "/search?q=security"))
        y.append(0)
        
    # Phishing dataset expansion
    for url in phishing_urls:
        X.append(extract_features(url))
        y.append(1)
        X.append(extract_features(url + "/login.php"))
        y.append(1)
        X.append(extract_features(url + "?userid=admin&auth=true"))
        y.append(1)
        X.append(extract_features(url + "/index.html"))
        y.append(1)
        
    X = np.array(X)
    y = np.array(y)
    
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    
    joblib.dump(clf, MODEL_PATH)
    print(f"[+] Model trained successfully and saved to: {MODEL_PATH}")
    return clf

# Load or Train the classifier at startup
if os.path.exists(MODEL_PATH):
    try:
        classifier = joblib.load(MODEL_PATH)
        print(f"[+] Loaded existing model from: {MODEL_PATH}")
    except Exception as e:
        print(f"[-] Failed to load model: {e}. Re-training...")
        classifier = train_and_save_model()
else:
    classifier = train_and_save_model()

@app.after_request
def add_cors_headers(response):
    """Enables Cross-Origin Resource Sharing (CORS) for extension and dashboard access."""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Serve static dashboard at root /
@app.route('/')
def index():
    """Serves the static Web EDR Dashboard."""
    return app.send_static_file('index.html')

# Dashboard API Routes
@app.route('/api/status', methods=['GET'])
def get_dashboard_status():
    """Returns the full centralized EDR dashboard state."""
    return jsonify(edr_state)

@app.route('/api/modules/toggle', methods=['POST'])
def toggle_module():
    """Toggles a specific module state and logs the action."""
    data = request.get_json()
    if not data or 'module' not in data or 'enabled' not in data:
        return jsonify({"error": "Missing parameters."}), 400
        
    module_name = data['module']
    enabled_state = bool(data['enabled'])
    
    if module_name in edr_state["modules"]:
        edr_state["modules"][module_name] = enabled_state
        state_str = "AKTİF" if enabled_state else "PASİF"
        
        friendly_names = {
            "cookie_shield": "Çerez Kalkanı",
            "sinkhole": "DNS Sinkhole",
            "phishing_detector": "ML Oltalama Dedektörü"
        }
        friendly_name = friendly_names.get(module_name, module_name)
        
        add_log("Kontrol Paneli", f"{friendly_name} modülü kullanıcı tarafından {state_str} hale getirildi.", "info")
        return jsonify({"success": True, "modules": edr_state["modules"]})
    
    return jsonify({"error": "Invalid module name."}), 400

@app.route('/api/logs', methods=['POST'])
def post_log():
    """Accepts log entries from external modules (Cookie Shield, Sinkhole)."""
    data = request.get_json()
    if not data or 'module' not in data or 'message' not in data:
        return jsonify({"error": "Missing parameters."}), 400
        
    module = data['module']
    message = data['message']
    level = data.get('level', 'info')
    
    add_log(module, message, level)
    
    if level in ("warning", "error"):
        edr_state["stats"]["blocked_threats"] += 1
        
    return jsonify({"success": True})

# Virus Scanner API Endpoint
@app.route('/api/scan', methods=['POST'])
def scan_directory():
    """Scans files in a given folder path for suspicious signatures and calculates hashes."""
    data = request.get_json()
    if not data or 'path' not in data:
        return jsonify({"error": "Missing 'path' parameter."}), 400
        
    target_path = data['path'].strip()
    if not os.path.exists(target_path):
        return jsonify({"error": "Belirtilen klasör yolu sistemde bulunamadı."}), 404
        
    scanned_files_count = 0
    threats_detected = []
    
    # Track files to scan (recursive file walk)
    files_to_scan = []
    if os.path.isfile(target_path):
        files_to_scan.append(target_path)
    else:
        for root, dirs, files in os.walk(target_path):
            for file in files:
                files_to_scan.append(os.path.join(root, file))
                # Cap file limit to 200 files to keep scan response fast
                if len(files_to_scan) >= 200:
                    break
            if len(files_to_scan) >= 200:
                break
                
    add_log("Virüs Tarayıcı", f"Tarama başlatıldı: {target_path} ({len(files_to_scan)} dosya)", "info")
    
    for file_path in files_to_scan:
        try:
            scanned_files_count += 1
            is_malicious = False
            reasons = []
            
            # 1. Generate SHA-256 Hash of the file
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            
            # 2. Heuristics Check for Script/Code Files
            _, ext = os.path.splitext(file_path.lower())
            if ext in ('.py', '.bat', '.ps1', '.js', '.vbs', '.txt', '.sh'):
                try:
                    # Read file contents as text to match rules
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    for pattern, explanation in SUSPICIOUS_SIGNATURES:
                        if pattern.search(content):
                            is_malicious = True
                            reasons.append(explanation)
                except Exception:
                    pass
            
            if is_malicious:
                threat_info = {
                    "file_name": os.path.basename(file_path),
                    "file_path": file_path,
                    "hash": file_hash,
                    "reasons": reasons
                }
                threats_detected.append(threat_info)
                
                # Log to system EDR log stream
                message = f"Zararlı Yazılım Algılandı! Dosya: {threat_info['file_name']} | Nedeni: {', '.join(reasons)}"
                add_log("Virüs Tarayıcı", message, "error")
                edr_state["stats"]["blocked_threats"] += 1
                
        except Exception as e:
            # Skip unreadable or locked files
            continue
            
    add_log("Virüs Tarayıcı", f"Tarama tamamlandı. {scanned_files_count} dosya tarandı. {len(threats_detected)} tehdit bulundu.", "info")
    
    return jsonify({
        "status": "success",
        "scanned_count": scanned_files_count,
        "threats_count": len(threats_detected),
        "threats": threats_detected
    })

# Phishing Classifier Request Interceptor
@app.route('/predict', methods=['POST'])
def predict():
    """Predicts if a given URL is a phishing URL using the ML model."""
    try:
        if not edr_state["modules"]["phishing_detector"]:
            return jsonify({
                "url": request.get_json().get('url', ''),
                "is_phishing": False,
                "risk_score": 0.0,
                "info": "Module disabled"
            })
            
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Missing 'url' parameter in request body."}), 400
            
        url = data['url']
        
        edr_state["stats"]["checked_urls"] += 1
        
        features = extract_features(url)
        probabilities = classifier.predict_proba([features])[0]
        phishing_probability = float(probabilities[1])
        is_phishing = True if phishing_probability >= 0.65 else False
        
        feature_names = [
            "url_length", "domain_length", "dot_count", "hyphen_count", "slash_count",
            "subdomain_count", "has_at", "has_ip", "sus_keyword_count", "digit_ratio"
        ]
        feature_dict = dict(zip(feature_names, features))
        
        response = {
            "url": url,
            "is_phishing": is_phishing,
            "risk_score": round(phishing_probability, 4),
            "features": feature_dict
        }
        
        if is_phishing:
            edr_state["stats"]["blocked_threats"] += 1
            add_log("ML Oltalama Dedektörü", f"Şüpheli URL algılandı ve engellendi: {url} (Risk Skoru: %{round(phishing_probability*100, 1)})", "warning")
        else:
            add_log("ML Oltalama Dedektörü", f"URL tarandı (Güvenli): {url}", "info")
            
        return jsonify(response)
        
    except Exception as e:
        print(f"[-] Error processing prediction request: {e}")
        return jsonify({"error": "Internal server error during prediction."}), 500

@app.route('/status', methods=['GET'])
def status():
    """Returns the status and health of the EDR ML API."""
    return jsonify({
        "status": "active",
        "module": "Personal EDR - ML Phishing Detector API",
        "model_loaded": classifier is not None,
        "features_tracked": 10
    })

if __name__ == '__main__':
    print("=========================================================")
    print("  Personal EDR: ML Oltalama (Phishing) API Başlatılıyor")
    print("  Port: 5000 | Adres: http://localhost:5000")
    print("=========================================================")
    app.run(host='0.0.0.0', port=5000, debug=False)
