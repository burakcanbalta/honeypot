import socket
import threading
import datetime
import os
import csv
import subprocess
import requests
import time
import json
from collections import defaultdict, deque

LOG_DIR = "logs"
BAN_FILE = os.path.join(LOG_DIR, "banlist.txt")
CONFIG_FILE = "honeytrap_config.json"
PORTS = [22, 2222, 22222]
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_HERE"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY_HERE"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_KEY_HERE"

SILENT_MODE = False
ENABLE_FIREWALL_BLOCK = True
ENABLE_GEOBLOCK = False
MAX_CONNECTIONS_PER_IP = 5
CONNECTION_TIMEOUT = 30

ip_connection_counter = defaultdict(int)
ip_connection_times = defaultdict(deque)
banned_ips = set()
os.makedirs(LOG_DIR, exist_ok=True)

DEFAULT_CONFIG = {
    "ports": [22, 2222, 22222],
    "silent_mode": False,
    "firewall_block": True,
    "max_connections": 5,
    "timeout": 30,
    "discord_webhook": "",
    "abuseipdb_key": "",
    "virustotal_key": ""
}

def load_config():
    global PORTS, SILENT_MODE, ENABLE_FIREWALL_BLOCK, MAX_CONNECTIONS_PER_IP, CONNECTION_TIMEOUT
    global DISCORD_WEBHOOK_URL, ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                PORTS = config.get('ports', PORTS)
                SILENT_MODE = config.get('silent_mode', SILENT_MODE)
                ENABLE_FIREWALL_BLOCK = config.get('firewall_block', ENABLE_FIREWALL_BLOCK)
                MAX_CONNECTIONS_PER_IP = config.get('max_connections', MAX_CONNECTIONS_PER_IP)
                CONNECTION_TIMEOUT = config.get('timeout', CONNECTION_TIMEOUT)
                DISCORD_WEBHOOK_URL = config.get('discord_webhook', DISCORD_WEBHOOK_URL)
                ABUSEIPDB_API_KEY = config.get('abuseipdb_key', ABUSEIPDB_API_KEY)
                VIRUSTOTAL_API_KEY = config.get('virustotal_key', VIRUSTOTAL_API_KEY)
        except Exception as e:
            print(f"Config yükleme hatası: {e}")

def save_config():
    config = {
        'ports': PORTS,
        'silent_mode': SILENT_MODE,
        'firewall_block': ENABLE_FIREWALL_BLOCK,
        'max_connections': MAX_CONNECTIONS_PER_IP,
        'timeout': CONNECTION_TIMEOUT,
        'discord_webhook': DISCORD_WEBHOOK_URL,
        'abuseipdb_key': ABUSEIPDB_API_KEY,
        'virustotal_key': VIRUSTOTAL_API_KEY
    }
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Config kaydetme hatası: {e}")

def load_banned_ips():
    if os.path.exists(BAN_FILE):
        with open(BAN_FILE, 'r') as f:
            for line in f:
                banned_ips.add(line.strip())

def get_log_file():
    date_str = datetime.datetime.now().strftime('%Y-%m-%d')
    return os.path.join(LOG_DIR, f"honeypot_{date_str}.csv")

def init_csv_log():
    log_file = get_log_file()
    if not os.path.exists(log_file):
        with open(log_file, mode="w", newline="", encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "IP", "Country", "Org", "Port", "Username", "Password", "Flagged", "Downloaded URL", "Threat Score"])
    return log_file

def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("country", "Unknown"), data.get("org", "Unknown"), data.get("as", "Unknown")
        return "Unknown", "Unknown", "Unknown"
    except Exception:
        return "Unknown", "Unknown", "Unknown"

def check_virustotal(ip):
    if not VIRUSTOTAL_API_KEY:
        return 0
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            return malicious
    except Exception:
        pass
    return 0

def report_to_abuseipdb(ip, category=18, comment="Honeypot detected suspicious behavior."):
    if not ABUSEIPDB_API_KEY:
        return
    try:
        response = requests.post(
            "https://api.abuseipdb.com/api/v2/report",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            data={
                "ip": ip,
                "categories": category,
                "comment": comment
            },
            timeout=10
        )
        if response.status_code == 200:
            print(f"[ABUSEIPDB] {ip} bildirildi.")
    except Exception as e:
        print(f"[ABUSEIPDB] HATA: {e}")

def send_discord_alert(ip, country, org, port, username, password, flagged, threat_score=0, url=""):
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        color = 0xff0000 if flagged else 0xffff00
        embed = {
            "title": "🚨 HoneyTrapTR Uyarısı",
            "color": color,
            "fields": [
                {"name": "IP", "value": ip, "inline": True},
                {"name": "Ülke", "value": country, "inline": True},
                {"name": "Organizasyon", "value": org[:100] + "..." if len(org) > 100 else org, "inline": True},
                {"name": "Port", "value": str(port), "inline": True},
                {"name": "Kullanıcı", "value": f"`{username}`", "inline": True},
                {"name": "Şifre", "value": f"`{password}`", "inline": True},
                {"name": "Tehdit Skoru", "value": str(threat_score), "inline": True}
            ],
            "timestamp": datetime.datetime.now().isoformat()
        }
        if url:
            embed["fields"].append({"name": "İndirme URL", "value": f"`{url}`", "inline": False})
        if flagged:
            embed["fields"].append({"name": "Durum", "value": "⚠️ ŞÜPHELİ IP BANLANDI", "inline": False})
        
        requests.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]}, timeout=5)
    except Exception:
        pass

def log_event(ip, port, username, password, flagged=False, downloaded_url="", threat_score=0):
    log_file = init_csv_log()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    country, org, asn = get_ip_info(ip)
    
    with open(log_file, mode="a", newline="", encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, ip, country, org, port, username, password, "Yes" if flagged else "No", downloaded_url, threat_score])
    
    status_icon = "⚠️" if flagged else "🔍"
    print(f"[{timestamp}] {status_icon} {ip} ({country}) [{org}] => {username}:{password} | Skor: {threat_score}" +
          (f" | Download: {downloaded_url}" if downloaded_url else ""))
    
    send_discord_alert(ip, country, org, port, username, password, flagged, threat_score, downloaded_url)
    
    if flagged:
        report_to_abuseipdb(ip)

def ban_ip(ip):
    if ip in banned_ips:
        return
    
    banned_ips.add(ip)
    with open(BAN_FILE, "a", encoding='utf-8') as banlist:
        banlist.write(ip + "\n")
    
    print(f"[!] IP BANLANDI: {ip}")
    
    if ENABLE_FIREWALL_BLOCK:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True, timeout=10)
            print(f"[FIREWALL] iptables DROP kuralı uygulandı: {ip}")
        except subprocess.TimeoutExpired:
            print(f"[FIREWALL] Timeout: iptables kuralı eklenemedi: {ip}")
        except Exception as e:
            print(f"[FIREWALL] HATA: {e}")

def is_ip_banned(ip):
    return ip in banned_ips

def should_flag_ip(ip):
    current_time = time.time()
    ip_connection_times[ip].append(current_time)
    
    while ip_connection_times[ip] and current_time - ip_connection_times[ip][0] > 3600:
        ip_connection_times[ip].popleft()
    
    return len(ip_connection_times[ip]) > MAX_CONNECTIONS_PER_IP

def fake_shell(client_socket, ip, port, username, password, flagged):
    if SILENT_MODE:
        client_socket.close()
        return

    shell_responses = {
        "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
        "ls -la": "total 96\ndrwxr-xr-x  23 root root  4096 Dec  1 10:00 .\ndrwxr-xr-x  23 root root  4096 Dec  1 10:00 ..\n-rw-------   1 root root  1024 Dec  1 09:58 .bash_history",
        "whoami": "root",
        "id": "uid=0(root) gid=0(root) groups=0(root)",
        "pwd": "/root",
        "uname -a": "Linux server 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash",
        "ps aux": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.0  16948  1084 ?        Ss   10:00   0:01 /sbin/init",
    }

    try:
        client_socket.settimeout(CONNECTION_TIMEOUT)
        client_socket.sendall(b"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-42-generic x86_64)\n\n")
        client_socket.sendall(b"Last login: Fri Dec  1 10:00:00 2023 from 192.168.1.1\n")
        client_socket.sendall(b"root@server:~# ")

        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                command = data.decode('utf-8', errors='ignore').strip()
                
                if command.lower() in ['exit', 'logout', 'quit']:
                    client_socket.sendall(b"logout\n")
                    break
                elif command.lower().startswith("wget ") or command.lower().startswith("curl "):
                    url = command.split(" ", 1)[1] if " " in command else "UNKNOWN"
                    log_event(ip, port, username, password, flagged, url)
                    client_socket.sendall(b"bash: " + command.split()[0].encode() + b": command not found\n")
                elif command.lower() in shell_responses:
                    response = shell_responses[command.lower()] + "\n"
                    client_socket.sendall(response.encode())
                elif command.lower() == "":
                    client_socket.sendall(b"root@server:~# ")
                else:
                    client_socket.sendall(b"bash: " + command.encode() + b": command not found\n")
                
                client_socket.sendall(b"root@server:~# ")
                
            except socket.timeout:
                break
            except Exception:
                break
                
    except Exception as e:
        print(f"Shell hatası: {e}")
    finally:
        client_socket.close()

def handle_client(client_socket, addr, port):
    ip = addr[0]
    
    if is_ip_banned(ip):
        client_socket.close()
        return

    try:
        client_socket.settimeout(10)
        
        if not SILENT_MODE:
            client_socket.sendall(b"Ubuntu 20.04.6 LTS\nserver login: ")
            username_data = client_socket.recv(1024)
            username = username_data.decode('utf-8', errors='ignore').strip()
            
            client_socket.sendall(b"password: ")
            password_data = client_socket.recv(1024)
            password = password_data.decode('utf-8', errors='ignore').strip()
        else:
            username, password = "silent", "silent"

    except socket.timeout:
        client_socket.close()
        return
    except Exception:
        client_socket.close()
        return

    threat_score = check_virustotal(ip)
    flagged = should_flag_ip(ip) or threat_score > 2
    
    log_event(ip, port, username, password, flagged, "", threat_score)

    if flagged:
        ban_ip(ip)
        client_socket.sendall(b"Access denied.\n")
        client_socket.close()
        return

    if not SILENT_MODE:
        client_socket.sendall(b"Access granted. Starting session...\n")
    
    fake_shell(client_socket, ip, port, username, password, flagged)

def start_honeypot(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("0.0.0.0", port))
        server.listen(10)
        print(f"[+] Honeypot port {port} dinleniyor... (SILENT_MODE={SILENT_MODE}, FIREWALL={ENABLE_FIREWALL_BLOCK})")
        
        while True:
            try:
                client_socket, addr = server.accept()
                threading.Thread(target=handle_client, args=(client_socket, addr, port), daemon=True).start()
            except Exception as e:
                print(f"Bağlantı kabul hatası: {e}")
                
    except Exception as e:
        print(f"Port {port} bağlama hatası: {e}")
    finally:
        server.close()

def print_banner():
    banner = """
    🕷️ HoneyTrapTR - Advanced SSH Honeypot
    🔥 Gelişmiş Saldırı Tespit Sistemi
    📍 Portlar: {}
    🔒 Firewall: {}
    👻 Silent Mode: {}
    """.format(PORTS, ENABLE_FIREWALL_BLOCK, SILENT_MODE)
    print(banner)

if __name__ == "__main__":
    load_config()
    load_banned_ips()
    print_banner()
    
    for port in PORTS:
        threading.Thread(target=start_honeypot, args=(port,), daemon=True).start()

    print("[*] HoneyTrapTR FULL STEALTH MODE aktif. Ctrl+C ile çık.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Honeypot kapatılıyor...")
        save_config()
