import socket
import threading
import datetime
import os
import csv
import subprocess
import requests
from collections import defaultdict

LOG_DIR = "logs"
BAN_FILE = os.path.join(LOG_DIR, "banlist.txt")
PORTS = [22, 2222]
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/XXXX/XXXX"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
SILENT_MODE = False
ENABLE_FIREWALL_BLOCK = True  # iptables engeli aktif/pasif

ip_connection_counter = defaultdict(int)
os.makedirs(LOG_DIR, exist_ok=True)

def get_log_file():
    date_str = datetime.datetime.now().strftime('%Y-%m-%d')
    return os.path.join(LOG_DIR, f"honeypot_{date_str}.csv")

def init_csv_log():
    log_file = get_log_file()
    if not os.path.exists(log_file):
        with open(log_file, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "IP", "Country", "Org", "Port", "Username", "Password", "Flagged", "Downloaded URL"])
    return log_file

def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return response.get("country", "Unknown"), response.get("org", "Unknown")
    except Exception:
        return "Unknown", "Unknown"

def report_to_abuseipdb(ip, category=18, comment="Honeypot detected suspicious behavior."):
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
            }
        )
        if response.status_code == 200:
            print(f"[ABUSEIPDB] {ip} bildirildi.")
    except Exception as e:
        print(f"[ABUSEIPDB] HATA: {e}")

def send_discord_alert(ip, country, org, port, username, password, flagged, url=""):
    try:
        content = f"**🚨 HoneyTrapTR Uyarısı**\n**IP:** {ip} ({country})\n**Org:** {org}\n**Port:** {port}\n**Kullanıcı:** `{username}`\n**Şifre:** `{password}`"
        if flagged:
            content += "\n⚠️ Şüpheli IP tespit edildi!"
        if url:
            content += f"\n📥 İndirme Talebi: `{url}`"
        requests.post(DISCORD_WEBHOOK_URL, json={"content": content})
    except:
        pass

def log_event(ip, port, username, password, flagged=False, downloaded_url=""):
    log_file = init_csv_log()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    country, org = get_ip_info(ip)
    with open(log_file, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, ip, country, org, port, username, password, "Yes" if flagged else "No", downloaded_url])
    print(f"[{timestamp}] {ip} ({country}) [{org}] => {username}:{password}" +
          (" ⚠️" if flagged else "") + (f" | wget/curl: {downloaded_url}" if downloaded_url else ""))
    send_discord_alert(ip, country, org, port, username, password, flagged, downloaded_url)
    if flagged:
        report_to_abuseipdb(ip)

def ban_ip(ip):
    with open(BAN_FILE, "a") as banlist:
        banlist.write(ip + "\n")
    print(f"[!] IP BANLANDI: {ip}")
    if ENABLE_FIREWALL_BLOCK:
        try:
            subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            print(f"[FIREWALL] iptables DROP kuralı uygulandı: {ip}")
        except Exception as e:
            print(f"[FIREWALL] HATA: {e}")

def fake_shell(client_socket, ip, port, username, password, flagged):
    if SILENT_MODE:
        return
    shell_responses = {
        "ls": "documents  downloads  secret.txt",
        "whoami": "admin",
        "pwd": "/home/admin",
        "cat secret.txt": "Top Secret: honeypot triggered",
    }

    client_socket.sendall(b"Welcome to Ubuntu 20.04 LTS \n")
    client_socket.sendall(b"Type 'exit' to quit.\n$ ")

    while True:
        try:
            command = client_socket.recv(1024).strip().decode(errors="ignore")
        except:
            break
        lower_command = command.lower()
        if lower_command == "exit":
            client_socket.sendall(b"logout\n")
            break
        elif lower_command.startswith("wget ") or lower_command.startswith("curl "):
            url = command.split(" ", 1)[1] if " " in command else "UNKNOWN"
            log_event(ip, port, username, password, flagged, url)
            response = f"Downloading {url} ... done\n$ "
        elif lower_command in shell_responses:
            response = shell_responses[lower_command] + "\n$ "
        else:
            response = "bash: command not found\n$ "
        client_socket.sendall(response.encode())

def handle_client(client_socket, addr, port):
    ip = addr[0]
    ip_connection_counter[ip] += 1

    try:
        if not SILENT_MODE:
            client_socket.sendall(b"login: ")
            username = client_socket.recv(1024).strip().decode(errors="ignore")
            client_socket.sendall(b"password: ")
            password = client_socket.recv(1024).strip().decode(errors="ignore")
        else:
            username, password = "silent", "silent"
    except:
        client_socket.close()
        return

    flagged = ip_connection_counter[ip] > 5
    log_event(ip, port, username, password, flagged)

    if flagged:
        ban_ip(ip)

    if not SILENT_MODE:
        client_socket.sendall(b"Access granted.\n")
    fake_shell(client_socket, ip, port, username, password, flagged)
    client_socket.close()

def start_honeypot(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"[+] Honeypot listening on port {port}... (SILENT_MODE={SILENT_MODE}, FIREWALL={ENABLE_FIREWALL_BLOCK})")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr, port)).start()

if __name__ == "__main__":
    for port in PORTS:
        threading.Thread(target=start_honeypot, args=(port,), daemon=True).start()

    print("[*] HoneyTrapTR FULL STEALTH MODE aktif. Ctrl+C ile çık.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[*] Honeypot kapatıldı.")