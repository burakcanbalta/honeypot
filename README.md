# 🐝 HoneyTrapTR — Advanced Deception and Monitoring Honeypot

**HoneyTrapTR** is a versatile and robust honeypot designed for advanced network security operations. It emulates a live SSH environment, records malicious behaviors, and performs real-time threat intelligence and response actions with automated integrations.

---

## 🔍 Overview

HoneyTrapTR is built to lure, monitor, and analyze unauthorized access attempts in a stealthy and realistic way. It's ideal for both offensive security professionals and defensive analysts who need a reliable deception tool to detect, analyze, and react to potential intrusions.

---

## ✨ Core Capabilities

- **SSH Emulation** — Simulates an interactive terminal with basic command responses (`ls`, `whoami`, etc.)
- **Credential Logging** — Captures and stores login attempts (usernames/passwords)
- **GeoIP & WHOIS Lookup** — Extracts country and organization data of attacker IPs
- **Download Trap** — Monitors for `wget` or `curl` usage and logs URLs
- **Real-Time Alerts** — Sends Discord notifications for every incident
- **AbuseIPDB Reporting** — Reports malicious IP addresses to AbuseIPDB
- **Silent Operation Mode** — Optionally runs without revealing any interaction to the attacker
- **Live Firewall Rules** — Applies `iptables` rules to block repeated attackers instantly
- **Web Dashboard** — Flask-powered visual log viewer (localhost:5000)

---

## 🛠 Intended Use Cases

- **Cyber Threat Intelligence**: Feed real-world attacker behavior into your analysis workflows.
- **Red/Blue Team Operations**: Simulate high-value targets and observe tactics, techniques, and procedures (TTPs).
- **Security Education**: Use in cybersecurity labs and training environments.
- **SOAR Pipelines**: Integrate with automation playbooks via Discord/AbuseIPDB hooks.

---

## 👥 Ideal For

- Red team operators
- Blue team defenders / SOC analysts
- Security educators
- Cybersecurity researchers
- Ethical hackers and hobbyists

---

## 🚀 Quick Start

```bash
git clone https://github.com/yourname/HoneyTrapTR
cd HoneyTrapTR
pip install -r requirements.txt
sudo python3 honeypot_final.py
```

Start the web dashboard:

```bash
python3 panel.py
```

---

## ⚙ Configuration

Edit `honeypot_final.py`:

```python
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/..."
ABUSEIPDB_API_KEY = "your_key"
SILENT_MODE = False  # Set True for passive logging only
ENABLE_FIREWALL_BLOCK = True
```

---

## ⚖ Legal Disclaimer

This software is intended **strictly for authorized testing and research purposes**. Unauthorized deployment or use against third-party networks may be illegal.

---

## 📄 License

MIT License – free to use, modify and distribute under open source terms.