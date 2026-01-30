# 🔥 Task 10: Firewall Configuration & Testing

## 📌 Project Overview
This project demonstrates practical firewall configuration and testing skills using host-based firewalls. The goal is to understand firewall concepts, configure security rules, test network connectivity, analyze logs, block malicious traffic, and document the impact of firewall rules.

This lab simulates real-world defensive security tasks commonly performed by system administrators and cybersecurity professionals.

---

## 🛠️ Tools Used
- **UFW (Uncomplicated Firewall)** – Linux
- **Windows Defender Firewall** – Windows
- **iptables** (Alternative / Advanced option)
- **nmap** – Port scanning
- **ping / curl / telnet** – Connectivity testing
- **log files** – Firewall event analysis

---

## 🎯 Objectives
- Learn core firewall concepts
- Configure inbound and outbound firewall rules
- Allow and deny specific ports
- Test network connectivity after rule changes
- Observe and analyze firewall logs
- Block a malicious IP address
- Document firewall rules clearly
- Explain the security impact of configurations

---

## 📚 Firewall Concepts Covered
- Inbound vs Outbound traffic
- Stateful vs Stateless firewalls
- Default deny vs default allow
- Port-based filtering
- IP-based blocking
- Logging and monitoring

---

## ⚙️ Firewall Configuration

### 1️⃣ Enable Firewall
**Linux (UFW):**
``bash
`sudo ufw enable`
`sudo ufw status verbose`
Windows:

# Windows Security → Firewall & Network Protection → Enable Firewall
2️⃣ Set Default Policies
- sudo ufw default deny incoming
- sudo ufw default allow outgoing
✔️ This follows the principle of least privilege.

# 3️⃣ Allow Required Ports
- `sudo ufw allow ssh`
- `sudo ufw allow 80/tcp`
- `sudo ufw allow 443/tcp`
- `Port	Service	Reason`
- `22	SSH	Remote administration`
- `80	HTTP	Web traffic`
- `443	HTTPS	Secure web traffic`
# 4️⃣ Deny Unused or Risky Ports
- `sudo ufw deny 21`
- `sudo ufw deny 23`
- `Port	Service	Risk`
- `21	FTP	Cleartext credentials`
- `23	Telnet	Insecure protocol`
# 5️⃣ Block a Malicious IP
`sudo ufw deny from 192.168.1.100`
✔️ Prevents communication from a known malicious or suspicious source.

#🧪 Testing & Verification
- Connectivity Tests
- ping google.com
- curl http://localhost
- Port Scanning
- nmap localhost
- ✔️ Confirms allowed ports are accessible
- ❌ Blocked ports are unreachable

#📄 Log Monitoring
View Firewall Logs (Linux)
`sudo tail -f /var/log/ufw.log`
- ✔️ Observed blocked packets
- ✔️ Verified denied IP traffic
- ✔️ Confirmed rule enforcement

📝 Firewall Rules Documentation
Rule #	Action	Port/IP	Protocol	Purpose
- 1	Allow	22	TCP	Secure remote access
- 2	Allow	80	TCP	Web traffic
- 3	Allow	443	TCP	Secure web traffic
- 4	Deny	21	TCP	Block FTP
- 5	Deny	23	TCP	Block Telnet
- 6	Deny	192.168.1.100	All	Block malicious IP
#🔍 Security Impact Analysis
- Reduced attack surface by blocking unused services

- Prevented unauthorized inbound connections

- Mitigated risk from insecure legacy protocols

- Improved visibility through logging

- Demonstrated effective host-based firewall management

# 📦 Deliverables
- Firewall rules documentation

- Connectivity test results

- Log analysis

- Security impact explanation

# ✅ Final Outcome
- ✔️ Practical firewall management skills
- ✔️ Hands-on experience with real security tools
- ✔️ Portfolio-ready cybersecurity project

# 🚀 Future Improvements
- Automate rule deployment with scripts

- Integrate IDS/IPS (Snort / Suricata)

- Centralized logging with SIEM

- Apply firewall hardening benchmarks

# 🧑‍💻 Author
[NATTO MUNI CHAKMA]
Cybersecurity Student | Blue Team | Network Security
