# 🔥 Task 10: Firewall Configuration & Testing

## 📌 Project Overview
This project demonstrates practical firewall configuration and testing skills using host-based firewalls. The goal is to understand firewall concepts, configure security rules, test network connectivity, analyze logs, block malicious traffic, and document the impact of firewall rules.

This lab simulates real-world defensive security tasks commonly performed by system administrators and cybersecurity professionals.

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
## Firewall Definition: What Is A Network Firewall?
A firewall is a network security device designed to monitor, filter, and control incoming and outgoing network traffic based on predetermined security rules. The primary purpose of a firewall is to establish a barrier between a trusted internal network and untrusted external networks.

Firewalls come in both hardware and software forms, and they work by inspecting data packets and determining whether to allow or block them based on a set of rules. Organizations can configure these rules to permit or deny traffic based on various criteria, such as source and destination IP addresses, port numbers, and protocol type. 

### Firewalls have evolved through four distinct phases:
![images](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/firewall-types1.png)

- First-generation firewalls began in 1989 with the packet filtering approach. These firewalls examine individual data packets, making decisions to allow or block them based on predefined rules. However, these were unable to identify if those packets contained malicious code (i.e., malware).

- Second-generation firewalls began in the early 2000s. Otherwise known as stateful firewalls, these track the state of active connections. By observing network traffic, they use context to identify and act on suspicious behavior. Unfortunately, this generation also has its limitations.

- Third-generation firewalls emerged in the latter half of the early 2000s. Often called proxy firewalls or application-level gateways, these act as intermediaries between a client and server, forwarding requests and filtering responses.

- Fourth-generation firewall, also known as next-generation firewall (NGFW), started in 2010. NGFWs combine traditional capabilities with new, advanced features such as intrusion prevention (IPS), application-layer filtering, and advanced threat detection.

## How Does A Firewall Work?
Firewalls are essential security tools that monitor and control network traffic, acting like gatekeepers for your system. They inspect data packets, comparing them to predefined rules to determine whether to allow or block them. 


### How Firewalls Filter Traffic to Prevent Unauthorized Access

Process in 5 Steps:

1. Traffic Monitoring: Constantly monitors all incoming and outgoing network traffic, acting as a vigilant gatekeeper for your system.
2. Rule Application: Compares each data packet against predefined security rules to determine if it should be allowed or blocked.
3. Packet Inspection: Examines packet headers and contents, including source/destination IP addresses and ports, for suspicious activity.
4. Decision Making:  Based on inspection and rules, decides to allow legitimate traffic and block potential threats.
5. Logging and Alerts:  Maintains detailed logs of actions and generates alerts for suspicious activity or unauthorized access attempts.

## Firewall Types
![image](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/types-of-firewall.png)


## 🛠️ Tools Used
- **UFW (Uncomplicated Firewall)** – Linux
- **Windows Defender Firewall** – Windows
- **iptables** (Alternative / Advanced option)
- **nmap** – Port scanning
- **ping / curl / telnet** – Connectivity testing
- **log files** – Firewall event analysis

---


## ⚙️ Configure inbound and outbound Firewall Configuration

### 1️⃣ Enable Firewall
**Linux (UFW):**
```bash
`sudo ufw enable`
`sudo ufw status verbose`
```
![images]()

Note: Kali Linux does not include UFW by default, as it primarily relies on iptables.
For this project, UFW was manually installed to demonstrate simplified firewall
management and rule documentation.


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
- 
## 📚 Firewall Concepts Covered
- Inbound vs Outbound traffic
- Stateful vs Stateless firewalls
- Default deny vs default allow
- Port-based filtering
- IP-based blocking
- Logging and monitoring

---

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
