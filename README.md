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
![images](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/UFW-1.png)


Note: Kali Linux does not include UFW by default, as it primarily relies on iptables.
For this project, UFW was manually installed to demonstrate simplified firewall
management and rule documentation.
## Configure Default Firewall Policies
- Deny All Incoming Traffic
`sudo ufw default deny incoming`

- Allow All Outgoing Traffic
  `sudo ufw default allow outgoing`
## Allow Essential Inbound Traffic
- Allow SSH (VERY IMPORTANT)

- Even if you’re local now, always do this first.
  `sudo ufw allow ssh`

- or explicitly:
  `sudo ufw allow 22/tcp`
## Allow Web Traffic
```
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

## Allowing and Denying Firewall Ports

Firewall rules were configured to explicitly allow required services and deny
unused or insecure ports.

### Allowed ports:
- 22/tcp (SSH) for secure remote access `sudo ufw allow 22/tcp`
- note:
  * ✔️ Secure remote access
  * ✔️ Mandatory on servers
- 80/tcp (HTTP) for web traffic `sudo ufw allow 80/tcp`
  Note:
  * ✔️ Web traffic
  * ✔️ Common real-world services
- 443/tcp (HTTPS) for encrypted web traffic `sudo ufw allow 443/tcp`

### Denied ports:
- 21/tcp (FTP) due to plaintext credential transmission `sudo ufw deny 21/tcp`
- note:
  * ❌ Sends credentials in plaintext
  * ❌ High risk
- 23/tcp (Telnet) due to lack of encryption `sudo ufw deny 23/tcp`
- note:
  * ❌ No encryption
  * ❌ Common attack target
This configuration reduces the system attack surface while ensuring required
services remain accessible.

### 🔍 Verify Allowed Ports
`sudo ufw status numbered`

### 🔍 Verify Denied Ports
`sudo ufw status numbered`

```
### Connectivity Testing (Nmap)

Network connectivity was tested using Nmap from an external Ubuntu machine.

Scan command:
nmap 10.0.2.15

Results:
- Port 22/tcp (SSH) is open, confirming allowed inbound access
- All other TCP ports are closed or filtered
- No unnecessary services are exposed

This confirms that firewall rules are correctly enforced and only required
services are accessible.
```

![images](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/UFW-3.png)

### Firewall Log Monitoring

UFW logging was enabled to monitor firewall activity and verify rule enforcement.
Firewall logs were observed using the ufw.log file.

Blocked connection attempts were recorded when scanning denied ports, confirming
that firewall rules were actively enforced. Log entries included source IP,
destination IP, protocol, and destination port information.

Log monitoring provides visibility into suspicious activity and supports
incident investigation and troubleshooting.

### Enable Logging
`sudo ufw logging on`

- From ubuntu machine check the kali open ports

![image](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/ubuntu%20output-1.png)

### Blocked Port Verification (Telnet)

- A connection attempt was made from an external Ubuntu machine to port 23 (Telnet)
on the target system.

- Command used:
`telnet 10.0.2.15 23`

The connection was refused, confirming that the firewall successfully blocked
Telnet traffic. This verifies that insecure legacy services are effectively
restricted by the firewall configuration.

![image](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/ubuntu%20output-2.png)
### Set Logging Level
`sudo ufw logging medium`
 - note: UFW logs are stored at:
`/var/log/ufw.log`

### View Firewall Logs
`sudo tail /var/log/ufw.log`

### Monitor Logs in Real Time
`sudo tail -f /var/log/ufw.log`

![image](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/f%20log%20obsevation.png)

🔴 [UFW BLOCK]

Example:

```
[UFW BLOCK] IN=eth0 SRC=140.82.113.25 DST=10.0.2.15
```


Means:

  ❌ Traffic was blocked

  🌐 Came from an external IP

  🛡️ Firewall rule was enforced

  📌 Logged successfully

### This satisfies:
  ✅ Observe logs
  ✅ Block traffic
  ✅ Explain impact

### 🟢 [UFW ALLOW]

Example:

```
[UFW ALLOW] OUT=eth0 SRC=10.0.2.15 DST=192.168.1.1 DPT=53
```


Means:

  ✅ Outbound traffic allowed

  🌍 DNS requests (port 53)
 
  🔁 Normal system behavior

This proves:

   * Outbound rules are working

   * Stateful firewall behavior is correct


## 🪟 Windows Firewall Configuration

Windows Defender Firewall was configured using administrative command-line tools
to enforce secure inbound and outbound traffic policies. The firewall was enabled
for all network profiles to protect the system across public, private, and domain
networks.

---

### 🔐 Enable Windows Firewall

The firewall was enabled for all profiles using an elevated command prompt:

``powershell
```
netsh advfirewall set allprofiles state on
```
![image](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/wfw-1.jpeg)
  🛡️ Default Firewall Policies

To follow the principle of least privilege, default firewall policies were set
to block all inbound traffic while allowing outbound traffic.

```
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

- Inbound traffic is blocked by default to prevent unauthorized access

- Outbound traffic is allowed to enable normal system operations such as
 updates and web access

  ✅ Allow Required Inbound Ports

Only essential services were explicitly allowed through the firewall.
```
- netsh advfirewall firewall add rule name="Allow SSH" dir=in action=allow protocol=TCP localport=22
- netsh advfirewall firewall add rule name="Allow HTTP" dir=in action=allow protocol=TCP localport=80
- netsh advfirewall firewall add rule name="Allow HTTPS" dir=in action=allow protocol=TCP loc
```
![image]()
![image]()
![image]()
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
