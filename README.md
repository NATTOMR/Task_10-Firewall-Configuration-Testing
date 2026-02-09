<p align="center">
  <img src="images/banner.png" alt="Firewall Configuration & Testing" width="100%" height="350">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Project-Firewall%20Configuration%20%26%20Testing-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Firewall-UFW%20%7C%20Windows%20Defender-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Security-Blue%20Team-informational?style=for-the-badge" />
</p>
# 🔐 Firewall Configuration & Testing

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

``
![images](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/UFW-3.png)
---
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
---
### Set Logging Level
`sudo ufw logging medium`
 - note: UFW logs are stored at:
`/var/log/ufw.log`

### View Firewall Logs
`sudo tail /var/log/ufw.log`

### Monitor Logs in Real Time
`sudo tail -f /var/log/ufw.log`

![image](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/f%20log%20obsevation.png)
---
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
    
  > ✅ Observe logs
  > ✅ Block traffic
  > ✅ Explain impact
---
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
----

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
![image](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/wfw-2.jpeg)
![image](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/wfw-3.jpeg)
![image](https://github.com/NATTOMR/Task_10-Firewall-Configuration-Testing/blob/main/images/wfw-4.jpeg)

### 🧱 Blocking a Malicious IP Address (Windows Firewall)

Blocking a malicious IP address is a common defensive security measure used to
prevent unauthorized access, repeated attack attempts, or suspicious network
activity.

---

####  Block Malicious IP (Inbound Traffic)

The following command was executed in an **elevated Command Prompt / PowerShell**
to block all inbound traffic from the malicious IP address:

powershell <br>
`netsh advfirewall firewall add rule name="Block Malicious IP" dir=in action=block remoteip=140.82.113.25`

---

## 📊 Firewall Rules Summary Table

| Rule No. | Platform | Direction | Action | Port / IP | Protocol | Purpose |
|--------|----------|-----------|--------|-----------|----------|---------|
| 1 | Linux (UFW) | Inbound | Allow | 22 | TCP | Secure remote administration |
| 2 | Linux (UFW) | Inbound | Allow | 80 | TCP | Allow web traffic |
| 3 | Linux (UFW) | Inbound | Allow | 443 | TCP | Allow secure web traffic |
| 4 | Linux (UFW) | Inbound | Deny | 21 | TCP | Block insecure FTP |
| 5 | Linux (UFW) | Inbound | Deny | 23 | TCP | Block insecure Telnet |
| 6 | Linux (UFW) | Inbound | Deny | 140.82.113.25 | All | Block malicious IP |
| 7 | Windows | Inbound | Allow | 22 | TCP | Allow SSH |
| 8 | Windows | Inbound | Allow | 80 | TCP | Allow HTTP |
| 9 | Windows | Inbound | Allow | 443 | TCP | Allow HTTPS |
| 10 | Windows | Inbound | Block | 21 | TCP | Block FTP |
| 11 | Windows | Inbound | Block | 23 | TCP | Block Telnet |
| 12 | Windows | Inbound | Block | 140.82.113.25 | All | Block malicious IP |


### 🔐 Default Firewall Policies

| Platform | Incoming Traffic | Outgoing Traffic | Security Model |
|--------|------------------|------------------|----------------|
| Linux (UFW) | Deny | Allow | Least Privilege |
| Windows Firewall | Block | Allow | Least Privilege |

---

### 🛡️ Overall Security Impact
- Reduced system attack surface  
- Prevented unauthorized inbound access  
- Blocked insecure legacy services  
- Mitigated threats from malicious IP addresses  
- Enforced least-privilege network access model  

This firewall configuration demonstrates effective host-based security hardening
across both Linux and Windows environments.

---

# ✅ Final Outcome
- ✔️ Practical firewall management skills
- ✔️ Hands-on experience with real security tools
- ✔️ Portfolio-ready cybersecurity project

## 🏁 Conclusion

This project demonstrated practical firewall configuration and testing across
both Linux and Windows environments using host-based firewalls. UFW was used on
Kali Linux to configure inbound and outbound rules, enforce a deny-by-default
policy, monitor firewall logs, and block malicious traffic. Windows Defender
Firewall was configured using administrative command-line tools to apply similar
security controls and enforce least-privilege access.

Firewall rules were tested using tools such as Nmap and Telnet from an external
system, confirming that only required services were accessible while insecure
and unused ports were successfully blocked. Firewall logging and system journal
analysis verified that rules were actively enforced and provided visibility into
allowed and denied traffic.

## 📚 Security References

1. NIST. (2009). *Guidelines on Firewalls and Firewall Policy (SP 800-41 Rev.1)*.  
   https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final

2. OWASP Foundation. (n.d.). *Network Security and Hardening*.  
   https://owasp.org

3. Microsoft. (n.d.). *Windows Defender Firewall with Advanced Security*.  
   https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/

4. Canonical Ltd. (n.d.). *UFW – Uncomplicated Firewall Documentation*.  
   https://help.ubuntu.com/community/UFW

5. Nmap Project. (n.d.). *Nmap Network Scanning Reference Guide*.  
   https://nmap.org/book/man.html <br>
   
> **⚠️ All configurations and testing procedures in this project were performed in a
> controlled virtual lab environment for educational purposes.**


# 🧑‍💻 Author
[NATTO MUNI CHAKMA] <br>
 Cybersecurity Enthusiast | SOC & Blue Team Learner
