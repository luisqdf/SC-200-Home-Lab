
# 🛡️ Microsoft Sentinel — Brute Force Detection & Account Monitoring Home Lab

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SIEM-blue?style=for-the-badge&logo=microsoft)
![KQL](https://img.shields.io/badge/KQL-Query%20Language-orange?style=for-the-badge)


## 📌 Overview

This home lab is part of my preparation for the **Microsoft SC-200: Microsoft Security Operations Analyst** certification. The goal is to simulate real-world attack scenarios inside a cloud environment and use **Microsoft Sentinel** to detect, investigate, and respond to threats using **KQL (Kusto Query Language)**.

This project demonstrates the skills expected of a **Security Operations Center (SOC) Analyst**, including threat detection, log analysis, and incident monitoring — all core competencies tested in the SC-200 exam and required in real SOC environments.

---

## 🎯 Objectives

- Deploy and configure **Microsoft Sentinel** with a Log Analytics Workspace
- Ingest **Windows Security Event Logs** into Sentinel
- Write **KQL queries** to detect attack patterns from raw log data
- Simulate a brute force attack and trace the full attack chain:
  1. Multiple failed login attempts
  2. Successful login after brute force
  3. Attacker creates a backdoor account
  4. Attacker escalates privileges by adding account to Administrators group

---

## 🧰 Tools & Technologies

| Tool | Purpose |
|------|---------|
| Microsoft Azure | Cloud environment hosting the lab |
| Microsoft Sentinel | SIEM/SOAR platform for detection and response |
| Log Analytics Workspace | Central log ingestion and querying |
| Windows Security Event Logs | Primary data source for all detections |
| KQL (Kusto Query Language) | Query language used to detect threats |

---

## 📋 Windows Security Event IDs

These are the specific Windows Event IDs monitored in this lab:

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| **4625** | Failed logon attempt | Core indicator of brute force activity |
| **4624** | Successful logon | Used to detect a successful compromise after failures |
| **4720** | A user account was created | Attackers create backdoor accounts for persistence |
| **4732** | A member was added to the local Administrators group | Indicates privilege escalation |

---

## 🔍 KQL Detection Queries

### 🔴 1. Brute Force Detection — Multiple Failed Logins (Event ID 4625)
Detects any account receiving **10 or more failed login attempts within 1 hour**.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 1h)
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

---

### 🟡 2. Successful Login Following Multiple Failures (Event ID 4625 → 4624)
Detects a **successful login from an account that previously had 5+ failed attempts** — a strong indicator of a successful brute force compromise.

```kql
let FailedLogins = SecurityEvent
| where EventID == 4625
| summarize FailCount = count() by Account, IpAddress
| where FailCount >= 5;
SecurityEvent
| where EventID == 4624
| join kind=inner FailedLogins on Account
| project TimeGenerated, Account, IpAddress, FailCount
```

---

### 🟠 3. New User Account Created (Event ID 4720)
Monitors for **any new user account creation**, which attackers use to establish persistence.

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Account, SubjectUserName, Computer
| order by TimeGenerated desc
```

---

### 🔴 4. User Added to Administrators Group (Event ID 4732)
Detects **privilege escalation** — when any account is added to the local Administrators group.

```kql
SecurityEvent
| where EventID == 4732
| project TimeGenerated, Account, MemberName, SubjectUserName, Computer
| order by TimeGenerated desc
```

---

## 🔗 Attack Chain Simulated

This lab simulates the following attack progression:

```
[Attacker] 
    │
    ├── 1. Runs brute force against target (Event ID 4625 — repeated failures)
    │
    ├── 2. Guesses correct password (Event ID 4624 — successful login)
    │
    ├── 3. Creates new backdoor user account (Event ID 4720)
    │
    └── 4. Adds backdoor account to Administrators group (Event ID 4732)
```

Each step in this chain is detectable using the KQL queries above inside Microsoft Sentinel.

---

## 📁 Repository Structure

```
📦 sc-200-sentinel-lab
 ┣ 📂 kql-queries
 ┃ ┣ 📄 brute-force-detection.kql
 ┃ ┣ 📄 successful-login-after-failure.kql
 ┃ ┣ 📄 account-creation.kql
 ┃ ┗ 📄 privilege-escalation.kql
 ┣ 📂 screenshots
 ┃ ┗ 📄 (Sentinel dashboards, query results, incidents)
 ┗ 📄 README.md
```

---

## 📸 Screenshots
> *(To be added — Sentinel workspace, query results, triggered alerts, and incidents)*

---

## 🚀 Status & Roadmap

- [x] Define detection use cases and Event IDs
- [x] Write KQL detection queries
- [ ] Deploy Azure environment and configure Sentinel
- [ ] Ingest Windows Security Event Logs
- [ ] Run and validate KQL queries against live data
- [ ] Create Sentinel Analytics Rules to auto-trigger alerts
- [ ] Document screenshots and findings

---

## 👤 About This Project

This lab is part of my cybersecurity portfolio as I work toward the **Microsoft SC-200 certification**. It is designed to showcase hands-on skills in:

- Cloud-based SIEM configuration
- Threat detection using real Windows event log data
- KQL query writing for security investigations
- Understanding attacker behavior and the attack lifecycle

Feel free to reach out if you have questions or feedback!

---

## 📄 License
This project is for educational purposes only.
