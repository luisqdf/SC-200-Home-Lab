# SC-200 Home Lab — SOC Detection and Response

A self-built SOC environment simulating real-world detection and response scenarios, created while studying for the Microsoft SC-200 certification.

## Overview

This home lab is part of my preparation for the Microsoft SC-200: Microsoft Security Operations Analyst certification. The goal is to simulate real-world attack scenarios inside a cloud environment and use Microsoft Sentinel to detect, investigate, and respond to threats using KQL (Kusto Query Language).

The project demonstrates core SOC analyst skills — threat detection, log analysis, and incident response — tested in the SC-200 exam and used in real SOC work.

## Goal

Simulate a realistic, multi-stage intrusion against the lab domain (soclab.local) from an attacker machine (Kali Linux, kept outside the domain trust), and demonstrate detection, investigation, and response using Microsoft Defender for Endpoint, Microsoft Defender for Identity, and Microsoft Sentinel.

Rather than testing isolated detections, the lab follows a single continuous attack narrative — the way a real intrusion actually unfolds — with each stage mapped to the MITRE ATT&CK framework.

## Attack Chain Overview

Kali Linux (attacker, untrusted)
│
▼
[1] Brute Force ──► [2] Execution ──► [3] Persistence & Privilege Escalation
│
┌─────────────────────────────────────────┘
▼
[4] Credential Access (LSASS + Kerberoasting) ──► [5] Lateral Movement ──► [6] Defense Evasion

## Stage-by-Stage Breakdown

| # | Stage | MITRE ATT&CK Technique | Tactic | Target | Detection Source |
|---|-------|------------------------|--------|--------|-------------------|
| 1 | Brute-force login attempts, followed by a successful login | T1110 – Brute Force | Credential Access → Initial Access | testtarget decoy account on WIN-SERVER | Microsoft Sentinel — scheduled analytics rule on the SecurityEvent table (Event IDs 4625/4624), collected via Azure Monitor Agent + DCR |
| 2 | Suspicious PowerShell / living-off-the-land execution | T1059.001 – PowerShell | Execution | WIN-SERVER | Defender for Endpoint (DeviceProcessEvents) |
| 3 | Backdoor account creation, then added to Administrators group | T1136 – Create Account / T1098 – Account Manipulation | Persistence / Privilege Escalation | WIN-SERVER (AD) | Defender for Identity (IdentityDirectoryEvents) |
| 4a | LSASS memory dumping to harvest cached credentials | T1003.001 – OS Credential Dumping: LSASS Memory | Credential Access | WIN-SERVER | Defender for Endpoint |
| 4b | Kerberoasting — bulk service ticket requests for offline cracking | T1558.003 – Kerberoasting | Credential Access | WIN-SERVER (AD) | Defender for Identity |
| 5 | Lateral movement using harvested credentials (Pass-the-Hash) | T1550.002 – Pass the Hash | Lateral Movement | WIN-11PRO | Defender for Endpoint + Identity |
| 6 | Defense evasion — clearing logs / tampering with security tooling | T1070.001 – Clear Windows Event Logs / T1562.001 – Impair Defenses | Defense Evasion | WIN-SERVER | Defender for Endpoint |

## Why This Structure

Realistic ordering — this is the sequence a genuine attacker typically follows: get in, establish a foothold, escalate, harvest more credentials, spread, then cover their tracks.

Dual-sensor coverage — the chain includes both identity-layer attacks (brute force, Kerberoasting, account manipulation) and endpoint-layer attacks (PowerShell abuse, LSASS dumping, log tampering), showing why Defender for Endpoint and Defender for Identity are needed together rather than either alone.

Safe by design — all attacks are run against a dedicated decoy account (testtarget), never against real lab accounts, and entirely within an isolated lab network with no production impact.

## Environment

| Machine | Role | Notes |
|---|---|---|
| WIN-SERVER | Domain Controller (soclab.local) | Windows Server 2025, Server Core. Defender for Endpoint + Defender for Identity |
| WIN-11PRO | Domain-joined workstation | Windows 11 Enterprise. Defender for Endpoint |
| BeticoKali | Attacker machine | Kali Linux, outside the domain trust, no Defender agent |

## Roadmap

### Stage 1 — Initial Access: Brute Force
Technique: T1110 – Brute Force | Detection: Microsoft Sentinel (SecurityEvent, Event IDs 4625/4624). Status: Complete — full writeup below.

### Stage 2 — Execution: Suspicious PowerShell / LOLBins
Technique: T1059.001 – PowerShell | Detection: Defender for Endpoint (DeviceProcessEvents)

Execute a suspicious PowerShell command (encoded command / download cradle) on WIN-SERVER post-compromise, and trace the resulting Defender for Endpoint alert.

### Stage 3 — Persistence & Privilege Escalation: Backdoor Account
Technique: T1136 – Create Account / T1098 – Account Manipulation | Detection: Defender for Identity (IdentityDirectoryEvents)

Create a new AD user account and add it to the Administrators group, simulating an attacker establishing persistent, privileged access.

### Stage 4a — Credential Access: LSASS Dumping
Technique: T1003.001 – OS Credential Dumping: LSASS Memory | Detection: Defender for Endpoint

Dump LSASS memory to harvest cached credentials, and trace the resulting Defender for Endpoint alert.

### Stage 4b — Credential Access: Kerberoasting
Technique: T1558.003 – Kerberoasting | Detection: Defender for Identity

Request service tickets in bulk for offline cracking, and trace the resulting Defender for Identity alert.

### Stage 5 — Lateral Movement: Pass-the-Hash
Technique: T1550.002 – Pass the Hash | Detection: Defender for Endpoint + Identity

Use harvested credentials to authenticate from WIN-11PRO without the plaintext password, simulating an attacker spreading across the domain.

### Stage 6 — Defense Evasion: Log Tampering
Technique: T1070.001 – Clear Windows Event Logs / T1562.001 – Impair Defenses | Detection: Defender for Endpoint

Attempt to clear event logs or disable security tooling to cover tracks, and trace the resulting alert.

