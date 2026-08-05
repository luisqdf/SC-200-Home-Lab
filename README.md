# SC-200 Home Lab, SOC Detection and Response

A self-built SOC environment simulating real-world detection and response scenarios, created while studying for the Microsoft SC-200 certification.

## Overview

This home lab is part of my preparation for the Microsoft SC-200: Microsoft Security Operations Analyst certification. The goal is to simulate real-world attack scenarios inside a cloud environment and use Microsoft Sentinel to detect, investigate, and respond to threats using KQL (Kusto Query Language).

The project demonstrates core SOC analyst skills like threat detection, log analysis, and incident response. These are tested in the SC-200 exam and used in real SOC work.

Red team tooling such as Kali Linux, NetExec, and the Impacket suite is used only to generate realistic attack telemetry. This is a defensive project at heart (Blue team). The goal is not the attack itself, but observing how Microsoft Defender and Sentinel detect, alert on, and respond to each technique once it reaches the environment.

## Goal

Simulate a realistic, multi-stage intrusion against the lab domain (soclab.local) from an attacker machine (Kali Linux, kept outside the domain trust), and demonstrate detection, investigation, and response using Microsoft Defender for Endpoint, Microsoft Defender for Identity, and Microsoft Sentinel.

Rather than testing isolated detections, the lab follows a single continuous attack narrative, the way a real intrusion actually unfolds, with each stage mapped to the MITRE ATT&CK framework.

## Attack Chain Overview

```
BeticoKali (Kali Linux, attacker, outside the domain)
        │
        │  attacks over the network
        ▼
WIN-SERVER (Domain Controller, soclab.local)
        │
        ▼
[1] Brute Force
[2] Suspicious PowerShell
[3] Account Creation
[4] Log Clearing
```



## Stage-by-Stage Breakdown


| # | Stage | MITRE ATT&CK Technique | Tactic | Target | Detection Source |
| --- | --- | --- | --- | --- | --- |
| 1 | Brute Force | T1110, Brute Force | Credential Access | testtarget decoy account on WIN-SERVER | Microsoft Sentinel, scheduled analytics rule on SecurityEvent (Event IDs 4625/4624) |
| 2 | Suspicious PowerShell | T1059.001, PowerShell | Execution | WIN-SERVER | Defender for Endpoint (DeviceProcessEvents) |
| 3 | Account Creation | T1136, Create Account | Persistence | WIN-SERVER (AD) | Defender for Endpoint, with Sentinel as backup on Event ID 4720 |
| 4 | Log Clearing | T1070.001, Clear Windows Event Logs | Defense Evasion | WIN-SERVER | Defender for Endpoint and Microsoft Sentinel |

## Why This Structure

The four stages follow the sequence a real intrusion actually unfolds in: break in (Credential Access), run commands on the host (Execution), plant a way back in (Persistence), then wipe the evidence (Defense Evasion). Each stage is the logical next move after the one before it, which is what makes the chain read as a single story rather than four unrelated tests.

The chain is deliberately covered by two independent controls: the SIEM layer (Microsoft Sentinel, reading Windows security events forwarded from the domain controller) and the EDR layer (Microsoft Defender for Endpoint, reading live device telemetry). Several stages are caught by both at once and correlated into a single incident. That is the whole point: no single control is the entire defense, and when one layer is bypassed, the other still catches the activity.


## Environment

| Machine | Role | Notes |
|---|---|---|
| WIN-SERVER | Domain Controller (soclab.local) | Windows Server 2025, Server Core. Defender for Endpoint and Defender for Identity |
| WIN-11PRO | Domain-joined workstation | Windows 11 Enterprise. Defender for Endpoint |
| BeticoKali | Attacker machine | Kali Linux, outside the domain trust, no Defender agent |

## Roadmap

### Stage 1, Initial Access: Brute Force
Technique: T1110, Brute Force. Detection: Microsoft Sentinel (SecurityEvent, Event IDs 4625/4624).
Ran a brute force from the Kali attacker host against the testtarget account on WIN-SERVER, produced a burst of failed logons followed by a success, and detected it with a scheduled Sentinel analytics rule. Triaged the incident, confirmed the account was compromised, contained it, and documented the root cause.

### Stage 2, Execution: Suspicious PowerShell
Technique: T1059.001, PowerShell. Detection: Defender for Endpoint (DeviceProcessEvents).
Execute a suspicious PowerShell command on WIN-SERVER post-compromise and trace the resulting Defender for Endpoint detection.

### Stage 3, Persistence: Account Creation
Technique: T1136, Create Account. Detection: Defender for Endpoint, with Microsoft Sentinel as a backup on Event ID 4720.
Used the compromised testtarget account to attempt remote creation of a backdoor account on the domain controller. Defender for Endpoint blocked the execution and Attack Disruption automatically contained the account. Triaged the incident, verified the account was never created, confirmed the scope of the automated response, and documented the root cause.

### Stage 4, Defense Evasion: Log Clearing
Technique: T1070.001, Clear Windows Event Logs. Detection: Defender for Endpoint and Microsoft Sentinel.
Cleared the Security event log on WIN-SERVER to simulate an attacker covering their tracks, which generated Event ID 1102. Both Defender for Endpoint and a Sentinel analytics rule detected it, and the platform correlated them into a single incident.
