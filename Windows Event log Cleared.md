# Windows Security Event Log Cleared (Event ID 1102)

**Tactic:** Defense Evasion (TA0005)
**Technique:** T1070.001 Indicator Removal: Clear Windows Event Logs
**Severity:** High
**Data source:** SecurityEvent (Windows Security Events via AMA)
**Detection type:** Microsoft Sentinel Scheduled Analytics Rule
**Affected host:** WIN-SERVER (domain controller, soclab.local)


This detection identifies when the Windows Security event log is cleared, which produces Event ID 1102. Clearing the security log is a deliberate defense evasion action. After gaining access, an attacker wipes local event history to hide earlier activity such as logons, privilege use, and command execution.

Because clearing the security log is a rare and intentional action, this rule alerts on any single occurrence rather than requiring a threshold. Alert grouping is enabled so repeated clears roll into one incident instead of many, applying the lesson learned from the brute force scenario.

An important point this scenario demonstrates: clearing the local log does not remove the evidence. The Azure Monitor Agent forwards every security event to the Log Analytics workspace as it happens, so Microsoft Sentinel already holds a copy in the cloud by the time the log is cleared on the host. The local record is destroyed but the SIEM record is not. This is the core reason centralized logging matters.

---

## Attack Simulation

The log clear was run directly on the domain controller as an account with administrative rights, which represents an attacker with admin access covering their tracks after a compromise.

Run on WIN-SERVER (PowerShell):

```
Clear-EventLog -LogName Security
```

Command breakdown:

`Clear-EventLog` wipes a Windows event log. `-LogName Security` targets the Security log specifically, which is the log the detections rely on. The moment the log is cleared, Windows writes a fresh Event ID 1102 that records the action, and that event is what the rule detects.

A remote execution path from Kali was considered (NetExec with smbexec running the clear as the compromised testtarget account), but that path is blocked by Defender for Endpoint, the same behavioral block seen in the account creation scenario. Running the clear locally as an admin reliably produces the 1102 event and keeps this a clean Sentinel detection story. Note that clearing the log permanently wipes the local Security log on WIN-SERVER, but the events already ingested into the SecurityEvent table in the workspace are preserved.



---

## Detection Logic (KQL)

<img width="1250" height="370" alt="image" src="https://github.com/user-attachments/assets/ecda7031-010a-411f-877e-7a53d165008e" />


---

## Analytics Rule Configuration

| Setting | Value |
|---|---|
| Rule type | Scheduled query rule (Sentinel, Configuration, Analytics) |
| Run frequency | Every 5 minutes |
| Lookup period | Last 1 hour |
| Alert threshold | Number of results greater than 0 |
| Severity | High |
| Alert grouping | Enabled, group related alerts into a single incident |
| Incident creation | Create incidents from alerts set to On |

This must be a Sentinel Scheduled Analytics Rule, not a Defender XDR Custom Detection Rule. Only the Sentinel scheduled rule with incident creation enabled produces an incident in the queue.

---



## Detection and Correlation Finding

Two things happened when the log was cleared, and both are worth documenting.

The Sentinel scheduled rule produced an alert on the 1102 event as designed. At the same time, Defender for Endpoint independently detected the log clearing and created its own incident. Sentinel created an alert but not a separate visible incident, because the unified correlation engine merged the Sentinel alert into the Defender created incident rather than raising a duplicate. This is not a Sentinel failure. The same merging behavior appeared in the brute force scenario, and the correct way to confirm what fired is to query the SecurityIncident table rather than assuming an incident is absent just because the queue does not show a separate Sentinel entry.

The takeaway is defense in depth. Two independent controls, the SIEM rule and the endpoint product, both caught the same action, and the platform correlated them into a single case for the analyst.

<img width="2664" height="636" alt="image" src="https://github.com/user-attachments/assets/1d9f0923-edf5-4929-bf14-f7c2d1d4ba5a" />

Both Microsoft Defender for Endpoint and Microsoft Sentinel detected the log clearing, but they reported it at different severity levels. That difference comes down to how each engine assigns severity. The Sentinel severity was set manually to High when the analytics rule was created, reflecting a deliberate decision that clearing the security log always warrants analyst review. Defender for Endpoint, by contrast, scores risk dynamically based on context, and it rated this event low. Because the clear was performed locally by the Administrator account and did not correlate with any surrounding chain of suspicious activity, the EDR assessed it as routine administrative behavior rather than an attack.


## Root Cause and Remediation

**Access to clear the log was too broad.**
Clearing the Security log requires the Manage auditing and security log right (SeSecurityPrivilege). The solution is to audit which accounts hold this right and remove it from any account that does not need it.

**The clearing account may be compromised.**
The account that cleared the log should be treated as suspect. The solution is to reset its credentials and investigate the surrounding activity for other signs of compromise, such as logons, privilege escalation, and process creation in the same window.

**Local logs are not a reliable record.**
Because logs can be cleared on the host, the durable defense is real time forwarding to a SIEM. The solution is to keep the Azure Monitor Agent and the Windows Security Events connector active so events are shipped to Sentinel before they can be removed locally.

**Detection depends on correlation.**
A single log clear with no surrounding activity may be a legitimate administrative action. The solution is to correlate the event with a timeline of prior activity, which is what separates routine maintenance from attacker cleanup.

---


## MITRE ATT&CK Mapping

| Tactic | Technique | Notes |
|---|---|---|
| Defense Evasion | T1070.001 Indicator Removal: Clear Windows Event Logs | Security log cleared on the domain controller to hide prior activity |
