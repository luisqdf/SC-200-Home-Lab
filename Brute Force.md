# Stage 1 — Brute-Force Attack Detection (T1110)

**Tactic:** Credential Access → Initial Access
**Technique:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
**Detection source:** Microsoft Sentinel scheduled analytics rule on the `SecurityEvent` table (Event IDs 4625 / 4624), collected from the domain controller via the Azure Monitor Agent and a Data Collection Rule.

---

## Objective

Simulate a credential brute-force attack against a decoy domain account and detect the resulting failed-logon pattern in Microsoft Sentinel.

---

## Attack Simulation

From a Kali Linux attacker node (`192.168.50.20`), a brute-force attack was launched against the domain controller (`WIN-SERVER`, `192.168.50.10`) targeting the decoy account `testtarget`, using NetExec over SMB:

```bash
netexec smb 192.168.50.10 -u testtarget -p ~/wordlist_big.txt
```

The wordlist contained 101 passwords — 100 incorrect, with the correct password placed last — simulating a realistic attack that eventually succeeds. This generated approximately 100 failed logon events (Event ID 4625) followed by one successful logon (Event ID 4624).

<img width="900" alt="NetExec brute-force run against the domain controller" src="https://github.com/user-attachments/assets/b4de04cf-89fe-485d-a640-f1a273663e1d" />

---

## Detection

The activity was detected in Microsoft Sentinel via a scheduled analytics rule querying the `SecurityEvent` table. The rule flags any account exceeding a threshold of failed logons within the query window, and returns the successful logon count, source IP addresses, and the exact attack window as supporting context:

```kusto
SecurityEvent
| where EventID in (4624, 4625)
| where Account has "testtarget"
| summarize FailedLogons     = countif(EventID == 4625),
            SuccessfulLogons = countif(EventID == 4624),
            SourceIPs        = make_set(IpAddress),
            FirstAttempt     = min(TimeGenerated),
            LastAttempt      = max(TimeGenerated)
    by Computer
| where FailedLogons > 5
```

| Setting | Value |
|---|---|
| Rule type | Scheduled analytics rule |
| Run frequency | Every 5 minutes |
| Lookback period | Last 1 hour |
| Threshold | Trigger if query returns more than 0 results |
| Severity | Medium |
| MITRE mapping | T1110 – Brute Force (Credential Access) |

<!-- Add your analytics rule and workbook screenshots here, each on its own line -->

---

## Investigation and Triage

### True-Positive Determination

The raw evidence was pulled to validate the alert:

```kusto
SecurityEvent
| where EventID in (4624, 4625)
| where Account has "testtarget"
| project TimeGenerated, EventID, Account, IpAddress, Computer, LogonType
| order by TimeGenerated asc
```

| Indicator | Observation | Assessment |
|---|---|---|
| Time compression | ~100 failures within seconds | Automated tool, not human error |
| Source | Single IP (`192.168.50.20`) | Targeted attack from one host |
| Outcome | Failures followed by one success (4624) | Account compromised |

**Verdict: True Positive.** The volume, speed, and single-source pattern are consistent with an automated brute-force tool, and the trailing successful logon indicates the account was compromised.

### Enrichment — Source IP

The source address `192.168.50.20` falls within the private range `192.168.0.0/16` and is therefore internal to the environment. An internal source raises severity rather than lowering it: it indicates the attacker is already operating inside the network — a compromised host or a malicious insider — rather than probing from the internet.

### Containment

Because a successful logon occurred, `testtarget` is treated as compromised and disabled to prevent further use while the investigation continues:

```powershell
Disable-ADAccount -Identity testtarget
```

In a production environment, containment weighs attacker disruption against business impact; a critical service account might be reset and monitored rather than hard-disabled.

### Scope

The account's activity was reviewed to determine whether the compromise spread to other systems:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Account has "testtarget"
| summarize Machines = make_set(Computer), Events = count() by EventID
```

During enumeration, `testtarget` was found to hold local administrator rights on the domain controller (NetExec `--shares` returned the `ADMIN$` and `C$` administrative shares). This is a significant misconfiguration: a single guessed password provides a direct path to full domain compromise and would enable remote code execution via PsExec, WMI, or WinRM.

### Remediation

- Reset the `testtarget` password and enforce a strong password policy.
- Remove `testtarget` from the local Administrators group on the domain controller. Standard user accounts should never hold administrative rights on a domain controller.
- Implement an account lockout policy to slow future brute-force attempts.

---

## Incident Closure

| Field | Value |
|---|---|
| Classification | True Positive |
| Severity | Medium (elevated by internal source and administrative misconfiguration) |
| Scope | Limited to `WIN-SERVER`; no confirmed lateral movement |
| Business impact | None (controlled lab; decoy account) |
| Containment | Account disabled |
| Remediation | Password reset; administrative rights removed; lockout policy recommended |
| Status | Resolved / Monitoring |

---

## Key Takeaways

- A brute force is defined by the flood of failed logons (4625); the trailing success (4624) is what escalates it from an attempt to a compromise.
- Windows records the same account under different formats (`SOCLAB\testtarget` versus `soclab.local\testtarget`) depending on whether NTLM or Kerberos handled the request. Detections must tolerate this by matching on the username or grouping on a stable field such as `Computer`, rather than assuming a single spelling.
- An internal attack source is more concerning than an external one, as it indicates the attacker is already inside the network.
- The most significant finding was not the brute force itself but the over-privileged decoy account, surfaced during the scoping step.
