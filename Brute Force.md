# Stage 1 — Brute-Force Attack Detection (MITRE T1110)

> **Tactic:** Credential Access → Initial Access
> **Technique:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
> **Detection source:** Microsoft Sentinel — Scheduled Analytics Rule on the `SecurityEvent` table (EventIDs 4625 / 4624), collected via Azure Monitor Agent + Data Collection Rule.

---

## 🎯 Objective

Simulate a credential brute-force attack against a decoy domain account and detect the resulting failed-logon pattern in Microsoft Sentinel.

---

## ⚔️ Attack Simulation

From a Kali Linux attacker node (`192.168.50.20`), a brute-force attack was launched against the domain controller (`WIN-SERVER`, `192.168.50.10`) targeting the decoy account `testtarget`, using **NetExec** over SMB:

```bash
netexec smb 192.168.50.10 -u testtarget -p ~/wordlist_big.txt

<img width="1540" height="830" alt="image" src="https://github.com/user-attachments/assets/b4de04cf-89fe-485d-a640-f1a273663e1d" />

```

The wordlist contained **101 passwords** — 100 incorrect, with the correct password placed last. Simulating a realistic attack that eventually succeeds. This generated ~100 **failed logon events (Event ID 4625)** followed by one **successful logon (Event ID 4624)**.

![Attack executed from Kali via NetExec](images/01-netexec-attack.png)
*NetExec brute-force run against the domain controller over SMB.*

---

## 🛡️ Detection

The activity was detected in Microsoft Sentinel via a **scheduled analytics rule** querying the `SecurityEvent` table (collected from the DC via the Azure Monitor Agent and a Data Collection Rule). The rule identifies accounts exceeding a threshold of failed logons within the query window, and reports the successful logon, source IP(s), and exact attack window as context:

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

**Rule configuration:**

| Setting | Value |
|---|---|
| Rule type | Scheduled analytics rule |
| Run frequency | Every 5 minutes |
| Lookback period | Last 1 hour |
| Threshold | Trigger if query returns > 0 results |
| Severity | Medium |
| MITRE mapping | T1110 – Brute Force (Credential Access) |

![Analytics rule configuration](images/02-analytics-rule.png)
*Scheduled analytics rule querying the SecurityEvent table.*

![Failed logon spike in Sentinel workbook](images/03-workbook-spike.png)
*Workbook visualization: the brute-force attack appears as a sharp spike in failed logons.*

---

## 🔍 Analyst Triage & Investigation

### 1. True-Positive Determination

Pulling the raw evidence to validate the alert:

```kusto
SecurityEvent
| where EventID in (4624, 4625)
| where Account has "testtarget"
| project TimeGenerated, EventID, Account, IpAddress, Computer, LogonType
| order by TimeGenerated asc
```

| Indicator | Observation | Conclusion |
|---|---|---|
| **Time compression** | ~100 failures within seconds | Automated tool, not human error |
| **Source** | Single IP (`192.168.50.20`) | Targeted attack from one host |
| **Outcome** | Failures followed by one success (4624) | Attack succeeded — possible compromise |

**Verdict: True Positive.** The volume, speed, and single-source pattern are consistent with an automated brute-force tool, and the trailing successful logon indicates the account was compromised.

![Raw logon evidence](images/04-triage-evidence.png)
*Failed logons (4625) followed by a successful logon (4624) from the attacker IP.*

### 2. Enrichment — Source IP

The source `192.168.50.20` falls within the private range `192.168.0.0/16`, making it **internal** to the environment.

An internal source raises severity rather than lowering it: it implies the attacker is already operating **inside the network** (a compromised host or malicious insider) rather than probing from the internet.

### 3. Containment

Because a successful logon occurred, `testtarget` is treated as compromised. Containment action:

```powershell
Disable-ADAccount -Identity testtarget
```

This prevents further use of the account while investigation continues. *(In production, containment weighs attacker disruption against business impact — a critical service account might be reset and monitored rather than hard-disabled.)*

### 4. Scope — Did It Spread?

Checking whether the compromised account touched other systems:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Account has "testtarget"
| summarize Machines = make_set(Computer), Events = count() by EventID
```

> ⚠️ **Finding:** During enumeration, `testtarget` was found to have **local administrator rights on the Domain Controller** (NetExec `--shares` returned `ADMIN$` and `C$`). This is a serious misconfiguration — a single guessed password provides a direct path to full domain compromise, and would enable remote code execution (PsExec / WMI / WinRM) as an escalation.

### 5. Remediation

- Reset the `testtarget` password and enforce a strong password policy.
- **Remove `testtarget` from local Administrators on the DC** (root-cause fix — standard user accounts should never hold admin on a domain controller).
- Consider an account lockout policy to slow future brute-force attempts.

---

## 📋 Incident Closure

| Field | Value |
|---|---|
| **Classification** | True Positive |
| **Severity** | Medium (elevated by internal source + admin misconfiguration) |
| **Scope** | Limited to `WIN-SERVER`; no confirmed lateral movement |
| **Business impact** | None (controlled lab; decoy account) |
| **Containment** | Account disabled |
| **Remediation** | Password reset; admin rights removed; lockout policy recommended |
| **Status** | Resolved / Monitoring |

---

## 🧠 Key Takeaways

- A brute force is defined by the **flood of failed logons (4625)**; the trailing **success (4624)** is what escalates it from "attempt" to "compromise."
- Windows records the same account under different formats (`SOCLAB\testtarget` vs `soclab.local\testtarget`) depending on NTLM vs Kerberos — detections must tolerate this (`has`, or grouping on a stable field like `Computer`) rather than assuming a single spelling.
- An **internal** attack source is more concerning than external — it implies the attacker is already inside.
- The most valuable finding was not the brute force itself but the **over-privileged decoy account**, surfaced during scoping.

---

*Part of the [SC-200 Home Lab](../../README.md) — a self-built SOC environment for detection and response practice.*
