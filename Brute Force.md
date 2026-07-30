# Stage 1 — Brute-Force Attack Detection (T1110)

**Tactic:** Credential Access → Initial Access
**Technique:** T1110 – Brute Force
**Detection source:** Microsoft Sentinel scheduled analytics rule on the `SecurityEvent` table (Event IDs 4625 and 4624), collected from the domain controller via the Azure Monitor Agent and a Data Collection Rule.

## Objective

Simulate a credential brute-force attack against a decoy domain account and detect the resulting failed-logon pattern in Microsoft Sentinel.

## Attack Simulation

The attack was run from a Kali node (`192.168.50.20`) against the domain controller `WIN-SERVER` (`192.168.50.10`), targeting the decoy account `testtarget` over SMB with NetExec:

```bash
netexec smb 192.168.50.10 -u testtarget -p ~/wordlist_big.txt
```

The wordlist held 101 passwords — 100 wrong, with the correct one last — so the run produces a long string of failures ending in a single success. That generated roughly 100 failed logons (4625) followed by one successful logon (4624).

## Detection

Sentinel picked this up through a scheduled analytics rule on the `SecurityEvent` table. The rule counts failed logons per host, and only fires when the count crosses the threshold. It also returns the success count, the source IPs, and the first/last timestamps so there's useful context on the alert itself rather than just a number:

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

The rule runs every 5 minutes over a 1-hour lookback, at Medium severity, mapped to T1110.

## Investigation and Triage

To validate the alert I pulled the raw events in the order they happened:

```kusto
SecurityEvent
| where EventID in (4624, 4625)
| where Account has "testtarget"
| project TimeGenerated, EventID, Account, IpAddress, Computer, LogonType
| order by TimeGenerated asc
```

The pattern is clearly automated: around 100 failures land within a few seconds, all from a single IP, and a successful logon follows immediately after. A human mistyping a password doesn't produce that. On that basis I called it a true positive — and the trailing success means the account wasn't just attacked, it was taken.

### Source IP

The source, `192.168.50.20`, is in the `192.168.0.0/16` private range, so it's internal. That's worse than an external hit, not better — it means whoever's doing this is already inside the network, either from a compromised host or an insider, rather than knocking from the internet. If the source had been a public address, the triage would shift toward IP reputation and geolocation, and toward the question of whether that service should be internet-facing at all.

### Containment

Since a login succeeded, I treated `testtarget` as compromised and disabled it to stop any further use while I looked into it:

```powershell
Disable-ADAccount -Identity testtarget
```

In a real environment this isn't automatic — disabling a critical service account can cause an outage, so the call sometimes is to reset and monitor instead. For a decoy account it's a clean disable.

### Scope

I then checked whether the account had touched anything beyond the DC:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Account has "testtarget"
| summarize Machines = make_set(Computer), Events = count() by EventID
```

Activity stayed on `WIN-SERVER`, so no lateral movement. The more interesting finding came from enumeration: `testtarget` could reach the `ADMIN$` and `C$` shares on the DC (via NetExec `--shares`), which means it holds local admin there. That's a serious problem on its own — a single guessed password on that account is a straight line to full control of the DC, and would open the door to remote execution through PsExec, WMI, or WinRM.

### Remediation

- Reset the password and enforce a stronger password policy.
- Remove `testtarget` from local Administrators on the DC. A standard user has no business holding admin on a domain controller, and fixing that removes the real risk here.
- Add an account lockout policy so a run like this trips a lockout well before 100 attempts.

## Incident Closure

Classified as a true positive, Medium severity — the severity nudged up by the internal source and the admin misconfiguration rather than the brute force alone. Scope stayed limited to `WIN-SERVER` with no lateral movement, and there was no real business impact since this was a lab decoy. Contained by disabling the account; remediation covered the password reset, removing the admin rights, and recommending a lockout policy. Closed as resolved, with monitoring.

## Notes

- The brute force is the failures (4625); the single success (4624) is what turns it from an attempt into a compromise. Worth keeping those two separate when reasoning about severity.
- The same account shows up as both `SOCLAB\testtarget` and `soclab.local\testtarget` depending on whether NTLM or Kerberos handled the request. Grouping on `Computer` (or matching the username with `has`) avoids the rule silently splitting one attack across two spellings — which cost me time before I caught it.
- The headline finding wasn't the brute force. It was the over-privileged decoy account, and that only surfaced because I ran the scope check instead of closing the alert at "true positive."
