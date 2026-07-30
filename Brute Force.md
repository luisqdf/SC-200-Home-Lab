# Brute-Force Attack

Technique: T1110 – Brute Force (Credential Access). Detected in Microsoft Sentinel using an analytics rule on the SecurityEvent table (Event IDs 4625 and 4624), collected from the domain controller via the Azure Monitor Agent.

## Attack

Ran a brute force from Kali (192.168.50.20) against the domain controller WIN-SERVER (192.168.50.10), targeting the decoy account testtarget over SMB:

```bash
netexec smb 192.168.50.10 -u testtarget -p ~/wordlist_big.txt
```
<img width="1540" height="830" alt="Screenshot 2026-07-30 153537" src="https://github.com/user-attachments/assets/0afa67e2-fc7a-45f9-8cfc-b8b3affe0a67" />

The wordlist had 101 passwords — 100 wrong, the correct one last. So the run makes about 100 failed logons (4625) and one success (4624) at the end.

<!-- screenshot: netexec run -->

## Detection

A scheduled rule counts failed logons per host and fires when they cross the threshold. It also pulls the success count, source IPs, and the attack's start and end time for context.

```kusto
SecurityEvent
| where EventID in (4624, 4625)
| where Account has "testtarget"
| summarize FailedLogons = countif(EventID == 4625),
            SuccessfulLogons = countif(EventID == 4624),
            SourceIPs = make_set(IpAddress),
            FirstAttempt = min(TimeGenerated),
            LastAttempt = max(TimeGenerated)
    by Computer
| where FailedLogons > 5
```

Runs every 5 minutes, 1-hour lookback, Medium severity.

<!-- screenshot: analytics rule -->
<!-- screenshot: workbook spike -->

## Triage

Pulled the raw events to check the alert:

```kusto
SecurityEvent
| where EventID in (4624, 4625)
| where Account has "testtarget"
| project TimeGenerated, EventID, Account, IpAddress, Computer, LogonType
| order by TimeGenerated asc
```

<img width="1738" height="1270" alt="image" src="https://github.com/user-attachments/assets/64795c97-92fc-489d-bb37-16ac5842d8c9" />


About 100 failures in a few seconds, all from one IP, then a success. That's automated, not a person mistyping. True positive — and the success means the account was compromised, not just hit.

<!-- screenshot: raw logon events -->

## Source IP

192.168.50.20 is a private address (192.168.0.0/16), so internal. That's worse, not better — the attacker is already inside the network. If it had been a public IP, I'd be checking reputation and geolocation instead.

If it had been a public IP, I'd be checking its reputation and geolocation instead. Common sources for that:

- VirusTotal (virustotal.com) — reputation, and any malware or reports tied to the IP
- AbuseIPDB (abuseipdb.com) — community-reported abuse history and a confidence score
- Cisco Talos (talosintelligence.com) — reputation and email/web block reputation
- GreyNoise (greynoise.io) — flags whether an IP is mass-scanning the internet (a lot of brute-force sources are)
- Shodan (shodan.io) — what services the IP exposes, useful for profiling the host
- MaxMind GeoIP2 or ipinfo.io — geolocation (country, city, ASN, hosting provider)

## Containment

A login succeeded, so I disabled the account to stop further use:

```powershell
Disable-ADAccount -Identity testtarget
```

For a real service account you'd weigh the outage risk first. For a decoy, just disable it.

## Scope

Checked whether the account touched anything else:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Account has "testtarget"
| summarize Machines = make_set(Computer), Events = count() by EventID
```

Everything stayed on WIN-SERVER — no lateral movement.

<!-- screenshot: scope query result -->

The bigger find came from enumeration: testtarget can reach the ADMIN$ and C$ shares, so it has local admin on the DC. That's the real problem — one guessed password on that account means full control of the domain controller.

## Remediation

- Reset the password, enforce a stronger policy.
- Remove testtarget from local Administrators on the DC.
- Add a lockout policy so this trips well before 100 tries.

## Closure

True positive, Medium severity, contained to WIN-SERVER, no lateral movement, no real impact (lab decoy). Account disabled, admin rights to be removed, lockout policy recommended. Closed — monitoring.
