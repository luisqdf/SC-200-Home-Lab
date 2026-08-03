# Account Creation on a Domain Controller

### Detection and Triage with Microsoft Defender for Endpoint / SENTINEL


This scenario simulates an attacker who has already compromised a standard user account through a brute force attack and then attempts to create a new account on the domain controller to maintain persistence. It documents the attack, how Microsoft Defender for Endpoint responded, and the triage process an analyst would follow in a real environment.

---

## The Attack

After the brute force attack and successfully guessing the correct password for the `testtarget` account, I used NetExec to attempt remote account creation on the domain controller. The objective was to create a new account (`svc_backup`) that the attacker could use to maintain access to the environment.

I ran the following command from the Kali attacker host:

nxc smb 192.168.50.10 -u testtarget -p 'ThisisnotThePassword!' -x 'net user svc_backup P@ssw0rd123! /add'

NetExec authenticated to the domain controller successfully. The `(Pwn3d!)` result confirmed that the compromised `testtarget` account held administrative rights on the target. However, the account creation was not possible. The tool connected and attempted to run the command, but the new account was never created.

To confirm this on the domain controller itself, I checked the account list with `net user`. The `svc_backup` account was not present, which verified that the account creation never completed.

---

## Defender/Sentinel Detection

I then opened Microsoft Defender for Endpoint and looked for the incident. Defender had already generated one for this activity through its built in behavioral detections, and grouped the related alerts into a single incident on a critical asset.

<img width="2168" height="1314" alt="image" src="https://github.com/user-attachments/assets/0679f94e-6b85-43d4-b857-c593bbb329ab" />


Microsoft Defender for Endpoint blocked the account creation at the moment of execution. The captured command line showed the exact malicious action (`cmd.exe /Q /c net user svc_backup ...`) being prevented. In addition, the Attack Disruption capability automatically contained and disabled the account that was being used to perform the attack, without any analyst intervention.

<img width="2086" height="352" alt="image" src="https://github.com/user-attachments/assets/e153fedf-2132-4e0d-8ebd-f095184021fb" />


---

## Why This Matters (Defense in Depth)

This scenario highlights two important points about layered security.

First, if Microsoft Defender for Endpoint had not been installed on the domain controller, the attack would have succeeded and the `svc_backup` account would have been created.

Second, if that account had been created, it would have generated a Windows security event (Event ID 4720, "a user account was created"). The Microsoft Sentinel analytics rule built for this detection keys off that event, so Sentinel would have detected the account creation and raised the incident on the SIEM side.

The endpoint layer (Defender for Endpoint) stopped the attack before it could happen, and the SIEM layer (Sentinel) acts as the safety net that would have caught the result if the endpoint layer had not been there. Running both layers together is what provides defense in depth.

---

## Analyst Triage

In a real environment, this is how I would act on and triage this incident.

**1. Assess the priority.**
The incident targeted a domain controller, was flagged as human operated activity, and involved a known offensive toolkit. A domain controller is a critical asset, so this is treated as a high priority incident.

**2. Determine whether the attack succeeded.**
I verified this directly on the domain controller by listing the accounts with `net user` and confirming that `svc_backup` was not present. This is the most important early question, because a blocked attack and a successful one are very different situations. In this case the attack was blocked.

**3. Review the automated response.**
Because of the Attack Disruption tag, I checked the Activities log and the Action Center to see what Defender had already done. Defender had automatically disabled and contained the `testtarget` account.

**4. Confirm the scope of the containment.**
I queried Active Directory to make sure only the compromised account was affected and that no legitimate accounts were disabled. Only `testtarget` and the expected default accounts were disabled, so the response was correctly scoped.

**5. Separate true positives from false positives.**
Defender marked several items as suspicious. Some of these were legitimate background activity, such as the Azure Arc service and the Server Core logon script, which I confirmed as benign so they did not distract from the real attack chain.

**6. Identify the root cause.**
The compromised `testtarget` account had been given Domain Admin rights it should not have had, which turned a low value credential into a domain controller level threat. The origin of the compromise was a prior brute force attack from the same attacker host.

**7. Classify, document, and close.**
Once the impact was confirmed and the root cause was understood, the incident would be classified as a true positive, documented with the findings, and closed.

---

## Lessons Learned and Solutions

**No account lockout policy was in place.**
The domain allowed unlimited password guessing, which made the original brute force possible. The solution is to implement an account lockout policy so that accounts lock after a small number of failed attempts, for example locking the account after five failed attempts, keeping it locked for fifteen minutes, and resetting the failed count after fifteen minutes. This control is owned by the identity and Active Directory team and should go through change management, since it affects every account in the domain.

**A standard user held Domain Admin rights.**
This excessive privilege is what allowed the attack to reach the domain controller. The solution is to apply the principle of least privilege: remove `testtarget` from the Domain Admins group, review group membership regularly, and grant administrative rights only to accounts that require them.

**The compromised account needed to be secured.**
Even though the account was automatically contained, the credential itself was still exposed. The solution is to reset the password for the compromised account before re enabling it, and to investigate how the password was obtained in the first place.

**Detection depends on layered coverage.**
This attack was caught by the endpoint layer, but the environment should not rely on a single control. The solution is to keep both Microsoft Defender for Endpoint and Microsoft Sentinel active. Defender detects endpoint behavior in real time, and Sentinel provides broader log based detection across the environment.

**Verify, do not assume.**
During triage it is important to confirm findings against the actual systems rather than trusting a single tool. The solution is to always verify ground truth: confirm whether an account exists on the host, confirm the scope of any automated action against Active Directory, and confirm which alerts are real before drawing conclusions.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Notes |
|---|---|---|
| Credential Access | T1110 Brute Force | Origin of the credential compromise |
| Lateral Movement | T1021.002 Remote Services: SMB Windows Admin Shares | NetExec SMB access to the domain controller |
| Execution | T1569.002 System Services: Service Execution | The smbexec method created a service to run the command |
| Persistence | T1136.002 Create Account: Domain Account | Account creation attempted and blocked |
