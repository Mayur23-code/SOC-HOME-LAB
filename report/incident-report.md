# Incident Report — SOC Home Lab Attack Simulation
**Date:** July 2026
**Analyst:** Renu
**Severity:** Critical (simulated — isolated lab environment)
**Status:** Closed

---

## 1. Executive Summary

A simulated five-stage attack chain was executed against an isolated VirtualBox
lab environment to validate detection capability across MITRE ATT&CK techniques
T1566.001, T1547.001, T1548.002, T1021.002, and T1560. The attacker (Kali Linux,
192.168.2.8) gained initial access via a malicious HTA payload, established
persistence via a registry Run key, escalated privileges via a UAC bypass, moved
laterally to gain SYSTEM-level access via SMB/PsExec, and staged data for
exfiltration via archive creation. All five stages were detected. Mean time to
detect ranged from under 1 second (Snort network layer) to approximately 9
seconds (Wazuh FIM).

---

## 2. Lab Environment

| Host | IP | Role |
|---|---|---|
| pfSense | 192.168.1.1 / 192.168.2.1 | Gateway + Snort IDS |
| Ubuntu 22.04 (Wazuh 4.14) | 192.168.1.25 | SIEM/XDR Manager |
| Windows 11 + Sysmon | 192.168.1.11 | Victim endpoint |
| Kali Linux | 192.168.2.8 | Attacker (isolated OPT1 subnet) |

---

## 3. Attack Timeline

| Time (UTC) | Stage | Technique | Action | Detection |
|---|---|---|---|---|
| 06:44:29 | Initial Access | T1566.001 | mshta.exe executed update.hta | Snort sid:1000001 + Wazuh 100010 |
| 09:01:08 | Persistence | T1547.001 | reg.exe wrote Run key | Wazuh 92302 (2.7s MTTD) |
| 01:59:38 | Privilege Escalation | T1548.002 | eventvwr.exe spawned unexpected child | Wazuh 100012 |
| 12:42:33 | Lateral Movement | T1021.002 | psexec.py obtained SYSTEM shell | Wazuh 92650, 92218, 92052 (<1s) |
| 20:22:51 | Exfiltration | T1560 | loot3.zip created in C:\Users\Public | Wazuh 554 FIM (~9s) |

---

## 4. Stage Analysis

### Stage 1 — Initial Access (T1566.001)
A malicious HTA file was hosted on Kali and browsed to from Windows, causing
mshta.exe to spawn and execute VBScript — a standard phishing delivery mechanism.

**Detected by:**
- Wazuh custom rule 100010 — Sysmon Event 1, mshta.exe process create
- Snort custom rule sid:1000001 — .hta in HTTP request URI

**Gap:** ET Open generated no alert. It targets known malware signatures, not
generic file-extension-over-HTTP patterns. Custom rule required.

---

### Stage 2 — Persistence (T1547.001)
reg.exe wrote a value to HKCU\...\CurrentVersion\Run pointing at calc.exe.

**Detected by:**
- Wazuh built-in rule 92302 — full MITRE T1547.001 tagging included
- MTTD: 2.7 seconds

Custom rule 100011 was not needed — built-in coverage was sufficient.

---

### Stage 3 — Privilege Escalation (T1548.002)
HKCU\Software\Classes\mscfile\shell\open\command was hijacked to point at
calc.exe. Running eventvwr.exe caused Windows to launch the payload as a
high-integrity process without a UAC prompt.

**Detected by:**
- Wazuh custom rule 100012 — eventvwr.exe as parent of unexpected child

**Key lesson:** Technique was initially misjudged as failed because no visible
popup appeared. Log review confirmed rule 100012 fired correctly. Telemetry,
not visual observation, is the arbiter of technique success.

---

### Stage 4 — Lateral Movement (T1021.002)
Impacket psexec.py authenticated to Windows 11 via SMB and obtained a
SYSTEM-level interactive shell via ADMIN$.

**Detected by:** Six built-in Wazuh rules firing within 1 second:
- 92650 — new service created in Windows root
- 92218 — admin share abuse
- 92052 — abnormal command prompt
- 92307 — service registry evidence
- 92652/67028 — remote NTLM logon + privilege assignment

**Notable:** Impacket randomizes service and executable names per run —
defeating literal-filename rules like PSEXESVC.exe matching.

---

### Stage 5 — Exfiltration (T1560)
Compress-Archive staged C:\Users\Public\Documents into loot3.zip.

**Detected by:**
- Wazuh FIM built-in rule 554 — file added to system
- MTTD: ~9 seconds

**Gap:** Sysmon Event 11 (FileCreate) generated zero entries — the
SwiftOnSecurity config filters .zip creation in user directories.
C:\Users\Public was also missing from the Wazuh syscheck block.
Pivoted to FIM after discovering both issues.

---

## 5. Detection Gap Summary

| Gap | Root Cause | Fix |
|---|---|---|
| Snort saw zero traffic | Flat network — packets never transited pfSense | Re-segmented into LAN/OPT1 subnets |
| Route hijacking on all VMs | Secondary NAT adapter had lower metric | Fixed per-VM via nmcli/route add/netplan |
| Rule 100010 silent failure | Regex typo (?!) instead of (?i) | Corrected + validated with wazuh-analysisd -t |
| ET Open missed .hta | Expected coverage limitation | Custom Snort rule sid:1000001 |
| Sysmon group naming inconsistency | sysmon_eventN vs sysmon_event_NN undocumented | Direct ruleset file inspection |
| Stage 3 wrong conclusion | Visual assumption instead of log check | Process lesson — always verify via SIEM |
| Sysmon FileCreate filtered | SwiftOnSecurity config excludes .zip in user dirs | Pivoted to Wazuh FIM |
| C:\Users\Public not monitored | Pre-flight setup step missed | Added to syscheck block in ossec.conf |

---

## 6. MITRE ATT&CK Coverage

| Stage | Technique ID | Name | Detected |
|---|---|---|---|
| 1 | T1566.001 | Phishing: Spearphishing Attachment | ✅ |
| 2 | T1547.001 | Boot/Logon Autostart: Registry Run Keys | ✅ |
| 3 | T1548.002 | Abuse Elevation Control: Bypass UAC | ✅ |
| 4 | T1021.002 | Remote Services: SMB/Windows Admin Shares | ✅ |
| 5 | T1560 | Archive Collected Data | ✅ |

**Detection rate: 5/5 — 100%**

---

## 7. Recommendations

1. Disable mshta.exe via AppLocker or WDAC
2. Alert on Run key writes from non-approved processes
3. Restrict SMB between workstations via host-based firewall
4. Enable FIM on C:\Users\Public and C:\Windows\Temp
5. Network segmentation is a prerequisite for network IDS effectiveness
