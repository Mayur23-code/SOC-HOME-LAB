# Detection Tracking — SOC Home Lab

Full tracking data from the five-stage attack simulation. See also the
[Excel version](detection-tracking-spreadsheet.xlsx) for the original
working file with formulas.

---

## Main Detection Tracker

| Stage | Technique ID | Name | Action | Log Source | Rule ID | Severity | Detected |
|---|---|---|---|---|---|---|---|
| 1 - Initial Access | T1566.001 | Phishing: Spearphishing Attachment | mshta.exe HTA download & execute | Sysmon Event ID 1 | 100010 (custom) | High | Y |
| 1 - Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Host .hta, browse from Windows VM | Snort HTTP .hta request | 1000001 (custom) | Medium | Y |
| 2 - Persistence | T1547.001 | Boot or Logon Autostart: Registry Run Key | reg add ...CurrentVersion\Run → calc.exe | Sysmon Event ID 13 | Wazuh 92302 (built-in) | High | Y |
| 2 - Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell used throughout lab as execution vector | — | — | Medium | Not Tested (not isolated as its own test) |
| 3 - Privilege Escalation | T1548.002 | Abuse Elevation Control: Bypass UAC | eventvwr.exe mscfile hijack | Sysmon Event ID 1 (unexpected child process) | Wazuh 100012 (custom) | Critical | Y |
| 4 - Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Impacket psexec.py → SYSTEM shell via ADMIN$ | Sysmon Event ID 1 + Windows Security Events | Wazuh 92650, 92218, 92052, 92307, 92652, 67028 (built-in) | Critical | Y |
| 4 - Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | SMB logon from unusual source | Security Event ID 4624 (Logon Type 3) | Wazuh 92652 / 67028 | High | Y |
| 4 - Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | ADMIN$/C$ share access | Security Event ID 5145 | Wazuh 92218 | Medium | Y |
| 5 - Exfiltration | T1560 | Archive Collected Data | Compress-Archive staged loot3.zip in Public dir | Wazuh FIM (syscheck) | 554/550 (built-in) — custom rule 100014 never fired | High | Y |
| 5 - Exfiltration | T1041 | Exfiltration Over C2 Channel | Network POST of staged .zip | Snort/Wazuh network alert | — | Critical | Not Tested |

---

## MITRE ATT&CK Coverage Matrix

Tactics (columns) x techniques exercised in this lab. Status reflects
detection outcome, not technique risk.

**Legend:** DETECTED = technique executed and alerted successfully &middot;
RULE WRITTEN, NOT FIRED = custom rule authored but did not trigger, detection
achieved via a different rule &middot; NOT TESTED = technique not executed in
this lab iteration

| Technique / Sub-technique | Initial Access | Execution | Persistence | Privilege Escalation | Lateral Movement | Collection | Exfiltration |
|---|---|---|---|---|---|---|---|
| T1566.001 — Phishing: Spearphishing Attachment | DETECTED | | | | | | |
| T1059.001 — Command & Scripting Interpreter: PowerShell | | NOT TESTED | | | | | |
| T1547.001 — Boot/Logon Autostart: Registry Run Key | | | DETECTED | | | | |
| T1548.002 — Abuse Elevation Control: Bypass UAC | | | | DETECTED | | | |
| T1021.002 — Remote Services: SMB/Windows Admin Shares | | | | | DETECTED | | |
| T1560 — Archive Collected Data | | | | | | DETECTED | |
| T1041 — Exfiltration Over C2 Channel | | | | | | | NOT TESTED |

> **Note:** T1547.001 and T1560 show DETECTED despite their associated
> custom rules (100011, 100014) never firing — detection was instead
> achieved via Wazuh's built-in ruleset. Both debugging efforts are
> documented in the Detection Gaps section below and represent deliberate
> engineering decisions to rely on existing coverage rather than force a
> redundant custom rule.

---

## MTTD Tracker

| Stage | Tool / Rule | Time Triggered | Time Alert Seen | MTTD (sec) |
|---|---|---|---|---|
| 1 | Snort sid:1000001 | 06:44:29 | 06:44:29 | ~0-1 |
| 1 | Wazuh 100010 | 06:44:29 | 12:30:22.185 | ~2 |
| 2 | Wazuh 92302 | 09:01:08.184 | 09:01:10.929 | 2.7 |
| 3 | Wazuh 100012 | Not recorded | 01:59:38.526 | TBD |
| 4 | Wazuh 92650 etc. | Not recorded | 12:42:34.045 | less than 1 |
| 5 | Wazuh FIM | ~20:22:51 | ~20:23:00 | ~9 |

---

## Indicators of Compromise

| Type | Value | Related Stage | First Observed | Notes |
|---|---|---|---|---|
| IP Address | 192.168.2.8 | 1 - Initial Access | 2026-07-14 | Kali attacker host — updated from original 192.168.1.8 after network re-segmentation onto OPT1 |
| IP Address | 192.168.1.11 | 1 - Initial Access | 2026-07-14 | Windows 11 victim endpoint |
| Filename | update.hta | 1 - Initial Access | 2026-07-14 | Malicious HTA payload (VBScript dropper; PoC payload launched calc.exe) |
| Filename | update.exe | 1 - Initial Access | 2026-07-16 | Real msfvenom Meterpreter payload (reverse_tcp) — revised Stage 1 payload after switching from the calc.exe PoC |
| File Hash (SHA256) | *(run `Get-FileHash` / `sha256sum` before publishing)* | 1 - Initial Access | *(fill after hashing)* | See commands below |
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater` | 2 - Persistence | 2026-07-14 | Points to calc.exe (PoC) |
| Registry Key | `HKCU\Software\Classes\mscfile\shell\open\command` | 3 - Privilege Escalation | 2026-07-16 | UAC bypass hijack — confirmed to have executed (Wazuh rule 100012 fired twice) |
| Process/Service Name | Randomized per run (e.g. `kEGl`, `BfxO` / `QNDYihdK.exe`, `DgXxqeCn.exe`) | 4 - Lateral Movement | 2026-07-16 | Impacket psexec.py artifact — not literally `PSEXESVC.exe`; Impacket randomizes both service and filename per run to evade signature matching |
| Authentication Event | NTLM remote logon, Logon Type 3 | 4 - Lateral Movement | 2026-07-16 | SMB authentication preceding SYSTEM shell |
| Filename | loot3.zip | 5 - Exfiltration | 2026-07-17 | Archive of C:\Users\Public\Documents, staged in C:\Users\Public |

**Get the real hash values before publishing:**
```powershell
Get-FileHash C:\Windows\Temp\update.exe -Algorithm SHA256
```
```bash
sha256sum /tmp/serve/update.hta
sha256sum /tmp/serve/update.exe
```

---

## Detection Gaps & Lessons Learned

*The most important section for interviews — be specific about what failed and how you fixed it.*

| Stage | What Failed | Root Cause | Fix Applied |
|---|---|---|---|
| 1 - Initial Access | Rule 100010 did not fire on mshta.exe execution | Regex typo: `(?!)` (empty negative lookahead, always fails) instead of `(?i)` case-insensitive flag. Valid PCRE2 syntax, so no load error — just silently matched nothing. | Corrected regex, validated with `wazuh-analysisd -t` and `wazuh-logtest` before restarting wazuh-manager |
| 1 - Initial Access | ET Open ruleset generated no alert on the .hta download over HTTP | ET Open's default policy targets known malware/exploit-kit signatures, not generic suspicious-extension-over-HTTP patterns — expected coverage limitation, not a misconfiguration | Wrote a custom Snort rule (sid:1000001) matching `.hta` in the HTTP URI to close this detection gap |
| 1 - Infra/Detection Visibility | Snort on LAN interface saw zero traffic between Kali and Windows VM | Kali and Windows were on the same flat VirtualBox internal network; inter-VM traffic on the same subnet is switched locally and never actually transits pfSense, so Snort (bound to pfSense interfaces) was structurally blind to it regardless of rule quality | Re-segmented the lab into two subnets — LAN (192.168.1.0/24) and OPT1 (192.168.2.0/24) — with pfSense routing between them, forcing all Kali↔Windows traffic through the firewall so Snort could actually inspect it |
| 2 - Persistence | Custom rule 100011 never fired despite correct group name, field name, and regex (all independently verified against raw event JSON) | Unresolved — extensive troubleshooting (group naming `sysmon_event_13` vs `sysmon_event13`, field path confirmation via raw JSON, `wazuh-logtest` isolation) ruled out every obvious cause; root cause not conclusively identified | Determined custom rule was unnecessary — Wazuh's built-in rule 92302 already provides full T1547.001 coverage with MITRE tagging out of the box. Deprioritized further debugging in favor of relying on validated built-in detection. |
| 3 - Privilege Escalation | Initially assumed the UAC bypass technique failed | No visible on-screen result (no Calculator popup) was mistaken for technique failure — conclusion was drawn from visual observation rather than checking the SIEM | Reviewed Wazuh logs retroactively and confirmed custom rule 100012 had in fact fired correctly (twice, at 01:59:38 and 02:02:19). No technical fix was needed — the real fix was procedural: always verify against telemetry before concluding a technique didn't work. |
| 4 - Lateral Movement | Custom rule 100013 had an XML syntax error (unclosed/malformed attribute) | Curly-quote or paste-corruption issue in local_rules.xml, same class of error as Stage 1 | Not fixed/needed — built-in ruleset (6 separate rules: 92650, 92218, 92052, 92307, 92652, 67028) already gave comprehensive coverage of the PsExec technique chain across service creation, admin share abuse, and remote logon |
| 5 - Exfiltration | Custom rule 100014 never fired despite correct-looking syntax | Two compounded issues: (1) wrong `if_group` assumed initially before the correct `sysmon_event_11` was found via direct ruleset inspection, and (2) Sysmon itself was not generating Event 11 at all for the target file — the deployed SwiftOnSecurity config filters `.zip` creation in user-writable directories by default | Pivoted from Sysmon-based detection to Wazuh FIM (syscheck), which operates independently of Sysmon. Discovered `C:\Users\Public` was never actually added to the agent's syscheck block despite being called out in the original setup. Added the directory with realtime monitoring, fixed a `C::\` double-colon typo in the config, and confirmed detection via built-in rule 554/550. |

---

## MITRE ATT&CK Coverage Summary

| Stage | Technique ID | Name | Detected |
|---|---|---|---|
| 1 | T1566.001 | Phishing: Spearphishing Attachment | Yes |
| 2 | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Yes |
| 3 | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Yes |
| 4 | T1021.002 | Remote Services: SMB/Windows Admin Shares | Yes |
| 5 | T1560 | Archive Collected Data | Yes |

**Detection rate: 5 out of 5 core techniques — 100%**
(T1059.001 and T1041 recorded as Not Tested — see matrix above)
