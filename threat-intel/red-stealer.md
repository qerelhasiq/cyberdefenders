## Challenge Information
- **Name:** Red Stealer Lab
- **Author:** Sameer_Fakhoury, CyberDefenders
- **Category:** Threat Intel
- **Difficulty:** Easy

---

## Scenario Overview
An executable file was discovered on a colleague's computer and is suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection.
The task is to investigate this executable by analyzing its hash. 
The goal is to gather and analyze data beneficial to other SOC members, including the Incident Response team, to respond to this suspicious behavior efficiently.

---

## Objectives

1. Determine the malware classification assigned by Microsoft in VirusTotal
2. Identify the original filename of the malware sample
3. Determine the UTC timestamp of the malware’s first submission to VirusTotal
4. Identify the MITRE ATT&CK technique ID associated with the malware’s data collection prior to exfiltration
5. Determine the social media-related domain resolved by the malware via DNS queries
6. Identify the malicious IP address and destination port used for communication
7. Determine the YARA rule name created by “Varp0s” that detects the malware in MalwareBazaar
8. Identify the malware alias associated with the malicious IP address according to ThreatFox
9. Determine the DLL leveraged by the malware for privilege escalation

---

## Tools Used
- VirusTotal
- MalwareBazaar
- Threatfox

---

## Investigation & Analysis Steps

### Initial Preparation
- Download the lab files
- Open `FileHash.txt`
- Submit the provided hash into a Threat Intelligence Platform (TIP) like VirusTotal
  
### Malware Classification (Microsoft Detection)
- Navigate to the **Detection** tab in VirusTotal
- Locate Microsoft under the security vendors list
- Microsoft detects it as: `Trojan:Win32/Redline!rfn`
- Malware category according to Microsoft: **Trojan**
  
### Malware Filename Identification
- Navigate to the **Details** tab
- Locate the **Names** subsection
- First common filename: **Wextract**

### First Submission Timestamp (UTC)
- In the **Details** tab, locate the **History** subsection
- _First Submission_ timestamp: `2023-10-06 04:41:50`

### MITRE ATT&CK Technique (Data Collection Before Exfiltration)
- Navigate to the **Behavior** tab
- Scroll to the **Activity Summary** section
- Locate **MITRE ATT&CK Tactics and Techniques**
- Under **Collection**, first technique is Data from Local System
- Technique ID: T1005
- Verify this technique via the official MITRE website: `https://attack.mitre.org/techniques/T1005/`
 
### Social Media-Related DNS Resolutions
- Go to Behavior → Activity Summary → DNS Resolutions
- Resolved domains observed:
  `business.bing.com → Microsoft/Bing<br>
  edge-mobile-static.azureedge.net → Azure CDN<br>
  edgeassetservice.azureedge.net → Azure CDN<br>
  facebook.com & connect.facebook.net → social media`
- Identify the social media domain: **facebook.com**

### Malicious IP Address and Destination Port
- Navigate to Behavior then Activity Summary and then IP Traffic
- Most ports: 443 (HTTPS), some 80 (HTTP) and 137 (NBNS)
- Odd port observed: 77.91.124.55:19071
- This IP also has no associated domain and uses a non-standard port
- Malicious IP and port: **77.91.124.55:19071**

### YARA Rule (MalwareBazaar)
- Access MalwareBazaar: `https://bazaar.abuse.ch/`
- Search using SHA256 hash from the lab file: `sha256 <sha256-hash>`
- Open the malware entry and navigate to the **YARA** section
- Read the rule name: `detect_Redline_Stealer`

### Malware Alias (ThreatFox)
- Access ThreatFox: `https://threatfox.abuse.ch/`
- Click "**Browse IOCs**"
- Search using the IP: `ioc:77.91.124.55`
- Locate Malware Alias field: **RECORDSTEALER**

### DLL Used for Privilege Escalation
- Go to **VirusTotal**, then **Details** and then **Imports**
- Imported DLLs observed:
| DLL              | What It Usually Handles              |
| ---------------- | ------------------------------------ |
| kernel32.dll     | Processes, memory, file I/O          |
| user32.dll       | GUI                                  |
| ws2_32.dll       | Networking                           |
| ntdll.dll        | Low-level NT functions               |
| **advapi32.dll** | Security, registry, services, tokens |
- DLL used for privilege escalation: `advapi32.dll`
- Confirm by checking functions inside `advapi32.dll` relevant for privilege escalation: AdjustTokenPrivileges, AllocateAndInitializeSid, EqualSid, FreeSid,
GetTokenInformation, LookupPrivilegeValueA, OpenProcessToken, RegCloseKey, RegCreateKeyExA, RegDeleteValueA

---

## Findings / Indicators of Compromise (IOCs)
| Type                   | Indicator                                                        |
| ---------------------- | ---------------------------------------------------------------- |
| File Hash              | 248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b |
| Malware Family         | Trojan:Win32/Redline!rfn                                         |
| Filename               | Wextract                                                         |
| First Submission UTC   | 2023-10-06 04:41:50                                              |
| MITRE ATT&CK Technique | T1005 – Data from Local System                                   |
| Social Media Domain    | facebook.com                                                     |
| Malicious IP & Port    | 77.91.124.55:19071                                               |
| YARA Rule              | detect_Redline_Stealer                                           |
| Malware Alias          | RECORDSTEALER                                                    |
| DLL Used               | advapi32.dll                                                     |

