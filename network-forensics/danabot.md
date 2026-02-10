## Challenge Information
- **Name:** DanaBot Lab
- **Author:** Abdelrhman322, CyberDefenders
- **Category:** Network Forensics
- **Difficulty:** Easy

---

## Scenario Overview
The Security Operations Center (SOC) detected suspicious network activity indicating that a host within the organization had been compromised. Further investigation revealed that sensitive company data was exfiltrated by the attacker.

The objective of this investigation is to analyze the provided Network Capture (PCAP) files and leverage Threat Intelligence to determine how the compromise occurred and identify the malware and techniques used during the intrusion.

---

## Objectives

1. Identify the attacker’s IP address used during initial access
2. Determine the name of the malicious file used for initial access
3. Obtain the SHA‑256 hash of the initial malicious file
4. Identify the process used to execute the malicious file
5. Determine the file extension of the second-stage malicious file
6. Obtain the MD5 hash of the second malicious file

---

## Tools Used
- Wireshark
- Isolated Virtual Environment
- Kali Linux

---

## Investigation & Analysis Steps

### Initial Setup

- The lab files were downloaded and extracted.
- A PCAP file was identified within the lab directory.
- The PCAP file was opened and analyzed using Wireshark.

### Attacker IP Address (Initial Access)
- Initial access typically occurs during the first interaction between the victim and attacker. Since victims rely on DNS to resolve external resources, DNS traffic was analyzed first.
- At timestamp 0.000, DNS traffic revealed a query for the domain: `portfolio.serveirc.com`
- Two DNS entries were observed, the second entry included a response.
- Inspection of the DNS response showed: 1 Question and 1 Answer (A record)
- The resolved IP address was: `62.173.142.148`
- Threat Intelligence validation using VirusTotal confirmed that portfolio.serveirc.com is flagged as malicious by multiple vendors.

### Malicious File Used for Initial Access
- A display filter was applied: `ip.src == 62.173.142.148`
- After selecting a packet and following the TCP stream, an HTTP response was observed.
- The Content-Disposition header revealed an attached file: `allegato_708.js`
- This JavaScript file represents the initial malicious payload delivered to the victim.
  
### SHA‑256 Hash of the Initial Malicious File
- HTTP traffic showed a request to `62.173.142.148`.
- The file was extracted using: `Wireshark → File → Export Objects → HTTP`
- The file `login.php` was saved inside an isolated virtual environment due to its malicious nature.
- The SHA‑256 hash was calculated in Kali Linux: `sha256sum login.php`

### Process Used to Execute the Malicious File
- Analysis of the HTTP GET request confirmed delivery of `allegato_708.js`.
- The JavaScript source code contained usage of: `new ActiveXObject(...)`
- `ActiveXObject` is exclusive to the Windows Script Host (WSH) environment.
- Multiple references to `WScript` were observed, confirming execution via WSH.
- Windows Script Host executes JavaScript using:
    - wscript.exe (GUI-based, default)
    - cscript.exe (CLI-based)

### File Extension of the Second Malicious File
- Recall the Attack Flow:
  1. allegato_708.js is downloaded
  2. JavaScript executes via Windows Script Host
  3. A second-stage payload is downloaded
  4. The payload is written to disk
- The JavaScript uses ADODB.Stream to write binary data:
`var stream = WScript.CreateObject("ADODB.Stream");
stream.Open();
stream.Type = 1;
stream.Write(response.ResponseBody);
stream.Position = 0;
stream.SaveToFile(path, 2);
stream.Close();`
- The filename is dynamically generated: `return randomName + ".dll";`

  
### MD5 Hash of the Second Malicious File
- The JavaScript performs an HTTP GET request to retrieve the DLL payload.
- The response body contains raw DLL bytes.
- The file was extracted using: `Wireshark → File → Export Objects → HTTP`
- The extracted DLL file was hashed in Kali Linux: `md5sum filename.dll`

---

## Findings / Indicators of Compromise (IOCs)
| Type                | Indicator              |
| ------------------- | ---------------------- |
| Malicious Domain    | portfolio.serveirc.com |
| Attacker IP Address | 62.173.142.148         |
| Initial Payload     | allegato_708.js        |
| Execution Process   | wscript.exe            |
| Second-Stage File   | *.dll                  |
| Malware Family      | DanaBot                |
