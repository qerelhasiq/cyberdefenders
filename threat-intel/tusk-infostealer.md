## Challenge Information
- **Name:** Tusk Infostealer Lab
- **Author:** 0x4104, CyberDefenders
- **Category:** Threat Intel
- **Difficulty:** Easy

---

## Scenario Overview
A blockchain development company detected unusual activity after an employee was redirected to an unfamiliar website while accessing a DAO management platform. Shortly after, multiple cryptocurrency wallets linked to the organization were drained. Investigators suspect a malicious tool was used to steal credentials and exfiltrate funds.
The objective of this investigation is to analyze the provided intelligence to uncover the attack methods, identify indicators of compromise, and track the threat actor’s infrastructure.

---

## Objectives

1. Identify the size and fingerprint of the malicious file used in the campaign
2. Determine how the threat actors internally refer to their victims in log messages
3. Identify the phishing website created to mimic the legitimate peerme.io DAO platform
4. Determine the cloud storage service used to host malware samples for both macOS and Windows variants
5. Extract the archive decompression password embedded within the malware configuration
6. Identify the function responsible for retrieving the field archive from the configuration file
7. Analyze the third sub-campaign in which an AI translator project was mimicked, including both the legitimate and malicious translators
8. Identify the command-and-control infrastructure used by StealC during the campaign
9. Identify the Ethereum cryptocurrency wallet associated with the attackers
   
---

## Tools Used
- VirusTotal
- Web browser

---

## Investigation & Analysis Steps

### Initial Analysis
1. The lab was downloaded and extracted.
2. A text file within the lab contained an MD5 hash. The instructions indicated that this hash should be queried on a threat intelligence platform.
3. MD5 is commonly used for quick identification across threat intelligence platforms, so VirusTotal was used for this analysis.

### Malicious File Identification
- The MD5 hash was submitted to VirusTotal.
- From the Details section, the file size of the malicious sample was identified.
- At this stage, fingerprinting becomes important. The SHA-256 hash was noted, as it is commonly used by researchers and vendors in public malware reports. Many security blogs and threat reports index samples using SHA-256 rather than MD5.

### Victims Description
- Using the SHA-256 hash, a search was performed in a browser to locate related threat intelligence articles.
- This led to a SecureList blog post describing the campaign.
- By using `Ctrl + F` and searching for _“victim”_, the word _Mammoth_ was observed being used in log messages to describe victims, referencing an ancient hunted creature.

### Malicious Website Mimicking peerme.io
- Within the SecureList blog, `Ctrl + F` was used to search for keywords such as _“peer”_, _“website”_, and _“DAO”_.
- In the first sub-campaign, the attackers were observed using the malicious domain **tidyme[.]io**, which mimicked the legitimate peerme.io platform.

### Cloud Storage Used to Host Malware Samples
- To identify where malware samples were hosted, keyword searches such as _“cloud”_, _“storage”_, and _“hosted”_ were used within the blog.
- The hosting platform was identified by locating the section describing how both macOS and Windows payloads were distributed.

### Password Used for Archive Decompression
- The blog post was searched using `Ctrl + F` for the keyword _“password”_.
- The password used for archived data decompression was found in plaintext within an image/figure shown in the analysis.

### Function Responsible for Retrieving the Field Archive
- Keywords such as _“function”_, _“retrieve”_, and _“configuration”_ were used to locate the relevant section in the blog.
- The function responsible for retrieving the field archive from the configuration file was identified from the malware analysis.

### Mimicked AI Translator in the Third Sub-Campaign
- The third sub-campaign section of the blog was reviewed.
- The legitimate AI translator project and the malicious translator created by the attackers were both explicitly mentioned and noted.

### StealC C2 Servers
- Using `Ctrl + F`, the blog was searched for references to _“StealC”_ and _“C2”_.
- Two IP addresses associated with StealC command-and-control servers were identified. Both were required to answer the question.

### Ethereum Wallet Used in the Campaign
- The blog was searched for keywords such as _“cryptocurrency”_ and _“wallet”_.
- The Ethereum wallet address used by the attackers was listed and recorded.

---

## Findings / Indicators of Compromise (IOCs)
| Type                  | Indicator                         |
| --------------------- | --------------------------------- |
| Malicious File Hash   | MD5 / SHA-256                     |
| Phishing Domain       | tidyme[.]io                       |
| Cloud Hosting Service | Identified cloud storage platform |
| StealC C2 Servers     | IP addresses identified in report |
| Ethereum Wallet       | Attacker wallet address           |
