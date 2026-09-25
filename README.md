# SOC-L1-Alert-Triage-THM
Home lab conducted following the Hack the box Soc L1 alert triage module.


## 🔎 Executive Summary
As a Tier 1 SOC Analyst, I investigated 4 alerts in THM SIEM indicating suspicious activity on a critical endpoint. The primary objective was to ingest event telemetry, analyze the artifacts, determine the true nature of the alert (True Positive vs. False Positive), and document actionable findings. Through diligent investigation, the activity was successfully classified, mapped to the MITRE ATT&CK framework, and packaged into a standardized escalation ticket.

## 🛠️ Security Stack & Environment
* **SIEM & Analytics:** Used THM SIEM
* **Telemetry Sources:** Endpoint Telemetry (Host-Based Logs) and specifically Sysmon (System Monitor) combined with Browser Download Logs.


## 📊 Scenario 1: Malicious Payload Delivery (Host-Based Threat)

### 🎯 Threat Indicators & Targeted Asset
* **Alert Ingested:** Double-Extension File Creation
* **Severity Classification:** High
* **Targeted Hostname:** `LPT-HR-009` (HR Department Laptop)
* **Impacted User Account:** `S.Conway`
* **Compromised Vector:** `chrome.exe` (Web Browser)
* **Target File Path:** `C:\Users\S.Conway\Downloads\cats2025.mp4.exe`
* **File MotW (Source URL):** `https://freecatvideoshd.monster/cats2025.mp4.exe`
* **File Cryptographic Hash:** `14d8486f3f63875ef93cfd240c5dc10b` (MD5)
<img width="1471" height="426" alt="scenario1_lumma_stealer" src="https://github.com/user-attachments/assets/c6e5e2e5-f1cd-4523-a795-e872384c0438" />



### 🛠️ Security Stack & Telemetry Sources
* **SIEM/Analytics:** [e.g., Splunk / Elastic Security / OpenSearch]
* **Telemetry Sources:** 
  * Microsoft-Windows-Sysmon (Event ID 11 - File Create) -> Populated target file and hash metadata.
  * Microsoft-Windows-Sysmon (Event ID 1 - Process Creation) -> Identified the downloading process (`chrome.exe`) and user context.
  * Windows Mark of the Web (MotW) / Alternative Data Streams -> Captured the remote source URL tracking context.

### 🔬 Technical Triage & Threat Intelligence Analysis
* **Evasion Technique Identification:** The rule triggered because a binary file was written to disk utilizing a double-extension format (`.mp4.exe`). This specific technique relies on the operating system's default configuration to suppress known file extensions, social engineering the user into executing a binary executable under the guise of an innocuous MP4 media file.
* **Open Source Intelligence (OSINT) Enrichment:** Pivot analysis of the MD5 file hash (`14d8486f3f63875ef93cfd240c5dc10b`) against threat intelligence platforms explicitly links this artifact to the **Lumma Stealer (LummaC2)** malware family.
* **Malware Objective:** Lumma Stealer acts as an information-scraping mechanism. If executed, it targets system memory to extract web browser credentials, session cookies, crypto-wallet data, and local configuration details before exfiltrating them over an external Command and Control (C2) network.

### ⚠️ Final Disposition & Action
* **Classification:** **True Positive** (Malicious Delivery Phase)
* **MITRE ATT&CK Mapping:**
  * Initial Access: **T1566.002** – Phishing: Malicious Link
  * Defense Evasion: **T1204.002** – User Execution: Malicious File
  * Defense Evasion: **T1036.007** – Masquerading: Double Extension
* **Recommended Containment & Next Steps:**
  1. Leverage Endpoint Detection and Response (EDR) capabilities to immediately isolate host `LPT-HR-009` from the local network to contain potential payload propagation or C2 communication.
  2. Implement an automated script or tool to locate and permanently purge `cats2025.mp4.exe` from the host's physical storage filesystem.
  3. Deploy a permanent blocklist rule at the perimeter firewall/web proxy for the malicious root infrastructure domain `freecatvideoshd.monster`.
  4. Revoke active session tokens and initiate a mandatory password reset policy for user `S.Conway` across enterprise services due to high credential exposure risk.



## 📊 Scenario 2: Data Exfiltration Analysis (Network Anomaly)

### 🎯 Threat Indicators & Targeted Asset
* **Alert Ingested:** Potential Data Exfiltration
* **Severity Classification:** Critical
* **Internal Source IP:** `192.168.45.66`
* **Network Segment:** `UK04/MEETINGROOM`
* **External Destination Domain:** `*.zoom.us` (Zoom Video Communications)
* **Data Transferred:** Sent: **5.8 GB** | Received: **5.2 GB**
<img width="1470" height="339" alt="scenario2_zoom_exfil" src="https://github.com/user-attachments/assets/0aaa04ca-d29a-498c-9067-f67ef4c7d90c" />



### 🛠️ Security Stack & Telemetry Sources
* **SIEM/Analytics:** [e.g., Splunk / Palo Alto Networks Cortex / Wireshark]
* **Telemetry Sources:** Network Flow Logs (NetFlow/Zeek), Firewall Perimeter Traffic Logs

### 🔬 Technical Triage & Analysis
* **Volume Discrepancy:** The correlation rule triggered on a high-volume outbound threshold (Device sent >5 GB to an external destination within 24 hours). 
* **Symmetry Evaluation:** Analysis of the underlying network flow logs revealed a symmetric data ratio (5.8 GB egress vs. 5.2 GB ingress). Adversarial data exfiltration typically demonstrates heavily asymmetric outbound spikes with negligible inbound traffic. 
* **Contextual Validation:** Cross-referencing the network segment (`UK04/MEETINGROOM`) with the destination infrastructure (`zoom.us`) confirmed the traffic corresponds to a high-definition enterprise video conferencing session rather than an unauthorized data staging/theft event.

### ⚠️ Final Disposition & Action
* **Classification:** **False Positive** (Legitimate Corporate Activity)
* **MITRE ATT&CK Mapping:** N/A (Legitimate utility usage mimicking *Exfiltration Over Web Service - T1567*)
* **Analyst Action Note:** Closed alert. No further host isolation or containment required. Recommended adjusting the SIEM correlation rule parameters to whitelist known enterprise video communication destinations (`*.zoom.us`, `*.teams.microsoft.com`) when originating from designated physical meeting room network blocks to reduce alert fatigue.

## 📊 Scenario 3: Post-Delivery Phishing Analysis (Inbound Mail Threat)

### 🎯 Threat Indicators & Targeted Asset
* **Alert Ingested:** Phishing After Delivery (Spoofed Microsoft Support)
* **Severity Classification:** High
* **Targeted Hostname / User:** `e.huffman-desktop` (Eddie Huffman, `e.huffman@tryhackme.thm`)
* **Malicious Attachment & Sender:** `REPORT.rar` from spoofed `support@microsoft.com`

### 🔬 Technical Triage & Analysis
* **Impersonation & Evasion:** The email spoofed a high-reputation domain but failed authentication protocols. The `.rar` attachment aimed to smuggle payloads past basic scanners.
* **Authentication Failures:** SPF, DKIM, and DMARC validations all failed, indicating unauthorized sending infrastructure and cryptographic mismatches.
* **Malware Objective:** Compressed archives like `REPORT.rar` are used to hide loaders or scripts, potentially leading to credential harvesting or initial access beaconing.

### ⚠ Final Disposition & Action
* **Classification:** **True Positive** (Malicious Delivery Phase)
* **MITRE ATT&CK Mapping:** T1566.001 (Phishing: Malicious Attachment) & T1036.005 (Masquerading)
* **Remediation Steps:** Purge the email from the user's mailbox, verify EDR logs on `e.huffman-desktop` for extraction activity, block the rogue origin IP at the gateway, and conduct user awareness training.
<img width="1844" height="427" alt="scenario3_phishing_reporting" src="https://github.com/user-attachments/assets/8ae66559-d56d-49d6-9aa5-8d74e7490655" />


## 📊 Scenario 3: Post-Delivery Phishing Analysis (Inbound Mail Threat)

### 🎯 Threat Indicators & Targeted Asset
* **Alert Ingested:** Phishing After Delivery (Spoofed Microsoft Support)
* **Severity Classification:** High
* **Targeted Hostname / User:** `e.huffman-desktop` (Eddie Huffman, `e.huffman@tryhackme.thm`)
* **Malicious Attachment & Sender:** `REPORT.rar` from spoofed `support@microsoft.com`

### 🔬 Technical Triage & Analysis
* **Impersonation & Evasion:** The email spoofed a high-reputation domain but failed authentication protocols. The `.rar` attachment aimed to smuggle payloads past basic scanners.
* **Authentication Failures:** SPF, DKIM, and DMARC validations all failed, indicating unauthorized sending infrastructure and cryptographic mismatches.
* **Malware Objective:** Compressed archives like `REPORT.rar` are used to hide loaders or scripts, potentially leading to credential harvesting or initial access beaconing.

### ⚠ Final Disposition & Action
* **Classification:** **True Positive** (Malicious Delivery Phase)
* **MITRE ATT&CK Mapping:** T1566.001 (Phishing: Malicious Attachment) & T1036.005 (Masquerading)
* **Remediation Steps:** Purge the email from the user's mailbox, verify EDR logs on `e.huffman-desktop` for extraction activity, block the rogue origin IP at the gateway, and conduct user awareness training.
<img width="1844" height="427" alt="scenario3_phishing_reporting" src="https://github.com/user-attachments/assets/da605663-b805-4eea-989a-4dcb4a0f649c" />


## 📊 Scenario 4: Spike of Domain Discovery Commands (Web Shell & Reconnaissance)

### 🎯 Threat Indicators & Targeted Asset
* **Alert Ingested:** Spike of Domain Discovery Commands
* **Severity Classification:** Critical
* **Targeted Hostname:** DMZ-MSEXCHANGE-2013 (Exposed Mail Infrastructure)
* **Impacted User Account:** NT AUTHORITY\SYSTEM (Maximum Local Privileges)
* **Compromised Vector:** w3wp.exe (IIS Web Server Worker Process)
* **Target File Path:** C:\Users\Public\revshell.exe
* **Target Domain:** tryhackme.thm

![scenario4_domain_discovery](scenario4_domain_discovery.png)

### 🛠 Security Stack & Telemetry Sources
* **SIEM/Analytics:** [e.g., Splunk / Elastic Security / OpenSearch]
* **Telemetry Sources:**
    * Microsoft-Windows-Sysmon (Event ID 1 - Process Creation) -> Captured the abnormal w3wp.exe -> revshell.exe -> cmd.exe process lineage.
    * Microsoft-Windows-Security-Auditing (Event ID 4688 - Process Creation) -> Tracked the rapid execution of internal domain discovery command arguments.

### 🔬 Technical Triage & Threat Intelligence Analysis
* **Evasion & Execution Lineage:** The incident presents a classic web application compromise. The IIS process (`w3wp.exe`) should only handle HTTP/HTTPS web requests; spawning an untrusted binary (`revshell.exe`) from a globally writable directory (`C:\Users\Public\`) confirms a web shell exploit or remote code execution (RCE) payload.
* **Adversary Objective:** Upon establishing the reverse shell connection under system privileges, the actor bypassed local privilege escalation and skipped directly to internal reconnaissance. The sequential use of `net group` and `nltest` indicates an automated script mapping the Active Directory layout.
* **Malware Objective:** The activity serves as the enumeration prelude to lateral movement. The actor is mapping out high-value accounts and identifying primary Domain Controllers to prepare for domain-wide takeover or ransomware deployment.

### Threat Intelligence & Artifacts

| Artifact Type | Indicator Value | Assessment / Context |
| :--- | :--- | :--- |
| **Parent Process** | `C:\Users\Public\revshell.exe` | **Malicious Carrier** (Unauthorized network-facing binary) |
| **Discovery Binary** | `nltest.exe /dclist:tryhackme.thm` | **Reconnaissance** (Active Directory Domain Controller query) |
| **Privilege Scope** | `whoami /priv` | **Enumeration** (Verifying administrative rights and tokens) |

### ⚠ Final Disposition & Action
* **Classification:** **True Positive** (Web Shell Compromise / Internal Reconnaissance)
* **MITRE ATT&CK Mapping:**
    * Initial Access: **T1190** – Exploit Public-Facing Application
    * Execution: **T1059.003** – Command and Scripting Interpreter: Windows Command Shell
    * Discovery: **T1087.002** – Account Discovery: Domain Account
    * Discovery: **T1018** – Remote System Discovery
* **Recommended Containment & Next Steps:**
    1. Leverage Endpoint Detection and Response (EDR) capabilities to immediately isolate host `DMZ-MSEXCHANGE-2013` from the network to kill the active C2 loop.
    2. Enforce absolute process termination over the rogue `revshell.exe` binary instance and clear any lingering child cmd loops.
    3. Collect `revshell.exe` along with corresponding IIS web application logs around the timestamp to analyze the web shell vector.
    4. Review Active Directory controller telemetry to verify whether the actor managed to utilize any discovered domain admin credentials against secondary servers.
<img width="1828" height="558" alt="scenario4_domain_discovery" src="https://github.com/user-attachments/assets/b80544ce-c161-4f27-8696-efaa0043aa01" />

## 📁 Case Study: Structured Alert Triage (Workbooks & Lookups)

### 📌 Overview
This section documents the implementation of structured analytical workflows using incident response workbooks and operational lookups. Rather than relying on ad-hoc analytical instincts, this framework ensures standardized, repeatable, and error-free alert triage for a Tier 1 SOC environment.

---

### 🧠 Core Concepts

#### 1. The Triage Lifecycle
*   **Enrichment:** Querying asset, identity, and threat intelligence lookups to add context to an alert.
*   **Investigation:** Cross-referencing enriched indicators against SIEM logs to determine intent.
*   **Escalation:** Systematically passing validated, high-severity threats to Tier 2 handlers.

#### 2. The Power of Lookups
*   **Asset Inventories:** Mapping IP addresses to device owners, critical servers, and network zones.
*   **Identity Lookups:** Verifying user roles, department alignment, and active HR travel logs.
*   **Network Diagrams:** Identifying perimeter boundaries to differentiate internal noise from external threats.

---

### 🚦 Queue Prioritization Matrix
To manage high-volume alert queues efficiently, incoming incidents are triaged based on a strict two-factor logic:

1.  **Severity First:** High/Medium alerts are always triaged before Low/Informational alerts.
2.  **Age Second:** If alerts share identical severity, the oldest uninvestigated alert is prioritized.

| Priority | Alert Severity | Age Context | Action |
| :--- | :--- | :--- | :--- |
| **1** | 🔴 High | Oldest first | Immediate isolation & containment |
| **2** | 🟡 Medium | Oldest first | Investigation within SLA window |
| **3** | 🔵 Low | Oldest first | Review when queue is clear |

---

### 📜 Incident Playbooks (SOPs)

#### 📋 Playbook 1: Unusual Login Location
*   **Trigger:** SIEM flags a user logging in from an atypical geographic location or IP range.
*   **Lookup Phase:** Check corporate HR records (e.g., BambooHR) for active travel requests.
*   **Log Verification:** Inspect VPN logs for concurrent sessions from conflicting geographic regions.
*   **Triage Logic:** 
    *   *Match:* If the user has an approved travel log matching the location → **Close as False Positive**.
    *   *No Match:* If no travel records exist and sessions overlap → **Escalate to Tier 2 (Account Compromise)**.

#### 📋 Playbook 2: Suspicious PowerShell Execution
*   **Trigger:** EDR logs a PowerShell process downloading an executable file from the internet.
*   **Enrichment Phase:** Extract the target URL and query Threat Intelligence platforms (VirusTotal/AbuseIPDB).
*   **Process Analysis:** Review the parent-child process tree (`cmd.exe` → `powershell.exe`).
*   **Triage Logic:**
    *   *Malicious:* URL matches known malicious infrastructure → **Isolate Endpoint & Escalate**.
    *   *Benign:* Process is a verified, digitally signed administrative script → **Whitelist & Document**.

#### 📋 Playbook 3: Internal Port Scanning
*   **Trigger:** Internal firewall blocks rapid connection attempts across multiple ports from a single host.
*   **Asset Lookup:** Match the source IP against the corporate Asset Inventory.
*   **Role Verification:** Check if the device is a designated vulnerability scanner (e.g., Nessus, Qualys).
*   **Triage Logic:**
    *   *Authorized:* Source IP matches an official security scanner on schedule → **Close as Informational**.
    *   *Unauthorized:* Source IP belongs to a standard user workstation → **Quarantine Host (Lateral Movement)**.

---

### 🎯 Key Takeaways & Skills Demonstrated
*   **Reduced MTTR (Mean Time to Respond):** Standardizing triage paths minimizes analytical hesitation during critical windows.
*   **Eliminated False Positives:** Leveraging context tools (lookups) prevents business-disrupting false alarms.
*   **Operational Consistency:** Ensures every analyst on the team reaches the exact same conclusion given the same data points.

## 📊 SOC Operations: Metrics & Objectives

### 🎯 Core Mission & Strategic Objectives
A Security Operations Center does not just chase alerts; it protects business continuity. This project aligns technical triage with three primary operational goals:
1.  **Maximize Visibility:** Ensure comprehensive log coverage across endpoints, network perimeters, and cloud environments.
2.  **Minimize Attacker Dwell Time:** Detect and neutralize threats before they can move laterally or exfiltrate data.
3.  **Optimize Resource Efficiency:** Use automation and well-defined playbooks to reduce fatigue on Tier 1 analysts.

---

### 📈 Key Performance Indicators (KPIs) & Metrics
To measure the effectiveness of the triage playbooks and queue management strategies implemented in this lab, the following industry-standard metrics are tracked:

#### 1. Time-Based Operational Metrics
*   **Mean Time to Detect (MTTD):** The average time from when a malicious event occurs to when the SIEM triggers an alert. 
    *   *Goal:* Minimal. Driven by optimized correlation rules.
*   **Mean Time to Acknowledge (MTTA):** The average time it takes a Tier 1 analyst to pick up an unassigned alert from the queue and begin tracking it.
    *   *Goal:* Under 15 minutes for High/Medium alerts.
*   **Mean Time to Respond/Remediate (MTTR):** The average time from alert acknowledgment to full containment or resolution (e.g., isolating the host, blocking an IP).
    *   *Goal:* Under 60 minutes for critical incidents, heavily accelerated by using the playbooks documented above.

#### 2. Data Quality & Efficiency Metrics
*   **False Positive Rate:** The percentage of alerts that turn out to be benign background noise or authorized behavior.
    *   *Impact:* High false positive rates cause analyst burnout. This repo's use of **Lookups** (Asset and HR directories) directly lowers this metric.
*   **Alert-to-Incident Ratio:** The volume of raw alerts compared to true security incidents that require escalation.
    *   *Impact:* Helps engineers tune SIEM rules to eliminate useless alert noise.

---

### 🛠️ Strategic Summary: The Analyst's Impact
As a Tier 1 analyst, my primary day-to-day focus directly influences **MTTA** and **False Positive Reduction**. By utilizing structured workbooks, I ensure that alerts are acknowledged instantly according to queue priority, and benign traffic is filtered out accurately using corporate lookups before it can skew our MTTR.


# TryHackMe: Introduction to EDR (Lab Walkthrough)

## 📌 Project Overview
This laboratory exploration focuses on the core mechanics, capabilities, and operational deployment of **Endpoint Detection and Response (EDR)** solutions within a modern Security Operations Center (SOC). 

Unlike traditional signature-based antivirus solutions, EDR provides continuous, real-time visibility into endpoint behavior. This lab demonstrates how EDR tools aggregate telemetry, construct process trees, detect advanced persistent threats (APTs), and facilitate rapid incident response.

<img width="959" height="874" alt="image" src="https://github.com/user-attachments/assets/b92361b8-5d0d-46ed-b049-daed933e3202" />


### 🛠️ Core Capabilities Demonstrated
* **Behavioral Analysis:** Overcoming static signature evasion by monitoring live system behavior.
* **Process Lineage Mapping:** Visualizing parent-child process relationships to track initial access and execution vectors.
* **Telemetry Aggregation:** Analyzing event logs, network connections, file modifications, and registry changes.
* **Incident Response & Remediation:** Executing host isolation, process termination, and artifact containment.

---

## 🏗️ Architectural Topology
To effectively triage EDR alerts, it is critical to understand the architecture enabling data collection. This lab covers the standard hub-and-spoke model utilized by enterprise EDR platforms:

```text
  [ Target Endpoint ]       [ Target Endpoint ]       [ Target Endpoint ]
  (w/ EDR Agent Installed)  (w/ EDR Agent Installed)  (w/ EDR Agent Installed)
            │                         │                         │
            └─────────────────────────┼─────────────────────────┘
                                      ▼
                        [ Continuous Telemetry Stream ]
                                      │
                                      ▼
                        ┌──────────────────────────┐
                        │    EDR Cloud/Console     │
                        │  (Ingestion & Analysis)  │
                        └─────────────┬────────────┘
                                      │
                                      ▼
                        ┌──────────────────────────┐
                        │   SOC Analyst Triage     │
                        │   (Alerts & Playbooks)   │
                        └──────────────────────────┘
```

1. **EDR Agent:** A lightweight service running on the endpoint monitoring API calls, memory, registry, network, and file systems.
2. **EDR Server/Cloud:** The centralized management console that ingests raw telemetry, correlates events, maps behavior against frameworks like MITRE ATT&CK, and surfaces actionable alerts.

---

## 🔍 Analytical Deep Dive & Log Triage

> [!NOTE]
> *Analyst Note: The following section documents the triage workflow, process tracking, and mitigation steps taken during the practical lab scenario.*

### 1. The Process Tree (Execution Lineage)
When investigating modern malicious payloads (such as living-off-the-land binaries), mapping process execution is critical. Below is the mapped lineage of the malicious activity identified during the lab:

```text
[PID 1024] explorer.exe (User Session)
   └── [PID 4096] outlook.exe (Malicious Email Attachment Opened)
        └── [PID 5120] cmd.exe (Spawned Command Line)
             └── [PID 6144] powershell.exe -EncodedCommand BASE64... (Obfuscated Execution)
                  └── [PID 7168] beacon.exe (C2 Callback established)
```

### 2. Telemetry Artifacts Identified
* **File System:** A suspicious binary dropped into `C:\Users\Public\`.
* **Network:** Outbound connections initiated by `powershell.exe` to an external, unclassified IP address on port `443`.
* **Registry:** Persistence established by modifying the `Run` key at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

---

## 🛡️ Defensive Engineering & Remediation Playbook
An EDR's primary value is its ability to stop an active attack in its tracks. The following containment strategies were explored:

* **Host Isolation:** Severing the compromised endpoint's network connectivity at the data link layer while maintaining the EDR management channel for forensic investigation.
* **Process Termination:** Instantly killing `PID 7168 (beacon.exe)` and its parent processes to stop active malicious memory loops.
* **Ban Hash (Blocklisting):** Submitting the SHA-256 hash of the malicious file to the global EDR policy engine to prevent execution on any other endpoint across the enterprise network.

---

## 🧠 Key Takeaways
1. **Visibility Over Signatures:** Traditional AV fails against fileless malware or memory injection. EDR fills this visibility gap by focusing on *what a process does*, not just *what it looks like*.
2. **Context is King:** Individual logs (like a single network connection or file creation) might look benign. EDR correlates these fragmented events into a chronological timeline, exposing the full attack lifecycle.

# TryHackMe: Introduction to SIEM (Lab Walkthrough)

## 📌 Project Overview
This section covers the core fundamentals of **Security Information and Event Management (SIEM)** solutions within a Security Operations Center (SOC). 

In enterprise environments, security infrastructure generates millions of fragmented data points daily. This lab explores how a SIEM serves as the centralized "brain" of a SOC—collecting, parsing, normalizing, and correlating massive volumes of disparate log data to detect active threats in real time.

### 🛠️ Core Concepts Demonstrated
* **Log Aggregation & Ingestion:** Collecting data from endpoints, firewalls, servers, and authentication databases into a single repository.
* **Data Normalization:** Converting messy, vendor-specific logs into a standardized format (e.g., mapping fields to generic names like `source_ip` and `dest_port`).
* **Correlation Rules:** Writing logic parameters that stitch separate, seemingly benign events together to flag a single complex attack pattern.
* **Alerting & Dashboarding:** Visualizing trends, identifying statistical anomalies, and generating actionable alerts for analysts.

---

## 🏗️ The SIEM Architecture Lifecycle
To effectively query logs, an analyst must understand how data travels from a local machine into the SIEM dashboard. The TryHackMe curriculum maps this out across three primary stages:

<img width="444" height="342" alt="image" src="https://github.com/user-attachments/assets/4eb967f3-a470-42ae-b2db-d653d927c10a" />


```text

┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
│  1. Log Collection   │ ───> │   2. Log Ingestion   │ ───> │  3. Log Retention    │
│ (Agents, Forwarders, │      │ (Parsing, Indexing,  │      │  (Storage, Archiving,│
│   Syslog Streamers)  │      │  Correlation Rules)  │      │   Search Queries)    │
└──────────────────────┘      └──────────────────────┘      └──────────────────────┘
```

1. **Data Collection:** Lightweight software agents (e.g., Splunk Forwarders, Elastic Beats, Logstash) monitor log files locally on targets and forward them to the central SIEM.
2. **Data Ingestion & Parsing:** The SIEM receives raw unstructured text, parses out key fields, hashes or stores timestamps accurately, and runs the data against active correlation alerts.
3. **Data Indexing & Searching:** The processed data is written to rapid-access storage disks, allowing SOC analysts to search history using specialized query languages (e.g., Splunk SPL or Lucene/KQL).

---

## 📊 Essential Log Sources Tracked
To build visibility across a target network, the SIEM pulls telemetry from highly specific system logs explored throughout this pathway:

* **Authentication Logs:** Tracking `Event ID 4624` (Successful Logon) and `Event ID 4625` (Failed Logon) in Windows, or `/var/log/auth.log` in Linux to catch brute-force attempts.
* **Network Logs:** Ingesting firewall permits/denies, DNS queries, and proxy server logs to trace command-and-control (C2) beacons or data exfiltration.
* **Application & Web Logs:** Monitoring Apache, Nginx, or IIS web server logs (tracking HTTP status codes like `403 Forbidden` or `500 Internal Error`) to spot web application attacks like SQL Injection or Local File Inclusion (LFI).

---

## 🧠 Key Takeaways
1. **The Power of Correlation:** A firewall block or a failed login sequence on its own might look normal. The true strength of a SIEM lies in its ability to alert an analyst when those two events happen simultaneously across different parts of the network.
2. **Standardization Saves Time:** Without a SIEM, an analyst would waste critical triage minutes adjusting to the structural log style differences between a Cisco firewall, a Linux server, and a Windows Domain Controller.


