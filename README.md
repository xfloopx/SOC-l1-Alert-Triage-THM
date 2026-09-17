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



