# SOC-l1-Alert-Triage-THM
Home lab conducted following the Hack the box Soc L1 alert triage module.
# Enterprise SIEM Alert Triage & Incident Analysis

## 🔎 Executive Summary
As a Tier 1 SOC Analyst, I investigated an automated high(senario 1) and critical-severity alerts(Scenario 2), indicating suspicious activity on a critical endpoint. The primary objective was to ingest event telemetry, analyze the artifacts, determine the true nature of the alert (True Positive vs. False Positive), and document actionable findings. Through diligent investigation, the activity was successfully classified, mapped to the MITRE ATT&CK framework, and packaged into a standardized escalation ticket.

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



