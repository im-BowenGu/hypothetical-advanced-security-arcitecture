# A Practical, Tiered Zero Trust Architecture and Implementation Blueprint

**Abstract:**
Traditional enterprise security, predicated on a trusted internal network, is failing against modern threats. We propose an "Immutable Endpoint Zero Trust Architecture" (IE-ZTA), a comprehensive framework that re-architects security by treating all endpoints as untrusted. This paper evolves the original IE-ZTA concept into a practical, optimized, and resilient blueprint.

This optimized architecture is built on three core principles:
1.  **Tiered Workspace Model:** Acknowledging that one size does not fit all, we segment users into **Non-Persistent VDIs** (for standard users) and **Persistent, Sandboxed VDIs** (for power users, via **Vanilla OS**).
2.  **Centralized "Day 2" Management:** Recognizing that complexity is the enemy of security, this architecture is managed via a centralized **IAM (FreeIPA)**, **Patching (Foreman/Ansible)**, **Secrets (Vault)**, **Backup (Proxmox Backup Server)**, and **PKI (Step-CA)**.
3.  **Integrated FOSS/On-Prem SOC:** A fully-featured Security Operations Center (SOC) is integrated from the ground up, built on the **Elastic Stack**, **TheHive**, **OpenCTI**, and an advanced analysis pipeline using **CAPE**, **LiteLLM**, and **`anythingLLM`**.

We will detail the full implementation stack, from the hypervisor (**Proxmox HA Cluster**) and storage (**Ceph** + **TrueNAS**) to the analyst's workflow, providing both open-source (FOSS) and commercial examples.

---

## 1.0 Introduction

The foundational "castle-and-moat" security model is obsolete. The proliferation of remote work, cloud applications, and sophisticated malware has rendered the traditional endpoint the single greatest liability in the enterprise.

This paper proposes a holistic "Immutable Endpoint Zero Trust Architecture" (IE-ZTA). The core principle is to **never trust the physical endpoint**. Instead, the client device is treated as a "dumb terminal" whose only function is to securely access a centrally-monitored workspace. This model moves all execution and data into a controlled, redundant data center environment.

This document serves as a blueprint for this architecture, segmented into the core components, the "Day 2" operational requirements, and the human workflow for security response.

---

## 2.0 Architectural Components

### 2.1 The "Tiered Workspace" Model (The Core Optimization)

This architecture's primary optimization is the rejection of a "one-size-fits-all" VDI. Users are segmented by risk and need.

* **Tier 1: Standard & High-Risk Users (e.g., Call Center, Finance)**
    * **Model:** **Non-Persistent VDI.**
    * **How:** The user gets a fresh, clean VM from a "golden image" at every login. When they log off, the VM is destroyed.
    * **Security:** This model **solves malware persistence** entirely. Any infection is wiped daily.

* **Tier 2: Power Users (e.g., Developers, Data Scientists, Analysts)**
    * **Model:** **Persistent, Sandboxed VDI.**
    * **How:** The user is provisioned a **Vanilla OS** VDI. The core OS is **immutable** (read-only and patched centrally). Users are given admin rights *only* within the **`apx` sandbox**, allowing them to safely install their own tools (e.g., VS Code, Python libraries).
    * **Security:** This provides the "best of both worlds": a secure, centrally-patched host OS (monitored by our EDR) and a flexible, persistent environment for the user.

### 2.2 The VDI & Endpoint Layer (The "User Factory")

This is the hyper-converged platform that builds and serves the VDI workspaces.

* **Hypervisor:** **Proxmox VE 3-Node HA Cluster**.
    * **Why:** A 3-node cluster provides high availability (HA) and quorum. If one physical server fails, all VMs (including the SOC) are automatically restarted on the other nodes.
* **VDI Access Portal:** **Apache Guacamole**.
    * **Why:** A clientless HTML5 gateway. The user only needs a web browser to access their VDI (via SPICE, RDP, or VNC).
* **Commercial Alternatives:** VMware Horizon or Citrix Virtual Apps and Desktops.

### 2.3 The Network & Perimeter Layer

This layer protects all ingress/egress traffic and replaces the traditional VPN.

* **Firewall/IDS/IPS:** **OPNsense (in HA)**.
    * **Why:** A robust, open-source firewall. It is run as two VMs (one on each Proxmox node) in a **CARP + pfsync** cluster for stateful, seamless failover. It also runs our **CrowdSec Bouncer**.
* **Zero Trust Access (ZTNA):** **Firezone (FOSS)** or **Zscaler Private Access (Commercial)**.
    * **Why:** Replaces VPN. Grants users granular, identity-aware access *only* to the specific applications they are authorized for (e.g., the Guacamole portal).
* **WAF & Reverse Proxy:** **NGINX (with ModSecurity)**.
    * **Why:** A dedicated VM that acts as the WAF and reverse proxy for all public-facing services (Guacamole, Mailcow webmail, etc.).
* **Commercial SASE Alternatives:** This entire layer can be (expensively) consolidated using a commercial SASE/SSE platform like **Palo Alto Prisma Access** or **Cloudflare One**.

### 2.4 The Storage Layer (Redundancy & Persistence)

This architecture uses two distinct, redundant storage tiers.

* **Infrastructure Storage:** **Ceph (via Proxmox)**.
    * **Why:** A hyper-converged, software-defined storage pool. The SSDs/NVMe drives inside the 3 Proxmox nodes are combined into a single, self-healing storage system. All VMs (the VDI golden images, the SOC servers) are stored here, enabling them to be live-migrated and restarted during a hardware failure.
* **User Data Storage:** **TrueNAS CORE**.
    * **Why:** A dedicated NAS (run as a highly-available VM or on separate hardware) using **ZFS** for extreme data integrity.
    * **Integration:** This server hosts all persistent user data. For Tier 1/2, a user's `/home` directory is redirected and mounted from TrueNAS. For Vanilla OS, this is where their persistent `apx` containers are stored.

### 2.5 The Advanced Threat Analysis Pipeline (Email/File)

This is the custom, AI-driven gateway for all email and file-based threats.

* **SMTP Server:** **Mailcow: dockerized**.
* **Analysis Sandbox:** **CAPEv2**.
* **AI Gateway (MCP):** **LiteLLM**.
* **RAG/AI Assistant:** **`anythingLLM`**.
* **Triage Workflow:** An email arrives at Mailcow. A custom Rspamd plugin orchestrates a multi-stage analysis:
    1.  **Stage 1 (Reputation):** IP checked against **CrowdSec**. Attachment hash checked against **VirusTotal**.
    2.  **Stage 2 (Text Analysis):** Email body is sent via the **LiteLLM** gateway to a fast model (e.g., `claude-3-haiku` or a local model) for a phishing score.
    3.  **Stage 3 (Detonation):** If the file is unknown, it is submitted to the **CAPEv2** sandbox for full behavioral analysis and a **MITRE ATT&CK** report.
    4.  **Verdict:** A final score is calculated, and the email is blocked or delivered. All reports are forwarded to the Elastic Stack.

### 2.6 The Security Operations Center (SOC) Stack

This is the central brain for monitoring, detection, and response.

* **SIEM:** **The Elastic Stack (Elasticsearch, Kibana)**.
    * **Why:** The central database and dashboard for all logs from OPNsense, Mailcow, Elastic Defend, CAPE, and all other services.
* **EDR (XDR):** **Elastic Defend**.
    * **Why:** The native EDR for the Elastic Stack. The **Elastic Agent** is installed on the VDI "golden images" (both Windows and Vanilla OS) and all server VMs. It provides anti-malware, ransomware prevention, and deep endpoint visibility.
* **SIRP (Case Management):** **TheHive**.
    * **Why:** The "case file" system for analysts. High-priority Elastic alerts are automatically forwarded to TheHive to create a new case for investigation.
* **TIP (Threat Intel):** **OpenCTI**.
    * **Why:** The "conspiracy board" for all threat intelligence. It ingests reports from CAPE and VT to link malware, threat actors, and techniques (T-numbers).
* **Commercial Alternatives:** Splunk (SIEM), CrowdStrike (EDR), Palo Alto XSOAR (SOAR/SIRP).

---

## 3.0 Day 2 Operations: Management & Resiliency

A complex stack fails without robust management. This is the "Day 2" layer that makes the architecture possible to run in production.

* **3.1 Identity & Access Management (IAM):** **FreeIPA**.
    * **Why:** The open-source equivalent of Active Directory. This is the **central source of truth for identity**. All services (Proxmox, Kibana, TheHive, Guacamole, TrueNAS, etc.) are configured to use FreeIPA's LDAP/Kerberos for authentication. This centralizes user management and access control.
* **3.2 Patch & Lifecycle Management:** **Foreman + Katello** or **Ansible**.
    * **Why:** Automates patching. Patches are synced locally, tested, and then rolled out to all Linux/BSD VMs in a controlled way. For VDIs, the process is simpler: patch the *one* "golden image," and all users get the update on their next login.
* **3.3 Backup & Disaster Recovery:** **Proxmox Backup Server (PBS)**.
    * **Why:** **HA is not a backup.** PBS is a separate, dedicated server that takes incremental, deduplicated backups of all Proxmox VMs and the TrueNAS data. This is the "undo" button for ransomware or catastrophic failure.
* **3.4 Secrets Management:** **HashiCorp Vault**.
    * **Why:** All API keys (VT, CrowdSec, LiteLLM) and database passwords are stored centrally in Vault. Services authenticate to Vault to retrieve their secrets at runtime. This prevents "secret sprawl" in config files.
* **3.5 Internal PKI:** **Step-CA**.
    * **Why:** Acts as the internal "Let's Encrypt" to issue valid SSL certificates for all internal web UIs (Kibana, Proxmox, TheHive, etc.), giving analysts a trusted "green padlock" in their browser.

---

## 4.0 The Analyst's Workflow & Toolkit

This scenario demonstrates how all components work together during a real incident.

1.  **Detection:** The **Elastic Defend** agent on a user's VDI detects a suspicious process (`powershell.exe` spawning from a Word doc). It blocks the process and sends a critical alert to the **Elastic Stack**.
2.  **Triage:** The alert is auto-forwarded to **TheHive**, which creates `CASE-2025-001`. TheHive's "Responders" automatically submit the file hash to **VirusTotal** and the file itself to the **CAPE** sandbox.
3.  **Enrichment:** The CAPE report is finished in 5 minutes. It includes a full process tree and maps the malware's behavior to the **MITRE ATT&CK** framework (e.g., T1053.005 - Scheduled Task). This data is all pulled into the TheHive case and visualized in **OpenCTI**.
4.  **Human Analysis (Workbench):** An analyst logs into **Guacamole** and opens their **FLARE-VM** (a Windows-based analysis VM) or **REMnux** (Linux-based) instance, which runs in a fully isolated "Analysis VLAN" (configured in OPNsense). They pull the malware sample from the CAPE report for manual reverse-engineering.
5.  **Human Analysis (AI Assistant):** The analyst opens their internal **`anythingLLM`** portal (which is pre-loaded with all company playbooks and OpenCTI data). They ask, "What is the playbook for T1053.005, and what other assets are on this user's subnet?" `anythingLLM` provides an instant, contextual answer.
6.  **Response:** The analyst, now fully informed, executes a response from within **TheHive**:
    * **Contain:** Triggers an **Elastic Defend** "Isolate Host" action on the VDI.
    * **Block:** Adds the malware's C2 IP address to a blocklist in **OPNsense**.
    * **Document:** Documents all findings in the **TheHive** case and closes it.

---

## 5.0 Conclusion

This optimized **Immutable Endpoint Zero Trust Architecture** provides a deeply resilient, defense-in-depth posture. By making the standard endpoint disposable (**Non-Persistent VDI**) and the power-user endpoint auditable and sandboxed (**Vanilla OS**), it neutralizes most endpoint malware.

Its true strength, however, lies in its practical integration. The complexity of a diverse FOSS stack is managed through robust "Day 2" automation and centralization (Foreman, Ansible) and a unified IAM (FreeIPA).

This architecture successfully shifts the primary attack surface from the *device* to the *identity*. By building the SOC and VDI infrastructure around a central identity provider, the final line of defense becomes a well-monitored, rapidly-responding human analyst, armed with the best-in-class open-source tools for detection, analysis, and response.
