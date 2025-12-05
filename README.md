# SOC Home Lab: Windows Domain, Sysmon Logging, Splunk SIEM, and Adversary Simulation

## Overview
This project involved building a security operations (SOC) home lab designed to simulate an enterprise environment and generate real telemetry for detection, alerting, and incident investigation. The environment included a Windows domain, endpoint logging via Sysmon, log ingestion into Splunk, and offensive security simulations to produce realistic data for analysis.

## Lab Architecture

### Virtual Machines
| System | Role | Key Details |
|-------|------|--------------|
| Windows Server 2022 | Domain Controller | Domain: cyberlab.local, Active Directory, DNS, GPO |
| Windows 10 Workstation | Domain-joined Endpoint | Users: cyberlab\lspark, cyberlab\jmurphy. Sysmon, Splunk Universal Forwarder, Atomic Red Team installed |
| Ubuntu | Splunk Server | Splunk Enterprise on port 8000, custom index: `endpoint` |
| Kali Linux | Attacker Machine | Used for RDP brute-force attempts with Hydra, Crowbar, Ncrack, xfreerdp |

---

## Project Objectives
- Build an enterprise-like Windows domain environment.
- Configure Sysmon logging tuned for security telemetry.
- Forward endpoint logs to Splunk for SOC analysis.
- Generate attack-based telemetry through brute-force attempts and MITRE ATT&CK simulations.
- Troubleshoot log ingestion and visibility issues.
- Perform detections and event correlation within Splunk.

---

## Configuration and Implementation

### 1. Active Directory and Domain Setup
- Installed and configured Windows Server 2022 as domain controller.
- Created domain `cyberlab.local` and joined Windows 10 to the domain.
- Managed user accounts, domain policies, and RDP authentication settings.

### 2. Endpoint Logging and SIEM Integration

#### Sysmon
Sysmon was deployed using Olaf Hartong’s modular configuration to capture high-value telemetry:

| Event IDs Logged | Description |
|------------------|-------------|
| 1 | Process creation |
| 3 | Network connections |
| 11 | File creation |

#### Splunk Universal Forwarder
Logs forwarded from the Windows 10 endpoint included:
- Security
- System
- Application
- Sysmon Operational

A custom index `endpoint` was created for ingestion.

#### Troubleshooting Log Ingestion
Initial ingestion failed due to missing Windows event log inputs. Manual monitors were added:
```powershell
.\splunk.exe add monitor "C:\Windows\System32\Winevt\Logs\Security.evtx"
.\splunk.exe add monitor "C:\Windows\System32\Winevt\Logs\System.evtx"
.\splunk.exe add monitor "C:\Windows\System32\Winevt\Logs\Application.evtx"

net stop splunkforwarder
net start splunkforwarder
```
This restored telemetry flow to Splunk, reinforcing understanding of inputs.conf and ingestion pipelines.

---

## Adversary Simulation and Telemetry Generation

### RDP Brute-Force Attempts
Tools used: Crowbar, Hydra, Ncrack, xfreerdp

The brute-force attempts did not authenticate successfully due to RDP security layers, NLA, NTLM, and CredSSP enforcement. However, the attacks generated valuable telemetry including:

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4634 | Logoff |
| 5379 | Credential Manager access |

### Atomic Red Team Execution
Executed the following MITRE ATT&CK techniques:

| Technique | Description |
|----------|-------------|
| T1136.001 | Local account creation |
| T1059.001 | PowerShell execution with policy bypass |

Resulting telemetry observed in Splunk:
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 3 (Network Connections)
- Event ID 4104 (PowerShell Script Block Logging)
- Event ID 4720 (Account Creation)

---

## Key Takeaways
This project provided hands-on experience building and defending a simulated enterprise network. Key skills developed include:

- Active Directory and domain administration
- Log pipeline configuration using Sysmon and Splunk Universal Forwarder
- Troubleshooting ingestion failures and validating event flow
- Understanding RDP authentication mechanisms (NTLM, CredSSP, NLA)
- MITRE ATT&CK testing and detection validation
- Event correlation and threat hunting within Splunk

---
