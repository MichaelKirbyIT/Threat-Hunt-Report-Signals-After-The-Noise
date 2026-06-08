# Threat Hunt Report — Signals After the Noise
**PHTG HealthCloud // Post-Intrusion Analysis**<br>
**Telemetry Window:** December 13, 2025<br>
**Analysis Completed:** May 2026<br>
**Analyst**: Michael Kirby | **Classification:** Internal

---

## Platforms and Languages Leveraged

- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- SIEM: Microsoft Sentinel (Log Analytics Workspace: LAW-Cyber-Range)

---

## Where It Started

The break-in was already established. The lead-up was known. What wasn't known was what the operator did once inside.

This hunt covered a seven-hour window on 13 December 2025, anchored at 09:48 UTC — the moment the operator's session became active. Two workstations were in scope: **azwks-phtg-01** and **azwks-phtg-02**. The compromised account was **vmadminusername**. My job was to reconstruct what the operator touched, what they stood up to stay resident, how they communicated out, and what they reached for at the end.

The first instinct when looking at the authentication table was to call it brute force. There were failed logons. Then there was a success. That sequence reads like credential guessing. It wasn't. Pulling that thread first changed the shape of everything that followed.

---

## Phase 1 — Cold Trail: How They Got Back In

Before hunting what the operator did on the host, I needed to confirm how they returned.

I summarized DeviceLogonEvents by ActionType, LogonType, RemoteIP, and AccountName to put failures and successes side by side in one view:

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| summarize count() by ActionType, LogonType, RemoteIP, AccountName
| order by ActionType asc
```

The failures came from a scatter of external IPs — different sources, generic account names: root, admin, administrator. Background internet noise, completely unrelated to vmadminusername. The vmadminusername success was different in every dimension: **Batch logon type, no RemoteIP**. No external source. No credential guessing preceded it.

A Batch logon with no RemoteIP means automated execution — a scheduled task or batch job running locally, not an interactive session from outside. The attacker didn't come back by guessing a password. They came back through a door they had already propped open.

Pivoting to DeviceEvents confirmed it. A scheduled task named **PHTG User Baseline Report** was cycling — deleted and re-created at regular intervals, running a PowerShell script from the HealthCloud directory under vmadminusername. This was persistence planted in a prior session, firing automatically. The operator hadn't typed a single character yet. Their tooling had already begun working.

**Access vector: credential reuse.** The attacker returned with credentials they already held. The scheduled task did the initial work before the operator even logged in interactively.

---

## Phase 2 — First Footsteps: Lateral Movement

With the session confirmed, the next question was direction. Where did the operator go?

I filtered DeviceLogonEvents to vmadminusername successful logons from the anchor time at 09:48, projecting account, source IP, target device, and logon type:

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where AccountName == "vmadminusername"
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public" or isnotempty(RemoteIP)
| project TimeGenerated, AccountName, RemoteIP, DeviceName, LogonType
| order by TimeGenerated asc
```

The key distinction in this table is perspective. DeviceLogonEvents records events from the **target device's point of view** — the RemoteIP field shows who connected to it, making it the source. The DeviceName field shows where the event was recorded, making it the target.

The first RemoteInteractive logon landed on **azwks-phtg-01** at 09:48, sourced from **10.0.0.152** — the internal IP of azwks-phtg-02. The attacker's compromised machine had reached out to a second workstation. Lateral movement, confirmed.

What made this finding significant was the timing. This happened at 09:48 — before the operator's manual RDP session from Uruguay arrived at 09:52. The scheduled task had performed the lateral movement automatically, before its operator had even sat down at the keyboard. The persistence mechanism did the work first.

To confirm the movement stopped there, I ran the same query against phtg-01's internal IP (10.0.0.105) across the full fleet with no DeviceName filter. No results. The attacker pivoted to phtg-01 and stayed there.

**Lateral movement summary: vmadminusername, 10.0.0.152, azwks-phtg-01.**

---

## Phase 3 — On the Host: Scripts, Staging, and Concealment

Once on azwks-phtg-01, the operator's activity became visible in process telemetry.

The first priority was identifying what they ran. Session startup is noisy — Windows fills the process table with background services, COM handlers, and display processes that all fire at the moment a desktop session begins. Filtering to script-related ProcessCommandLine entries cut through that noise immediately:

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName in ("azwks-phtg-01", "azwks-phtg-02")
| where AccountName == "vmadminusername"
| where ProcessCommandLine has ".ps1" or ProcessCommandLine has ".bat" or ProcessCommandLine has ".vbs"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
| take 10
```

The first script at 10:11 on azwks-phtg-01 was a deliberately inconspicuous file — **`_.ps1`**, a single underscore, easy to miss in any process list. The invocation used two PowerShell flags that together are a high-fidelity indicator of malicious execution: **`-WindowStyle Hidden`** suppresses the console window entirely, and **`-ExecutionPolicy Bypass`** overrides the system policy blocking unsigned scripts. Legitimate administration scripts rarely need both. Together they signal intent to run without being seen.

The ProcessCommandLine also revealed the operator's **staging directory** without any additional pivot. Every subsequent task script path contained `C:\ProgramData\PHTG\HealthCloud\Cache\` — and one level up was the root staging workspace: **`C:\ProgramData\PHTG\HealthCloud`**. The operator had nested their entire tooling infrastructure inside the directory of a legitimate internal application.

**File concealment followed.** The attacker ran `attrib.exe` against files in the staging directory, setting the hidden (+h) and system (+s) attributes to make them invisible in normal Explorer views and basic directory listings. Extracting the subdirectory from each attrib command line using `split` revealed two targeted locations — Cache and TempCache — with TempCache receiving the heavier treatment. A defender browsing those folders normally would see nothing.

**LOLBin masquerade.** Comparing FileName against ProcessVersionInfoOriginalFileName and excluding `C:\Windows\` paths surfaced a single anomalous binary: **PHTGHealthCloudSvc.exe**, running from `C:\ProgramData\PHTG\HealthCloud\`, claiming at compile time to be `bitsadmin.exe`. Every other filename mismatch in the results ran from System32 — legitimate Windows behaviour. This one didn't. The binary was masquerading as a Microsoft tool while living in an attacker-controlled directory.

---

## Phase 4 — Quiet Roots: Persistence

With active operations underway, the operator planted multiple mechanisms to ensure they could return.

I started where persistence almost always lives first — the registry Run key. Filtering DeviceRegistryEvents to Run-related paths under vmadminusername returned 280 events. Most were noise: desktop themes, MUI cache entries, COM CLSID re-registration. None of that matters. Filtering directly to `RegistryKey contains "Run"` cut to what did:

```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where RegistryKey contains "Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

Three values under the Run key. Two were legitimate: Edge auto-launch and an OneDrive cleanup entry. The third was the attacker's: **PHTGHealthCloudTray**, running a hidden PowerShell script at every user logon:

```
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"
```

The same three concealment flags seen in Q05. The same HealthCloud staging directory. Consistent operator signature throughout.

The Run key wasn't the only mechanism. A **Startup folder LNK file** — **PHTG HealthCloud.lnk** — was dropped into `C:\Users\vmAdminUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`. Windows executes everything in that folder at logon without requiring any registry entry. Two independent persistence mechanisms, each capable of surviving cleanup of the other.

A **third registry change** operated differently. Filtering to HKLM keys under vmadminusername revealed a write to `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloudSvc`. This wasn't persistence in the classic sense — it was capability. Registering under the EventLog Application key gives tooling the ability to write events to the Windows Application log via the standard Event Log API. The Application log is high-volume and full of legitimate software entries. Defenders focus on the Security log. Writing malicious telemetry into Application log traffic is harder to spot than almost anywhere else.

**To validate the persistence actually fired**, I checked which devices carried the Run key and when. The Run key existed on **both devices** — written to phtg-02 at 09:38:02 and to phtg-01 at 10:12:59. The Run key fires at interactive logon. Counting RemoteInteractive logons on phtg-02 after 09:38:02 within the investigation window returned **2** — the HealthCloudTray startup command executed twice within the window, both on phtg-02, where the key had been written earlier.

---

## Phase 5 — The Beacon Pair: Outbound Communications

With persistence planted, the operator's tooling established its outbound channels.

The masquerade binary **PHTGHealthCloudSvc.exe** was beaconing continuously. Filtering DeviceProcessEvents to that filename with `healthcheck` in the ProcessCommandLine and counting the executions returned **22** within the investigation window — a regular automated loop running at short intervals throughout the session.

That was one channel. Alongside it, two encoded PowerShell beacons fired independently:

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| where ProcessCommandLine has "EncodedCommand" or ProcessCommandLine has "-enc"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

The `-EncodedCommand` flag is PowerShell's base64 execution mechanism — almost always used to obscure what's being run. Decoding both blobs revealed Invoke-WebRequest calls to two distinct endpoints:

1. `https://status.health-cloud.cc/api/checkin` — first beacon at 10:13:43
2. `https://status.health-cloud.cc/api/status` — second beacon at 10:13:56

Both under the same parent domain: **health-cloud.cc**. One channel for pulling tasks, one for reporting status. The network path was confirmed in DeviceNetworkEvents filtered to vmadminusername PowerShell activity, which returned both FQDNs directly in the RemoteUrl field: **updates.health-cloud.cc** and **status.health-cloud.cc**.

Running two parallel channels wasn't accidental. The resilience benefit is direct — if one channel is detected and cut, the operator retains access through the second. The detection benefit is subtler: the second channel acts as a silent fallback that defenders may not know to look for, complicating correlation and response. A defender who finds the healthcheck loop and neutralizes it may believe they've resolved the threat. They haven't.

---

## Phase 6 — Execution Mechanics: How the Tooling Deployed

The operator's deployment loop had a consistent one-second signature.

At 10:12:16, an outbound request fired. One second later at 10:12:17, PHTGHealthCloudSvc.exe executed with `/healthcheck /flag:FLAG-01`. The pattern repeated for every subsequent FLAG task throughout the session. The first step pulled a task or payload from C2 via an outbound request. The second step immediately executed what was retrieved locally — a download-and-execute pattern, automated and repeating.

After the outbound connections succeeded at 10:13:44, the operator ran a plain non-encoded PowerShell script from the Bin staging directory: **`amsi_probe.ps1`**. The name is self-describing. AMSI is the Windows Antimalware Scan Interface — a script named `amsi_probe.ps1` is testing whether AMSI is active or bypassable before deploying further payloads. Pre-execution checks against defensive tooling are standard operator practice.

The operator also used **cmd.exe as an intermediary** on two occasions within the first hour after the anchor logon — once to launch `hc_lineage.ps1` and once to launch `phtg_health_diag_update_FLAG-22.bat`. Filtering to `FileName == "cmd.exe"` (the invocations themselves, not what cmd spawned) revealed both clearly:

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where FileName == "cmd.exe"
| where ProcessCommandLine !has "whoami"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

Inserting cmd.exe between the parent PowerShell and the payload breaks the direct parent-child relationship in the process tree — lineage breaking. Automated detection and manual triage both rely on process lineage to attribute activity. An extra hop obscures that attribution and makes each step harder to chain back to the operator's tooling.

---

## Phase 7 — Doors Held Open: Defender Handling

The operator's approach to Defender was deliberate and layered.

**Permanent exclusions** were written to the registry after persistence landed, silencing Defender against two specific targets:

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where RegistryKey contains "Defender"
| where RegistryKey contains "Exclusion"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

- **Path exclusion:** `C:\ProgramData\PHTG\HealthCloud\Cache` — the script staging directory
- **Process exclusion:** `C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe` — the masquerade binary

**Defender did fire.** Two AntivirusReport events were generated against the **PHTG HealthCloud.lnk** artefact. Both showed `WasExecutingWhileDetected: false` — the file was detected at rest, not while running. Defender reported it but did not block it. The persistence remained in place. Detection and prevention are different outcomes, and in this case Defender delivered only the first.

**The transient exclusion inside `_.ps1`** was the most surgical move. At exactly 10:11:42 — the same timestamp as `_.ps1`'s execution — a Defender exclusion was added for `C:\Users\vmAdminUsername\Documents\PHTG`. The add event was captured in registry telemetry. The delete event was not — MDE doesn't always log RegistryValueDeleted events. The timestamp correlation told the story anyway: the exclusion existed just long enough for the script to execute without Defender scanning it, then disappeared. Transient exclusions leave minimal forensic footprint, and the absence of a delete event in telemetry doesn't mean the cleanup didn't happen.

---

## Phase 8 — Hands on the Vault: Credential Access

At the end of the chain, the operator reached for credentials.

DeviceEvents showed 139 OpenProcessApiCall events targeting **lsass.exe** in the window. The vast majority were baseline — MsMpEng (Defender), WmiPrvSE, SenseIR (MDE sensor), and system-context processes. All legitimate, all excluded. One was not:

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
| where InitiatingProcessFileName !in ("MsMpEng.exe", "WmiPrvSE.exe", "SenseIR.exe")
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**powershell.exe under vmadminusername**, spawned by `task_FLAG-13.ps1`.

Two access attempts fired one second apart with escalating DesiredAccess values. The first request carried **5136** — limited, specific rights, a probe. The second carried **2047999 (0x1FFFFF)** — `PROCESS_ALL_ACCESS`. Every possible right. Including the right to read process memory, where lsass holds cached credentials.

The probe-then-escalate pattern is deliberate tradecraft. The attacker tested what was possible with limited rights first, then immediately committed to full access. One second between them.

Opening a full-access handle isn't dumping yet — it's a prerequisite. The confirmation came from a subsequent query filtering for memory-related ActionTypes under vmadminusername after the handle was opened: **ReadProcessMemoryApiCall** against lsass.exe from powershell.exe at 10:17:35.

The credential dump chain was complete. Three steps, all visible in telemetry:

1. **OpenProcessApiCall** — handle opened against lsass
2. **DesiredAccess 0x1FFFFF** — PROCESS_ALL_ACCESS granted
3. **ReadProcessMemoryApiCall** — lsass memory read confirmed

MITRE T1003.001 (LSASS Memory). Confirmed.

---

## What the Operator Left Behind

By end of session, the operator had built a fully operational presence across two hosts:

- **Scheduled task (PHTG User Baseline Report)** — already cycling on phtg-02 from the prior session, automated lateral movement at 09:48 before manual login
- **PHTGHealthCloudTray Run key** — written to both devices, firing at every interactive logon
- **PHTG HealthCloud.lnk** — Startup folder persistence on phtg-01, detected by Defender but not blocked
- **EventLog source registration** — operator tooling registered in the Windows Application log for blending
- **Defender exclusions** — Cache directory and masquerade binary silenced permanently
- **Transient exclusion** — `_.ps1` execution window protected and cleaned up
- **22 healthcheck beacons** — PHTGHealthCloudSvc.exe running in a continuous loop
- **Two encoded C2 beacon channels** — updates.health-cloud.cc and status.health-cloud.cc operating in parallel
- **Credentials harvested** — lsass memory read confirmed via PROCESS_ALL_ACCESS handle

The operator moved methodically. Everything had a purpose. The persistence mechanisms were redundant by design. The beacon channels were parallel by design. The Defender handling was layered by design. This wasn't opportunistic access — it was a deliberate operator working a plan.

---

## What I Learned

**Brute force is a pattern, not just a count.** Failures before a success looks like brute force. But if the failure IPs don't match the success IP, the failure accounts don't match the success account, and the success logon type is Batch with no RemoteIP — it's not brute force. Always compare across all four dimensions before calling it.

**Persistence validation matters as much as persistence detection.** Finding a Run key is step one. Confirming it fired requires checking every device it was written to and counting interactive logons after the write time. The key was on phtg-02 — not phtg-01 where I found it — and that's where it fired.

**Transient exclusions are the hardest defensive evasion to catch.** The window can be seconds. The delete event may not be logged. The only evidence may be a timestamp correlation between a registry add and a script execution. If you're not querying telemetry in tight time windows around script execution, you'll miss it.

**cmd.exe as an intermediary is lineage breaking, not just execution.** The attacker didn't use cmd.exe because they needed to — they used it to insert a hop in the process tree. That hop is the point. Automated detection that relies on parent-child attribution gets confused by it. Always filter on `FileName == "cmd.exe"` when hunting intermediary usage, not `InitiatingProcessFileName`.

**The credential dump chain requires all three steps.** An OpenProcessApiCall alone could be baseline. PROCESS_ALL_ACCESS alone could be a security tool probing lsass. ReadProcessMemoryApiCall alone without the preceding context could be explained away. All three together, in sequence, one second apart, under a compromised account — that's definitive.

---

## Appendix A — MITRE ATT&CK Mapping

| Technique ID | Technique Name | Evidence |
|---|---|---|
| T1078 | Valid Accounts | vmadminusername credential reuse for re-entry |
| T1053.005 | Scheduled Task | PHTG User Baseline Report cycling on phtg-02, automated lateral movement |
| T1021.001 | Remote Desktop Protocol | Lateral movement from phtg-02 (10.0.0.152) to phtg-01 |
| T1547.001 | Registry Run Keys / Startup Folder | PHTGHealthCloudTray Run key + PHTG HealthCloud.lnk on phtg-01 |
| T1036 | Masquerading | PHTGHealthCloudSvc.exe claiming to be bitsadmin.exe |
| T1564.001 | Hidden Files and Directories | attrib +h +s against Cache and TempCache staging directories |
| T1027 | Obfuscated Files or Information | Base64 EncodedCommand PowerShell beacons |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Permanent Defender exclusions + transient exclusion in _.ps1 |
| T1059.001 | PowerShell | _.ps1, amsi_probe.ps1, HealthCloudTray.ps1, encoded beacons |
| T1112 | Modify Registry | EventLog source registration + Defender exclusions |
| T1071.001 | Application Layer Protocol | Two-channel beacon via health-cloud.cc |
| T1090 | Proxy | Redundant parallel beacon channels for resilience |
| T1003.001 | OS Credential Dumping: LSASS Memory | OpenProcessApiCall → PROCESS_ALL_ACCESS → ReadProcessMemoryApiCall |

---

## Appendix B — Attack Timeline

| Time (UTC) | Event |
|---|---|
| 2025-12-13 09:38:02 | PHTGHealthCloudTray Run key written to azwks-phtg-02 (pre-anchor, prior persistence) |
| 2025-12-13 09:48:00 | Hunt anchor — scheduled task fires automatically on phtg-02 |
| 2025-12-13 09:48:40 | Lateral movement — RemoteInteractive logon to azwks-phtg-01 from 10.0.0.152 |
| 2025-12-13 09:52:00 | Operator RDPs interactively from Uruguay (173.244.55.131) |
| 2025-12-13 10:11:42 | _.ps1 executes — transient Defender exclusion added for Documents\PHTG |
| 2025-12-13 10:12:13 | task_FLAG-01.ps1 begins cycling — download-and-execute loop starts |
| 2025-12-13 10:12:17 | PHTGHealthCloudSvc.exe first healthcheck beacon fires |
| 2025-12-13 10:12:59 | PHTGHealthCloudTray Run key written to azwks-phtg-01 |
| 2025-12-13 10:13:00 | PHTG HealthCloud.lnk dropped to Startup folder |
| 2025-12-13 10:13:43 | First encoded PowerShell beacon — checkin endpoint (updates.health-cloud.cc) |
| 2025-12-13 10:13:56 | Second encoded PowerShell beacon — status endpoint (status.health-cloud.cc) |
| 2025-12-13 10:13:44 | amsi_probe.ps1 executed from Bin directory — AMSI bypass probe |
| 2025-12-13 10:14:30 | Permanent Defender exclusions written — Cache path and SvcExe process |
| 2025-12-13 10:14:37 | lsass OpenProcessApiCall — probe (DesiredAccess 5136) |
| 2025-12-13 10:14:38 | lsass OpenProcessApiCall — PROCESS_ALL_ACCESS (DesiredAccess 2047999) |
| 2025-12-13 10:17:35 | ReadProcessMemoryApiCall against lsass — credential dump confirmed |

---

## Appendix C — KQL Queries Used

**Authentication summary — failures vs successes**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| summarize count() by ActionType, LogonType, RemoteIP, AccountName
| order by ActionType asc
```

**Scheduled task persistence confirmation**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-02"
| where ActionType contains "ScheduledTask"
| project TimeGenerated, ActionType, AdditionalFields
| order by TimeGenerated asc
```

**Lateral movement — RemoteInteractive logons from anchor time**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where AccountName == "vmadminusername"
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public" or isnotempty(RemoteIP)
| project TimeGenerated, AccountName, RemoteIP, DeviceName, LogonType
| order by TimeGenerated asc
```

**Onward movement check — fleet-wide**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where RemoteIP == "10.0.0.105"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, RemoteIP, DeviceName, LogonType
| order by TimeGenerated asc
```

**First operator script — script extension filter**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName in ("azwks-phtg-01", "azwks-phtg-02")
| where AccountName == "vmadminusername"
| where ProcessCommandLine has ".ps1" or ProcessCommandLine has ".bat" or ProcessCommandLine has ".vbs"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
| take 10
```

**Concealment pattern — attrib.exe subdirectory extraction**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName == "attrib.exe"
| extend SubDir = tostring(split(ProcessCommandLine, "\\")[4])
| summarize count() by SubDir
```

**LOLBin masquerade identification**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName != ProcessVersionInfoOriginalFileName
| where FolderPath !startswith "C:\\Windows\\"
| project TimeGenerated, FileName, ProcessVersionInfoOriginalFileName, FolderPath, ProcessVersionInfoCompanyName
| order by TimeGenerated asc
```

**Run key persistence identification**
```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where RegistryKey contains "Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

**Startup folder persistence**
```kql
DeviceFileEvents
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where FolderPath contains "Startup"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**HKLM registry change — EventLog source registration**
```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where DeviceName == "azwks-phtg-01"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE"
| where InitiatingProcessAccountName == "vmadminusername"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

**Persistence validation — Run key on both devices**
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where RegistryValueName == "PHTGHealthCloudTray"
| project TimeGenerated, DeviceName, RegistryValueData
```

**Startup execution count — RemoteInteractive logons on phtg-02**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:38:02Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-02"
| where AccountName == "vmadminusername"
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| count
```

**Healthcheck beacon count**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName == "PHTGHealthCloudSvc.exe"
| where ProcessCommandLine has "healthcheck"
| count
```

**Encoded PowerShell beacons**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| where ProcessCommandLine has "EncodedCommand" or ProcessCommandLine has "-enc"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

**Operator outbound domains**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where InitiatingProcessFileName == "powershell.exe"
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated asc
```

**AMSI probe identification**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T10:13:44Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where ProcessCommandLine has "Bin" or ProcessCommandLine has "HealthCloud\\Bin"
| project InitiatingProcessCommandLine, ProcessCommandLine
```

**cmd.exe lineage break — both invocations**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where FileName == "cmd.exe"
| where ProcessCommandLine !has "whoami"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Defender exclusions — permanent**
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where RegistryKey contains "Defender"
| where RegistryKey contains "Exclusion"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

**Defender detection outcome — LNK artefact**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "AntivirusDetection" or ActionType contains "AntivirusReport"
| where FileName contains "HealthCloud" or FileName contains ".lnk"
| project TimeGenerated, FileName, ActionType, AdditionalFields
| order by TimeGenerated asc
```

**Transient Defender exclusion — timestamp correlation**
```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T10:11:40Z) .. datetime(2025-12-13T10:13:00Z))
| where DeviceName == "azwks-phtg-01"
| where RegistryKey contains "Defender"
| where ActionType in ("RegistryValueSet", "RegistryValueDeleted")
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

**lsass access anomaly**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
| where InitiatingProcessFileName !in ("MsMpEng.exe", "WmiPrvSE.exe", "SenseIR.exe")
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Access right escalation — DesiredAccess values**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T10:14:37Z) .. datetime(2025-12-13T10:14:39Z))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
| where InitiatingProcessAccountName == "vmadminusername"
| project TimeGenerated, AdditionalFields
| order by TimeGenerated asc
```

**Credential dump confirmation**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T10:14:37Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where ActionType contains "Memory" or ActionType contains "Read" or ActionType contains "Dump"
| project TimeGenerated, ActionType, FileName, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

*A huge thank you to Josh Madakor for building The Cyber Range and to Steven Cruz — the Threat Hunt Engineer behind this challenge. The operator tradecraft in this scenario demanded genuine analytical thinking at every step — from challenging the brute force assumption at the start, to validating persistence across two devices, to catching a transient Defender exclusion that existed for only seconds. I came out understanding the difference between detecting something and confirming it, and why mature operators build redundancy into everything they do.*
