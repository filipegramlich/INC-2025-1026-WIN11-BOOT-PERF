# INC-2025-1026-WIN11-BOOT-PERF | Windows 11 Endpoint Performance Investigation
 Investigation of a Windows 11 system experiencing 10+ minute boot times.
 
[![Blue Team](https://img.shields.io/badge/BlueTeam-darkblue)](https://github.com/yourusername)
[![SOC](https://img.shields.io/badge/SOC-Analysis-darkblue)](https://github.com/yourusername)

## Executive Summary

**Objective:** Investigate and resolve severe boot performance degradation on a Windows 11 endpoint.

**Initial State:** Boot time of 10+ minutes (614-720 seconds)

**Approach:** Systematic investigation using native Windows tools, focusing on:
- Malware/unwanted software detection
- System service analysis
- Hardware assessment
- Evidence-based decision making

**Outcome:** Multiple root causes identified, software optimizations applied, hardware upgrade recommended.

## Investigation Methodology

### Phase 1: Initial Reconnaissance

**Objective:** Establish baseline and identify obvious anomalies

```powershell
# Boot time analysis
$event = Get-WinEvent -ProviderName Microsoft-Windows-Diagnostics-Performance | 
         Where-Object {$_.Id -eq 100} | Select-Object -First 1

# Result: 614,967 ms (~10 minutes 15 seconds)
```

**Baseline established:** 10+ minute boot time vs expected 30-60 seconds

### Phase 2: Persistence Enumeration

**Objective:** Identify auto-starting programs and scheduled tasks

<details>
<summary>📌 Commands Used</summary>

```powershell
# Registry Run Keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Scheduled Tasks
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | 
    Select-Object TaskName, TaskPath, State
```
</details>

**Finding #1: Warsaw Technology (GAS Tecnologia)**
- Banking security software (legitimate but aggressive)
- High CPU usage during boot
- Known performance impact

**Action:** Removed

### Phase 3: Process & Service Analysis

**Objective:** Identify resource-consuming processes

```powershell
Get-Process | Sort-Object CPU -Descending | 
    Select-Object -First 15 ProcessName, CPU, PM
```

**Finding #2: TiWorker.exe (Windows Update)**
- Consuming 35+ CPU units
- Service timeouts during boot
- Update failures in event logs

**Action:** Reset Windows Update cache, configured manual startup

### Phase 4: Network Connections Review

**Objective:** Identify suspicious network activity

```powershell
Get-NetTCPConnection -State Established | 
    Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess
```

**Findings:**
- ✅ AnyDesk: Legitimate remote administration (verified)
- ✅ OneDrive: Microsoft Azure endpoints (expected)
- ✅ No suspicious connections identified

### Phase 5: Event Log Analysis

**Objective:** Correlate system events with boot issues

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='System'; 
    Level=1,2; 
    StartTime=(Get-Date).AddHours(-24)
} -MaxEvents 10
```

**Key Events:**
- Windows Update failures (0x80240016)
- Google Update service timeout (30s)
- Storage Service suspended during boot
- Previous unexpected shutdown (system crash)

### Phase 6: Hardware Assessment

**Objective:** Rule out hardware limitations

```powershell
Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus
Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory
```

**Finding #3: Mechanical HDD (ROOT CAUSE)**
- WDC 1TB HDD (not SSD)
- Sequential read speed: ~100-150 MB/s
- Windows 11 optimized for SSD random I/O
- **This explains the persistent boot delays**

  ## 🎯 Findings

### Root Causes Identified

| ID | Root Cause | Operational Impact | Severity |
|----|------------|--------------------|----------|
| F-01 | Mechanical hard disk drive (HDD) | I/O latency >100 ms; boot time >10 min | **Critical** |
| F-02 | `wuauserv` service loop | Cascading timeouts; risk of system instability | **High** |
| F-03 | Warsaw Technology (GAS) | CPU overhead (~90 units) during boot | **Medium** |


### MITRE ATT&CK Mapping

Investigation techniques mapped to MITRE framework:

- **T1082** - System Information Discovery
- **T1057** - Process Discovery
- **T1049** - System Network Connections Discovery
- **T1083** - File and Directory Discovery
- **T1547.001** - Boot/Logon Autostart Execution: Registry Run Keys
- **T1543.003** - Create or Modify System Process: Windows Service

---

## 🛠️ Remediation

### Immediate Actions (Software)

#### 1. Removed Warsaw Technology
```powershell
# Uninstalled via Control Panel
# Verified removal in services and startup
```

#### 2. Windows Update Optimization
```powershell
# Reset Windows Update cache
Stop-Service wuauserv, bits, cryptsvc -Force
Rename-Item C:\Windows\SoftwareDistribution C:\Windows\SoftwareDistribution.old
Start-Service wuauserv, bits, cryptsvc

# Configure manual startup
Set-Service wuauserv -StartupType Manual
Set-Service TrustedInstaller -StartupType Manual
```

**Rationale:** Balance security (updates still available) with performance

#### 3. Disabled Resource-Intensive Services
```powershell
# Windows Search (indexing)
Set-Service WSearch -StartupType Disabled

# SysMain (Superfetch - ineffective on HDD)
Set-Service SysMain -StartupType Disabled

# Xbox services (unused)
Set-Service XblAuthManager -StartupType Disabled
Set-Service XblGameSave -StartupType Disabled
Set-Service XboxGipSvc -StartupType Disabled
Set-Service XboxNetApiSvc -StartupType Disabled

# Telemetry
Set-Service DiagTrack -StartupType Disabled
```

#### 4. Visual Effects Optimization
```powershell
# Set to "Adjust for best performance"
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
Set-ItemProperty -Path $path -Name "VisualFXSetting" -Value 2 -Type DWord
```

