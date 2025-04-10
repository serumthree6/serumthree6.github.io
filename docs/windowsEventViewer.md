---
layout: default
title: Windows Event Viewer
---
[Back to Main Page](index.html)
# Windows Event Viewer

In this project, I analyze Windows Event Viewer logs to detect suspicious activity and identify potential security threats. By examining log files from different directories, I uncover malicious behavior such as DLL hijacking, process injection, LSASS dumping, and unusual parent-child relationships between processes.

Each analysis involves filtering event logs for specific Event IDs, correlating process behavior, and identifying anomalies using known attack techniques.

## Key Features:
- **Windows Event Analysis** – Examining Windows Event Viewer logs for security threats
- **Event ID Analysis** – Filtering and analyzing specific Event IDs for suspicious activity
- **Process Investigation** – Analyzing process creation and behavior patterns
- **Security Threat Detection** – Identifying potential security threats through log analysis
- **Hands-On Investigation** – Conducting detailed forensic analysis of Windows logs
- **Threat Hunting** – Using Windows Event Viewer to detect and analyze security threats

---

## **Analysis 1: Detecting DLL Hijacking**

**Question:** By examining the logs located in `C:\Logs\DLLHijack`, determine the process responsible for executing a DLL hijacking attack.

**Answer:** `Dism.exe`

### **Investigation Approach:**
- I examined the logs in `C:\Logs\DLLHijack` and filtered for **Event ID 7** and `false` value for `Signed` attribute using XML Query. I found that `DismCore.dll` was not digitally signed (`Signed: false`).
- A missing digital signature indicates the file's integrity cannot be verified, making it a prime target for DLL hijacking.
- Since `Dism.exe` loaded the unsigned DLL, it was the process responsible for executing the DLL hijacking attack.

![Analysis 1:](images/winEventViewer/winEventViewer_1.png)
![Analysis 1_2:](images/winEventViewer/winEventViewer_1_2.png)
---

## **Analysis 2: Detecting Unmanaged PowerShell Execution**

**Question:** By examining the logs located in `C:\Logs\PowershellExec`, determine the process that executed unmanaged PowerShell code.

**Answer:** `Calculator.exe`

### **Investigation Approach:**
- I opened the `PowershellExec` log file in Event Viewer and filtered for **Event ID 7** and `clr.dll`, `clrjit.dll` values related to OriginalFileName attribute.
- I looked for the presence of `clr.dll` and `clrjit.dll`, which indicate unmanaged PowerShell execution.
- These DLLs are part of the .NET runtime, and their unexpected presence in `Calculator.exe` suggests the execution of unmanaged PowerShell code.

![Analysis 2:](images/winEventViewer/winEventViewer_2.png)
![Analysis 2_2:](images/winEventViewer/winEventViewer_2_2.png)
---

## **Analysis 3: Detecting Process Injection**

**Question:** By examining the logs in `C:\Logs\PowershellExec`, determine the process that injected into the process that executed unmanaged PowerShell code.

**Answer:** `rundll32.exe`

### **Investigation Approach:**
- I filtered for **Event ID 8** in the `PowershellExec` logs.
- I specifically searched for the `CreateRemoteThread` API call, which is commonly used in process injection attacks.
- The logs indicated that `rundll32.exe` injected code into `Calculator.exe`, confirming its role in the attack.

![Analysis 3:](images/winEventViewer/winEventViewer_3.png)
---

## **Analysis 4: Detecting LSASS Dumping**

**Question:** By examining the logs in `C:\Logs\Dump`, determine the process that performed an LSASS dump.

**Answer:** `ProcessHacker.exe`

### **Investigation Approach:**
- I filtered the logs for **Event ID 10**, which tracks suspicious process access.
- I focused on logs where the **TargetImage** was `C:\Windows\System32\lsass.exe`.
- The logs showed that `ProcessHacker.exe` accessed LSASS with an **access mask of 0x1400**, indicating an attempt to dump memory.

![Analysis 4:](images/winEventViewer/winEventViewer_4.png)
---

## **Analysis 5: Detecting Post-LSASS Dump Login Attempts**

**Question:** By examining the logs in `C:\Logs\Dump`, determine if an ill-intended login took place after the LSASS dump.

**Answer:** `No`

### **Investigation Approach:**
- I searched for **Event ID 4624**, which logs successful logins.
- I focused on **Logon Types 2 (Interactive) and 10 (RemoteInteractive)**.
- By correlating login events with the timestamp of the LSASS dump, I found no evidence of unauthorized logins after the dump.

![Analysis 5:](images/winEventViewer/winEventViewer_5.png)
---

## **Analysis 6: Detecting Unusual Parent-Child Process Relationships**

**Question:** By examining the logs in `C:\Logs\StrangePPID`, determine a process that was used to temporarily execute code based on a strange parent-child relationship.

**Answer:** `WerFault.exe`

### **Investigation Approach:**
- I filtered for **Event ID 1**, which logs process creation events.
- The logs showed that `WerFault.exe`, typically used for Windows error reporting, unexpectedly launched `cmd.exe`.
- This behavior suggests that `WerFault.exe` was abused to execute malicious code in an attempt to bypass security controls.

![Analysis 6:](images/winEventViewer/winEventViewer_6.png)
---

Through these investigations, I leveraged Windows Event Viewer logs to detect security threats and analyze adversarial techniques. By understanding process execution, event correlation, and attacker behavior, I was able to uncover key indicators of compromise (IOCs) and gain insights into potential threats

---