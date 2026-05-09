# threat-hunting-scenario-tor

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/960hersi/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any files containing “tor” at first and narrowed down the endpoint “saeedtest”. This user downloaded and launched the tor browser and created a file called “tor-shopping-list.txt”. These events were found using the query below and started on May 7, 2026 12:42:37 AM .

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "saeedtest"
| where InitiatingProcessAccountName == "saeed"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1633" height="138" alt="Tor browser install" src="https://github.com/user-attachments/assets/5f5c8389-13ac-4db0-a825-12a018e7eb9d" />
<img width="1169" height="592" alt="tor downloads1" src="https://github.com/user-attachments/assets/241e3885-dd97-41dc-9280-017f89d13367" />


---

### 2. Searched the `DeviceProcessEvents` Table

I searched device process events for any logs relating to the string "tor-browser-windows-x86_64-portable-15.0.11.exe" and an employee using device “saeedtest” silently installed this process on May 7, 2026 12:42:26 AM. This was found using the query below.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "saeedtest"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.11.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1420" height="586" alt="Tor process" src="https://github.com/user-attachments/assets/85f0a2d4-99f1-43fb-a959-599d799210b1" />
<img width="1633" height="138" alt="Tor browser install" src="https://github.com/user-attachments/assets/c6bc2fd1-a9eb-4df0-8b8d-ec62459c2f6f" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

After confirming the user has installed tor browser, I searched logs in Device process events table where the user first launched tor on May 7, 2026 12:42:48 AM . There was also another log of tor.exe being launched as well. This was found using query below

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "saeedtest"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1420" height="586" alt="Tor process" src="https://github.com/user-attachments/assets/8193902d-90c0-489f-b7f3-36d554d1ae42" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

On May 7, 2026 at 12:43 AM, Firefox from the Tor Browser folder on the device saeedtest successfully made a network connection using port 9150, which is commonly used by the Tor Browser SOCKS proxy. The connection was started by the user account saeed. It was found using ports tor normally but temporarily uses like ports like 51078 as well as 443. This was found with the query below.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "saeedtest"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe", "tor-browser.exe")
| where RemotePort in ("9001", "9002", "9004", "9030", "9050", "9051", "9150", "9151", "80", "443", "51078")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1693" height="357" alt="tor-net" src="https://github.com/user-attachments/assets/9fb3cb3c-da85-47a2-ab9a-2a8a6f4257b6" />


---

## Chronological Event Timeline 

Investigation Scope
This investigation focused exclusively on Tor Browser-related activity associated with device saeedtest and user account saeed. The hunt analyzed file, process, and network telemetry from Microsoft Defender XDR tables including DeviceFileEvents, DeviceProcessEvents, and DeviceNetworkEvents.

### 1. File Download - TOR Installer

12:40:21 AM — Tor Browser Installer Renamed
A file rename event was recorded for the Tor Browser installer:
File: tor-browser-windows-x86_64-portable-15.0.11.exe
Location: C:\Users\saeed\Downloads\
This indicates the Tor Browser installer was present in the user's Downloads directory.
12:40:26 AM — Tor Browser Installer Downloaded
A file creation event confirmed the Tor Browser installer was downloaded to the endpoint.
Details
File: tor-browser-windows-x86_64-portable-15.0.11.exe
Path: C:\Users\saeed\Downloads\
SHA256:
 3ae94669801d4c1370066c2322eb3bd58a4e3cd063dab6670ea3eecf286145e7
User: saeed
This marks the initial confirmed Tor Browser download activity on the endpoint.


### 2. Process Execution - TOR Browser Installation

12:42:26 AM — Silent Installation of Tor Browser
Process telemetry showed execution of the Tor Browser installer using silent installation arguments.
Process Command Line
tor-browser-windows-x86_64-portable-15.0.11.exe /S
Observed Activity
Device: saeedtest
User: saeed
Installation Type: Silent install (/S)
This confirms Tor Browser was installed without interactive prompts.


### 3. Process Execution - TOR Browser Launch

12:42:37 AM — Tor Browser Files Created
Multiple Tor Browser-related files were created during installation.
Files Observed
tor.txt
Torbutton.txt
Tor-Launcher.txt
Location
C:\Users\saeed\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\
These file creation events confirm deployment of the Tor Browser application directory.

12:42:38 AM — tor.exe Created
The Tor executable was written to disk.
Details
File: tor.exe
Location:
 C:\Users\saeed\Desktop\Tor Browser\Browser\TorBrowser\Tor\
SHA256:
 a028d058c4d49cf0df10fe6069e4c8fe177d8996414550c6f10c1a97ee24a620
This confirms the Tor network client component was successfully installed.

12:42:42 AM — Desktop Shortcut Created
A desktop shortcut for Tor Browser was created.
Details
File: Tor Browser.lnk
Location:
 C:\Users\saeed\Desktop\Tor Browser\
This indicates the installation completed successfully and the application became accessible to the user.

12:42:48 AM — Initial Tor Browser Execution
Process telemetry confirmed Tor Browser execution activity.
Observed Processes
tor.exe
firefox.exe
tor-browser.exe
This marks the first observed launch of the Tor Browser application after installation.

### 4. Additional - TOR Browser Activity

12:42:49 AM — Browser Storage Database Created
Tor Browser profile storage files were generated.
File
storage.sqlite
Location
C:\Users\saeed\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\
This indicates the browser profile initialized successfully after execution.

12:42:52 AM — Synchronization Database Created
Additional Tor Browser profile artifacts were generated.
File
storage-sync-v2.sqlite
Location
C:\Users\saeed\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\
This further confirms active use of the Tor Browser profile.

### 5. Network Connection - TOR Network

12:43:19 AM — Tor Network Connection Established
Network telemetry confirmed outbound Tor-related communications.
Details
Device: saeedtest
User: saeed
Process: firefox.exe
Process Path:
 C:\Users\saeed\Desktop\Tor Browser\Browser\firefox.exe
Action: ConnectionSuccess
Remote Port: 9150
Port 9150 is commonly associated with the Tor Browser SOCKS proxy service.
Additional observed Tor-related network ports included:
443
51078
This confirms successful network activity originating from the Tor Browser environment.





### 6. File Creation - TOR Shopping List

12:45:40 AM — Tor Shopping List File Created
User activity indicated creation and access of a Tor-related text document.
Observed Files
tor-shopping-list.txt
tor-shopping-list.lnk
Locations
C:\Users\saeed\Desktop\
C:\Users\saeed\AppData\Roaming\Microsoft\Windows\Recent\
The .lnk artifact indicates the file was opened or accessed by the user.

12:46:01 AM — Tor Shopping List Modified
The previously created text file was modified.
Details
File: tor-shopping-list.txt
Location:
 C:\Users\saeed\Desktop\
SHA256:
 a03ad8475603e992b6855b216d2c65e876e81bada093578e2ceb0e4d640e733f
This indicates continued user interaction with the file after Tor Browser installation and execution.


---

## Summary

The investigation confirmed the following sequence of Tor-related activity on device saeedtest by user saeed:
Tor Browser installer was downloaded to the endpoint.
Tor Browser was silently installed using /S installation arguments.
Tor Browser application files and executables were deployed.
The user launched Tor Browser shortly after installation.
Tor Browser initialized browser profile and storage artifacts.
Successful Tor-related network communications were observed, including traffic over port 9150.
The user created and modified a file named tor-shopping-list.txt following Tor Browser usage.
The telemetry collectively confirms download, installation, execution, and active usage of the Tor Browser environment on the investigated endpoint.


---

## Response Taken

TOR usage was confirmed on the endpoint “saeedtest”. The device was isolated and the user's “saeed” direct manager was notified.

---
