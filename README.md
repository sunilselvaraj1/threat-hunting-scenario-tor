<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/sunilselvaraj1/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
// Tor download
DeviceFileEvents
| where DeviceName == "sunil-th-vm"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-29T08:44:17.538246Z)
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/76c45284-612f-459f-a219-62876916632d)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.8.exe". Based on the logs returned, at `2025-03-29T08:47:07.9776885Z`, an employee on the "sunil-th-vm" device ran the file `tor-browser-windows-x86_64-portable-14.0.8.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

// Tor install
DeviceProcessEvents
| where DeviceName == "sunil-th-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.8.exe"
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/23821752-fe7a-4390-84a1-fec7b2663166)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-03-29T08:47:49.5348136Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
// Tor process creation
DeviceProcessEvents
| where DeviceName == "sunil-th-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/de62ad01-a5aa-427a-88cb-6449740a882b)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-29T08:48:04.874704Z`, an employee on the "sunil-th-vm" device successfully established a connection to the remote IP address `77.174.62.158` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `C:\Users\insiDerthReAt5\Downloads\tor-browser-windows-x86_64-portable-14.0.8.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
// tor usage
DeviceNetworkEvents
| where DeviceName == "sunil-th-vm"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/9c51dfbd-7a00-4826-8f52-964c72ade82a)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-29T08:44:17.538246Z`
- **Event:** The user "insiderthreat5" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.8.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\insiDerthReAt5\Downloads\tor-browser-windows-x86_64-portable-14.0.8.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-29T08:47:07.9776885Z`
- **Event:** The user "insiderthreat5" executed the file `tor-browser-windows-x86_64-portable-14.0.8.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.8.exe /S`
- **File Path:** `C:\Users\insiDerthReAt5\Downloads\tor-browser-windows-x86_64-portable-14.0.8.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-29T08:47:54.5067405Z`
- **Event:** User "insiderthreat5" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\insiDerthReAt5\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-29T08:48:04.2793628Z`
- **Event:** A network connection to IP `77.174.62.158` on port `9001` by user "insiderthreat5" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\insiDerthReAt5\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-29T08:48:08.6579185Z` - Connected to `194.164.169.85` on port `443`.
  - `2025-03-29T08:48:19.3984126Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "insiderthreat5" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-29T08:56:12.9578254Z`
- **Event:** The user "insiderthreat5" created a file named `Shopping List.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\insiDerthReAt5\Desktop\Shopping List.txt`

---

## Summary

The user "insiderthreat5" on the "sunil-th-vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `Shopping List.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "Shopping List.txt" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `sunil-th-vm` by the user `insiderthreat5`. The device was isolated, and the user's direct manager was notified.

---
