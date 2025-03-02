<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MalachiElisnord/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, they then did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-03-01T23:23:17.63Z`. These events began at `2025-03-01T22:57:45.87Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "win10-malachi"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-01T22:57:45.8746135Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/73c407ea-898d-4916-9627-a5ee03bd9d78)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-03-01T22:59:05.7439809Z`, an employee on the "win10-malachi" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "win10-malachi"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/a15a0eb9-a41a-4c64-9585-33115dd9030d)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-03-01T22:59:48.329502Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "win10-malachi"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine 
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/e500558b-26aa-4c5c-b085-e3b2c465b347)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-01T23:00:04.2079815Z`, an employee on the "win10-malachi" device successfully established a connection to the remote IP address `217.160.98.239` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were also a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "win10-malachi"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/359d0742-fe51-4aaa-b4e2-796810dbdab4)


---

## Chronological Event Timeline 

#### **1. Download of Tor Browser Installer**  
- **Timestamp:** 2025-03-01T22:57:45Z  
- **Action:** The user "labuser" downloaded the Tor Browser installer file: `tor-browser-windows-x86_64-portable-14.0.6.exe`.
- **Location:** `C:\Users\labuser\Downloads\`
- **Hash:** 8396d2cd3859189ac38629ac7d71128f6596b5cc71e089...

#### **2. Execution of Tor Browser Installer**  
- **Timestamp:** 2025-03-01T22:59:05.74Z  
- **Action:** The installer was executed, initiating a silent installation.
- **Location:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`
- **Command Used:** `tor-browser-windows-x86_64-portable-14.0.6.exe --silent`

#### **3. Execution of Tor Browser and Associated Processes**  
- **Timestamp:** 2025-03-01T22:59:48.32Z  
- **Action:** The user launched the Tor Browser, initiating `tor.exe` and multiple instances of `firefox.exe`.
- **Location:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

#### **4. Initial Network Connections Over Encrypted Channels**  
- **Timestamp:** 2025-03-01T22:59:59.30Z  
- **Action:** Multiple encrypted connections were made over port 443.

#### **5. Additional Network Connection Related to Tor**  
- **Timestamp:** 2025-03-01T23:00:04.20Z  
- **Action:** The Tor executable established a connection to an external IP.
- **Remote IP:** 217.160.98.239
- **Remote Port:** 9001

#### **6. Creation of Tor-Related Files**  
- **Timestamp:** 2025-03-01T23:23:17Z  
- **Action:** Multiple Tor-related files were copied to the desktop, including `tor-shopping-list.txt`.
- **Location:** `C:\Users\labuser\Desktop\Tor Browser\`

---

## Summary

The user "labuser" on device "win10-malachi" downloaded and executed the Tor Browser installer on March 1, 2025. A silent installation was performed, and shortly after, the user launched Tor, spawning tor.exe and several instances of firefox.exe. The system first established a connection to a known Tor network IP on port 9001, followed by additional encrypted connections over port 443. Later, multiple Tor-related files were created, including tor-shopping-list.txt, indicating potential further usage of the browser.

---

## Response Taken

TOR usage was confirmed on endpoint **win10-malachi** by the user **labuser**. The device was isolated and the user's direct manager was notified.

---
