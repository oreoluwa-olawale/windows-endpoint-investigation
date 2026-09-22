# Windows Endpoint Investigation: Suspicious PowerShell Activity

## Project Overview

This project documents a simulated Windows endpoint security investigation conducted as part of my practical cybersecurity training.

The investigation focuses on suspicious PowerShell execution originating from Microsoft Word, followed by command execution and an external file download.

The objective was to analyze the available evidence, establish a timeline, identify suspicious activity, and determine what could and could not be confirmed from the available evidence.

> **Note:** This is a simulated training investigation. It does not represent a real-world company incident.

---

## Scenario

A user on an HR workstation opened Microsoft Word.

Shortly afterward, a series of processes were observed:

- Microsoft Word launched PowerShell.
- PowerShell executed a script using `ExecutionPolicy Bypass`.
- PowerShell launched Command Prompt.
- Command Prompt executed `whoami`.
- Command Prompt executed `net user`.
- PowerShell used `curl` to download an executable from an external IP address.
- The downloaded file was saved to `C:\ProgramData\update.exe`.

IT confirmed that the user normally works with Microsoft Word but does not normally use PowerShell scripts or `curl` to download files.

---

## Investigation Timeline

| Time | Event |
|---|---|
| 09:14:21 | `WINWORD.EXE` started |
| 09:14:23 | `WINWORD.EXE` launched `POWERSHELL.EXE` |
| 09:14:25 | PowerShell launched `CMD.EXE`, which executed `whoami` |
| 09:14:27 | `CMD.EXE` executed `net user` |
| 09:14:30 | PowerShell launched `CURL.EXE` |
| 09:14:30 | `curl` downloaded `update.exe` from an external IP |
| 09:14:30 | File saved to `C:\ProgramData\update.exe` |

---

## Process Tree

```text
WINWORD.EXE
    |
    └── POWERSHELL.EXE
          |
          ├── CMD.EXE
          |     |
          |     ├── whoami
          |     |
          |     └── net user
          |
          └── CURL.EXE
                |
                └── update.exe
