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
Evidence Analysis
1. Microsoft Word → PowerShell

Microsoft Word launching PowerShell is unusual in this scenario because the user normally uses Word for document-related work.

This is an indicator that requires investigation.

It does not, by itself, prove that the workstation was compromised.

2. PowerShell with ExecutionPolicy Bypass

PowerShell was executed using:

-ExecutionPolicy Bypass

This allows the PowerShell process to run without normal execution-policy restrictions.

Execution Policy Bypass can be used legitimately by administrators and applications, so it is not proof of malicious activity by itself.

In this scenario, however, it becomes more significant because it occurred immediately after Word launched PowerShell.

3. whoami

The command:

whoami

can be used to identify the account under which a process is running.

This can be useful during system or account discovery.

4. net user

The command:

net user

is commonly used to view or manage local user accounts.

The command by itself does not prove that a new account was created.

Account creation would require additional evidence, such as an account-creation event or a command specifically creating an account.

5. PowerShell → curl → external download

PowerShell launched curl, which downloaded:

update.exe

from an external IP address and saved it to:

C:\ProgramData\update.exe

This is one of the strongest indicators in the investigation because an executable was downloaded from an external source shortly after the suspicious process chain began.

However, the available evidence does not establish that update.exe is definitely malicious.

Further analysis would be required.

Key Indicators

The main indicators identified were:

Microsoft Word launching PowerShell
PowerShell using ExecutionPolicy Bypass
Discovery commands executed through the process chain
curl downloading an executable
External IP address used as the download source
Executable saved in C:\ProgramData

---
What Can Be Confirmed

Based on the available evidence, we can confirm that:

Microsoft Word launched PowerShell.
PowerShell executed with ExecutionPolicy Bypass.
PowerShell launched Command Prompt.
whoami and net user were executed.
PowerShell launched curl.
curl downloaded an executable from an external IP address.
The executable was saved to C:\ProgramData\update.exe.
What Cannot Yet Be Confirmed

The available evidence does not establish:

Who initiated the activity.
Whether the user intentionally performed the actions.
Whether update.exe is malicious.
Whether the workstation was fully compromised.
Whether persistence was established.
Whether lateral movement occurred.
Whether data was exfiltrated.
Whether the external IP address is malicious.

Additional evidence would be required before making these conclusions.

Recommended Investigation

Further investigation should include:

Reviewing Windows Security logs.
Reviewing PowerShell logs.
Examining process creation events.
Investigating the downloaded update.exe file.
Checking file hashes against trusted threat-intelligence sources.
Reviewing network and firewall logs.
Checking scheduled tasks and other persistence mechanisms.
Reviewing additional endpoint activity around the same timeframe.
Determining whether similar activity occurred on other systems.
Recommended Containment

If the investigation confirmed that the activity was unauthorized, recommended containment would include:

Isolate the affected workstation from the network.
Preserve relevant evidence before destructive cleanup.
Investigate and quarantine the downloaded executable where appropriate.
Review the affected user's credentials and sessions.
Search for the same indicators across other endpoints.
Block confirmed malicious infrastructure after evidence is preserved.
Investigation Conclusion

The activity observed on the workstation is suspicious and warrants further investigation.

The combination of Word spawning PowerShell, PowerShell using ExecutionPolicy Bypass, discovery commands, and an external executable download creates a strong investigative lead.

However, the available evidence alone is not sufficient to conclude that the user was responsible for the activity or that the downloaded executable was malicious.

The investigation demonstrates the importance of correlating multiple sources of endpoint evidence rather than treating a single suspicious event as proof of compromise.

Skills Demonstrated

This investigation demonstrates practical experience with:

Windows endpoint investigation
Process-tree analysis
PowerShell investigation
Windows command-line activity
Authentication and account investigation
Network activity analysis
Incident timeline construction
Evidence-based incident assessment
Incident containment planning

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
