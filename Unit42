Overview
This project is inspired by Palo Alto's Unit42 research on an UltraVNC campaign where attackers used a backdoored version of UltraVNC to maintain access to compromised systems. This lab focuses on the initial access stage of the campaign and guides participants through analyzing Sysmon logs to identify malicious activities on a Windows system.

Objective
The goal of this exercise is to investigate various Sysmon Event IDs to uncover the actions taken by a malicious actor who used a backdoored UltraVNC variant. Below is a detailed breakdown of the findings from the analysis.

Findings
1. Event Logs with Event ID 11
Event ID 11 logs represent file creation events. Filtering the logs for this Event ID reveals:
Total Logs Found: 56


2. Malicious Process Identified (Event ID 1)
Event ID 1 logs record details whenever a new process is created. This provides valuable insights into which programs were executed, allowing us to spot malicious activity. The analysis uncovered a malicious process with the following details:

Malicious Executable:
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
File Hashes:
SHA1: 18A24AA0AC052D31FC5B56F5C0187041174FFC61
MD5: 32F35B78A3DC5949CE3C99F2981DEF6B
SHA256: 0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3
IMPHASH: 36ACA8EDDDB161C588FCF5AFDC1AD9FA
MITRE ATT&CK Technique:
ID: T1204
Name: User Execution
Execution Timestamp:
2024-02-14 03:41:56.538


3. Malware Distribution Source (Event ID 22)
Event ID 22 logs capture DNS queries, revealing how the malware may communicate or where it may be sourced from. The analysis found that the malware was distributed through:

Cloud Drive: Dropbox
4. Timestamp Modification (Defense Evasion)
One defense evasion technique employed by the malware involved changing the timestamps of the files it created. The timestamp for a particular PDF file was altered to:

Modified Timestamp:
2024-01-14 08:10:06
5. Dropped Files on Disk
The malware dropped several files as part of its operation. One of these was a batch script file called once.cmd, which was found at the following location:

File Path:
C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd
6. Dummy Domain Connection Attempt
As part of its operation, the malware attempted to connect to a dummy domain, likely to check internet connectivity:

Domain Name:
www.example.com
7. IP Address Connection Attempt
The malicious process also tried to reach out to the following IP address during its execution:

IP Address:
93.184.216.34
8. Process Termination (Event ID 5)
After successfully infecting the system with a backdoored version of UltraVNC, the malicious process terminated itself:

Termination Timestamp:
2024-02-14 03:41:58
Conclusion
This Sysmon log analysis uncovered critical details about how a backdoored UltraVNC version was introduced to a system. By investigating Event IDs 1, 11, 22, and others, we could trace the execution of malicious processes, identify the files dropped on the disk, and reveal the malware’s communication attempts. The ability to track these activities in Sysmon logs is invaluable for analysts in detecting and responding to malicious campaigns effectively.

