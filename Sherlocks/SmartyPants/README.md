# HTB Sherlock: SmartyPants

**Category:** DFIR — Windows Event Log Forensics  
**Difficulty:** Beginner  
**Tools:** Kali Linux, python-evtx (custom wrapper), grep, sed, Python

## Scenario

Forela's CTO, Dutch, keeps critical files on a separate Windows machine, isolated from the frequently-breached domain environment. On 24 January 2025, an intruder accessed this fileserver via RDP, staged utilities, exfiltrated confidential files, destroyed the originals, and then demanded payment under threat of leaking the stolen data. SmartScreen Debug logging had been enabled machine-wide days earlier following a security research recommendation — this proved to be the single most valuable log source for the investigation.

## Tooling Setup

`python-evtx` 0.8.1 ships with a packaging bug where the `evtx_dump` entry-point script fails with `ModuleNotFoundError: No module named 'scripts'`. Worked around it with a small wrapper calling the library directly:

```python
import sys
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

with Evtx(sys.argv[1]) as evtx_log:
    for record_xml, record in evtx_file_xml_view(evtx_log.get_file_header()):
        print(record_xml)
```

Used as `python3 dump_evtx.py <file.evtx> > output.xml` throughout.

---

## Task 1 — RDP Login Timestamp

**Command:**
```bash
python3 dump_evtx.py "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx" > rdp_conn.xml
grep -n '1149' rdp_conn.xml
sed -n '385,410p' rdp_conn.xml
```

**Breakdown:**
Event ID 1149 in the RemoteConnectionManager/Operational channel logs the moment an RDP network connection is accepted, prior to full session establishment. The record includes `Param1` (account name used) and `Param3` (source address).

**Result:**
```
TimeCreated SystemTime="2025-01-24 10:15:14.456013+00:00"
Param1: Dutch
Param3: 0:0:fe80::d18c:695%1989170785
```

**Answer:** `2025-01-24 10:15:14`

![Task 1 and 2 proof](screenshots/Task_1_and_2.png)

---

## Task 2 — First Tool Downloaded & Installed

**Command:**
```bash
python3 dump_evtx.py "Microsoft-Windows-SmartScreen%4Debug.evtx" > smartscreen.xml
grep -n "applicationLookup" smartscreen.xml
```

**Breakdown:**
SmartScreen logs an `applicationLookup` scenario event each time a genuinely new file is downloaded and checked against Microsoft's reputation service — distinct from `onAllowedZoneCheck`, which fires for files that already exist locally and are simply being opened. Filtering for `applicationLookup` isolates true downloads only, in the order they occurred.

Parsed all `TimeCreated`/`path` pairs from the file and sorted chronologically to remove any ambiguity from non-linear EVTX chunk ordering:

```python
import re
with open('smartscreen.xml') as f:
    content = f.read()
events = content.split('<Event xmlns=')
records = []
for e in events[1:]:
    time_match = re.search(r'TimeCreated SystemTime="([^"]+)"', e)
    path_match = re.search(r'"path":"([^"]+)"', e)
    if time_match and path_match:
        records.append((time_match.group(1), path_match.group(1)))
records.sort()
for ts, path in records:
    print(ts, "|", path)
```

**Result:**
```
2025-01-24 10:17:14.017439+00:00 | C:\Users\Dutch\Downloads\winrar-x64-701.exe
2025-01-24 10:17:27.418650+00:00 | C:\Program Files\WinRAR\WinRAR.exe
```

The download-check event and the subsequent installed-executable event, ~13 seconds apart, confirm the download-then-install sequence.

**Answer:** `WinRAR`

![Answer to task 2 proof](screenshots/Answer_to_task_2.png)

---

## Task 3 — Portable File-Search Tool Path

**Breakdown:**
Same sorted timeline; the next `applicationLookup` after WinRAR points to `Everything.exe`, a well-known instant file-search utility by voidtools. No secondary install path appears anywhere else in the log — confirming it ran portable, directly from the Downloads folder.

**Command:**
```bash
grep -B3 -A3 "Everything.exe" smartscreen.xml | grep -E "path|TimeCreated"
```

**Result:**
```
C:\Users\Dutch\Downloads\Everything.exe
```

**Answer:** `C:\Users\Dutch\Downloads\Everything.exe`

![Task 3 and 4 proof](screenshots/Task_3_and_4.png)

---

## Task 4 — Execution Time of Everything.exe

**Result (from sorted timeline):**
```
2025-01-24 10:17:33.561323+00:00 | C:\Users\Dutch\Downloads\Everything.exe
```

**Answer:** `2025-01-24 10:17:33`

![Answer to task 4 proof](screenshots/Answer_to_task_4.png)

---

## Task 5 & 6 — Documents Breached

**Breakdown:**
Roughly 90 seconds after Everything.exe finished its lookup, two PDFs inside Dutch's board-of-directors document folder appear in SmartScreen's `isFileSupported` events — evidence they were opened. Their order in the sorted timeline gives the sequence of compromise.

**Result:**
```
2025-01-24 10:19:00.601812+00:00 | C:\Users\Dutch\Documents\2025- Board of directors Documents\Ministry Of Defense Audit.pdf
2025-01-24 10:19:19.294706+00:00 | C:\Users\Dutch\Documents\2025- Board of directors Documents\2025-BUDGET-ALLOCATION-CONFIDENTIAL.pdf
```

**Answers:**
- Task 5: `C:\Users\Dutch\Documents\2025- Board of directors Documents\Ministry Of Defense Audit.pdf`
- Task 6: `C:\Users\Dutch\Documents\2025- Board of directors Documents\2025-BUDGET-ALLOCATION-CONFIDENTIAL.pdf`

![Task 5 and 6 proof](screenshots/Task_5_and_6.png)

---

## Task 7 & 8 — Cloud Exfiltration Utility

**Breakdown:**
Following the same `applicationLookup` → installed-executable pattern used for WinRAR, an installer for MEGAsync (MEGA's desktop sync client) downloads and installs roughly two minutes after the documents were opened.

**Result:**
```
2025-01-24 10:20:05.128353+00:00 | C:\Users\Dutch\Downloads\MEGAsyncSetup64.exe
2025-01-24 10:22:19.479284+00:00 | C:\Users\Dutch\AppData\Local\MEGAsync\MEGAsync.exe
```

**Answers:**
- Task 7: `MEGAsync`
- Task 8: `2025-01-24 10:22:19`

![Task 7 and 8 proof](screenshots/Task_7_and_8.png)

---

## Task 9 — Anti-Forensic Destruction Utility

**Breakdown:**
Final tool in the download chain — a "File Shredder" installer, downloaded and installed roughly four minutes after MEGAsync, consistent with the scenario's description of files being "deleted... rendering them unrecoverable."

**Result:**
```
2025-01-24 10:26:40.806404+00:00 | C:\Users\Dutch\Downloads\file_shredder_setup.exe
2025-01-24 10:27:09.603857+00:00 | C:\Program Files\File Shredder\Shredder.exe
```

**Answer:** `File Shredder`

![Answer to task 9 proof](screenshots/Answer_to_task_9.png)

---

## Task 10 — Security Log Clear Time

**Command:**
```bash
python3 dump_evtx.py Security.evtx > security.xml
grep -n '>1102<' security.xml
sed -n '1,20p' security.xml
```

**Breakdown:**
Event ID 1102 (`Microsoft-Windows-Eventlog` provider) marks the exact moment an audit log is cleared, and is itself the first entry written back into the freshly emptied log. The `SubjectUserName` field ties the clear action to a specific account.

**Result:**
```xml
<EventID Qualifiers="">1102</EventID>
<TimeCreated SystemTime="2025-01-24 10:28:41.933849+00:00">
<Channel>Security</Channel>
<SubjectUserName>Dutch</SubjectUserName>
```

**Answer:** `2025-01-24 10:28:41`

Notably, the clear happened under Dutch's own account — the intruder operated as Dutch throughout, rather than creating a separate identity, consistent with a compromised-credential RDP session rather than a new local account being provisioned.

---

## Attack Chain Summary

| Time (UTC) | Action | Artifact |
|---|---|---|
| 10:15:14 | RDP logon | `Microsoft-Windows-TerminalServices-RemoteConnectionManager` Event 1149 |
| 10:17:14 | Download WinRAR | SmartScreen `applicationLookup` |
| 10:17:27 | Install/run WinRAR | `C:\Program Files\WinRAR\WinRAR.exe` |
| 10:17:33 | Download & run Everything (portable) | `C:\Users\Dutch\Downloads\Everything.exe` |
| 10:19:00 | Open Ministry of Defense Audit.pdf | SmartScreen `isFileSupported` |
| 10:19:19 | Open Budget Allocation Confidential.pdf | SmartScreen `isFileSupported` |
| 10:20:05 | Download MEGAsync | SmartScreen `applicationLookup` |
| 10:22:19 | Install/run MEGAsync | `AppData\Local\MEGAsync\MEGAsync.exe` |
| 10:26:40 | Download File Shredder | SmartScreen `applicationLookup` |
| 10:27:09 | Install/run File Shredder | `C:\Program Files\File Shredder\Shredder.exe` |
| 10:28:41 | Security log cleared | Event 1102, `SubjectUserName: Dutch` |

Full intrusion-to-anti-forensics window: **~13 minutes**.

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Remote Services: RDP | T1021.001 | Event 1149, TerminalServices logs |
| Ingress Tool Transfer | T1105 | SmartScreen download events (WinRAR, Everything, MEGAsync, File Shredder) |
| File and Directory Discovery | T1083 | Everything.exe (portable search utility) |
| Data from Local System | T1005 | PDF documents opened from Board of Directors folder |
| Exfiltration to Cloud Storage | T1567.002 | MEGAsync install and execution |
| Data Destruction | T1485 | File Shredder install and execution |
| Clear Windows Event Logs | T1070.001 | Security log Event 1102 |

## Lessons Learned & Remediation

- **SmartScreen Debug logging proved decisive.** A single log source captured the entire download-to-execution chain for every attacker tool, without needing to correlate across multiple channels.
- **Log clearing is self-defeating without deletion prevention.** Event 1102 exists specifically to flag its own predecessor's absence — a cleared log is itself evidence. Forwarding logs to a centralized, write-once collector (e.g. a SIEM) would have preserved the full picture even after the local clear.
- **Standalone/isolated hosts still need EDR.** The fileserver was deliberately kept off the breach-prone domain, but lacked any execution-blocking control — SmartScreen only logs and warns, it doesn't prevent. An EDR agent with process-blocking could have stopped WinRAR/MEGAsync/Shredder execution outright.
- **RDP exposure requires MFA.** A single compromised credential (Dutch's own account) was sufficient for full RDP access with no secondary factor challenged.


