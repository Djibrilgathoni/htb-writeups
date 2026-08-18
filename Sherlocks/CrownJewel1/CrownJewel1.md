# HTB Sherlock — CrownJewel1

**Category:** DFIR / Endpoint Forensics  
**Difficulty:** Very Easy  
**Author:** Djibril Gathoni  
**Date:** August 2026  

---

## Scenario

Forela's domain controller is under attack. The Domain Administrator account is believed to be compromised, and it is suspected that the threat actor dumped the NTDS.dit database on the DC. We just received an alert of `vssadmin` being used on the DC, since this is not part of the routine schedule we have good reason to believe that the attacker abused this LOLBIN utility to get the Domain environment's crown jewel. Perform some analysis on provided artifacts for a quick triage and if possible kick the attacker as early as possible.

Provided artifacts (`CrownJewel1.zip`):
- `C/$MFT` — Master File Table
- `SYSTEM.evtx` — System event log
- `SECURITY.evtx` — Security event log
- `Microsoft-Windows-NTFS.evtx` — NTFS operational event log

---

## Tools Used

- `analyzemft` — parsing `$MFT` into CSV
- `python-evtx` / `evtx` Python bindings — parsing `.evtx` logs
- Python `mft` (Rust-backed) library — accurate non-resident `$DATA` attribute sizes
- Windows Event ID reference (7036, 4799) and NTFS operational log event IDs (4, 9, 300–303)
- MITRE ATT&CK-style reasoning around LOLBIN abuse (`vssadmin`) and credential dumping (NTDS.dit)

---

## Investigation

### Task 1 — Identify the time when the Volume Shadow Copy service entered a running state

Attackers can abuse `vssadmin` to create volume shadow snapshots and then extract sensitive files like NTDS.dit to bypass security mechanisms. This state transition is logged as **Event ID 7036** (Service Control Manager) in the System event log.

I parsed `SYSTEM.evtx` and filtered for the VSS service entering the running state:

```bash
cat > parse_vss.py << 'EOF'
from Evtx.Evtx import Evtx

with Evtx('SYSTEM.evtx') as log:
    for record in log.records():
        xml = record.xml()
        if '7036' in xml and 'Volume Shadow Copy' in xml:
            print(xml)
EOF

python3 parse_vss.py
```

![Task 1](screenshots/Task%201.png)

The event showed `param1: Volume Shadow Copy`, `param2: running`, logged by the Service Control Manager on `DC01.forela.local`.

**Answer:** `2024-05-14 03:42:16`

---

### Task 2 — Find the two user groups the volume shadow copy process queries and the machine account that did it

When a shadow snapshot is created, VSS validates privileges by enumerating group membership on the machine account. This is captured as **Event ID 4799** ("A security-enabled local group membership was enumerated") in the Security log.

I parsed `SECURITY.evtx` for all 4799 events and narrowed to the ones fired directly by `VSSVC.exe` at the shadow copy creation timestamp:

```bash
cat > parse_4799.py << 'EOF'
from Evtx.Evtx import Evtx

with Evtx('SECURITY.evtx') as log:
    for record in log.records():
        xml = record.xml()
        if '4799' in xml:
            print(xml)
EOF

python3 parse_4799.py > events_4799.txt
```

![Task 2](screenshots/Task%202.png)

At `03:42:16.79`, two consecutive 4799 events fired with `CallerProcessName: C:\Windows\System32\VSSVC.exe`, `SubjectUserName: DC01$`, checking membership against **Administrators** (`S-1-5-32-544`) and **Backup Operators** (`S-1-5-32-551`) — both groups carry the backup/restore privileges VSS needs to snapshot the volume.

**Answer:** `Administrators, Backup Operators, DC01$`

---

### Task 3 — Identify the Process ID (in Decimal) of the volume shadow copy service process

The same 4799 events tied to `VSSVC.exe` carry its `CallerProcessId` in hex.

```bash
python3 -c "print(int('0x1190', 16))"
```

![Task 3](screenshots/Task%203.png)

**Answer:** `4496`

---

### Task 4 — Find the assigned Volume ID/GUID value to the Shadow copy snapshot when it was mounted

NTFS logs volume mount/dismount activity in `Microsoft-Windows-NTFS.evtx`. I parsed the log and filtered for events referencing the shadow copy device (`\Device\HarddiskVolumeShadowCopy1`):

```bash
python3 -c "
import re
with open('ntfs_all.txt') as f:
    content = f.read()
events = content.split('---')
for e in events:
    if 'HarddiskVolumeShadowCopy1' in e:
        print(e)
"
```

![Task 4](screenshots/Task%204.png)

The `VolumeId` field itself was empty for the shadow copy device, but every event tied to it — mount (EventID 4, 03:44:22), close (EventID 9), and dismount (EventID 300–303, 03:46:47) — carried the same `VolumeCorrelationId`, NTFS's internal identifier for the volume object across its lifecycle.

**Answer:** `{06c4a997-cca8-11ed-a90f-000c295644f9}`

---

### Task 5 — Identify the full path of the dumped NTDS database on disk

I searched `mft_output.csv` (parsed from `$MFT` with `analyzemft`) for records referencing `ntds`:

```bash
python3 -c "
import csv
with open('mft_output.csv', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if 'ntds' in row['Filename'].lower():
            print(row['Record Number'], row['Filename'], row['FN Creation Time'])
"
```

This surfaced a second `ntds.dit` record (#97945) created at `2024-05-14T03:44:22.813Z` — the exact same moment the shadow copy mounted — parented under record 42, separate from the legitimate database. I walked the parent-record chain up to the volume root to reconstruct the full path:

```bash
python3 -c "
import csv
records = {}
with open('mft_output.csv', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    for row in reader:
        records[row['Record Number']] = (row['Filename'], row['Parent Record Number'])

path_parts = []
current = '42'
seen = set()
while current in records and current not in seen:
    seen.add(current)
    name, parent = records[current]
    path_parts.append(name)
    if parent == '5' or parent == '':
        if parent == '5':
            path_parts.append('C:')
        break
    current = parent

path_parts.reverse()
print('\\\\'.join(path_parts))
"
```

![Task 5](screenshots/Task%205.png)

The chain resolved to `C:\Users\Administrator\Documents\backup_sync_dc` — the attacker staged the dump inside the Domain Administrator's own Documents folder, disguised behind an innocuous "backup sync" name.

**Answer:** `C:\Users\Administrator\Documents\backup_sync_dc\ntds.dit`

---

### Task 6 — When was the newly dumped ntds.dit created on disk?

The `$SI` Creation Time and all four `$FN` timestamps on MFT record 97945 agree: `2024-05-14T03:44:22.813Z` — matching the shadow copy mount event down to the millisecond.

![Task 6](screenshots/Task%206.png)

Notably, the `$SI` **Modification Time** on this record reads `2023-03-27T14:02:43.932Z`, over a year *before* the creation time — a classic timestomping artifact. The attacker's tooling appears to have copied the legitimate `ntds.dit`'s original modified-time metadata onto the new copy to make it look less suspicious, but this didn't propagate to the `$FN` attributes, which still show the true creation time.

**Answer:** `2024-05-14 03:44:22`

---

### Task 7 — Which registry hive was dumped alongside NTDS.dit, and what is its file size in bytes?

`ntds.dit` alone isn't enough — decrypting it offline requires the **SYSTEM** hive, which holds the boot key used to derive the password encryption key (PEK). I checked for other files sharing the same parent record (42, `backup_sync_dc`):

```bash
python3 -c "
import csv
with open('mft_output.csv', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['Parent Record Number'] == '42':
            print(row['Record Number'], row['Filename'], row['FN Creation Time'])
"
```

This returned `SYSTEM`, created at `03:44:42` — 20 seconds after `ntds.dit`, same staging folder.

`analyzemft` doesn't reliably populate the logical size for non-resident `$DATA` attributes, so I used the Rust-backed `mft` Python library instead, which parses this correctly:

```bash
pip install mft --break-system-packages

python3 -c "
from mft import PyMftParser
parser = PyMftParser('C/\$MFT')
for record in parser.entries():
    if isinstance(record, Exception):
        continue
    if record.entry_id == 663:
        print('Full path:', record.full_path)
        print('File size:', record.file_size)
"
```

![Task 7](screenshots/Task%207.png)

**Answer:** `SYSTEM, 17563648`

---

## Attack Timeline

| Time (UTC) | Action |
|---|---|
| 03:41:56 | Machine account `DC01$` begins group enumeration ahead of the snapshot |
| 03:42:16 | Volume Shadow Copy service (PID 4496) enters running state |
| 03:42:16 | VSS validates privileges against `Administrators` and `Backup Operators` |
| 03:44:22 | Shadow copy mounts (`VolumeCorrelationId {06c4a997-cca8-11ed-a90f-000c295644f9}`) |
| 03:44:22 | `ntds.dit` copied to `C:\Users\Administrator\Documents\backup_sync_dc\` |
| 03:44:42 | `SYSTEM` registry hive (17,563,648 bytes) copied to the same folder |
| 03:46:47 | Shadow copy device dismounted ("User request") |

---

## Key Takeaways

- **`vssadmin` / VSS abuse** is a quiet, "living-off-the-land" path to dumping `NTDS.dit` without touching the Domain Controller's live filesystem protections — but it still leaves a clean trail across the System, Security, and NTFS operational event logs.
- **Event ID 7036** (service state change) and **Event ID 4799** (group membership enumeration) together pinpoint exactly when and under what privileges a shadow copy was created.
- **NTFS operational logs** (`Microsoft-Windows-Ntfs/Operational`) track volume mount/dismount lifecycles via `VolumeCorrelationId`, even for ephemeral shadow copy devices that never get a proper `Volume{GUID}`.
- **`$MFT` parent-record chains** can reconstruct full file paths even when a tool like `analyzemft` doesn't expose `Filepath` directly — useful when hunting for staged/exfil files.
- **A dumped `ntds.dit` is only half the story** — attackers need the paired `SYSTEM` hive to derive the boot key and decrypt it offline. Always hunt for both together.
- **Mismatched `$SI`/`$FN` timestamps** (modification time predating creation time) are a reliable timestomping indicator worth flagging even when not directly asked for.
- Off-the-shelf parsers can silently under-report data — `analyzemft` left non-resident `$DATA` sizes as `None`; the Rust-backed `mft` library parsed them correctly.

---

*Writeup by Djibril Gathoni | [LinkedIn](https://linkedin.com/in/djibrilgathoni) | [GitHub](https://github.com/Djibrilgathoni)*
