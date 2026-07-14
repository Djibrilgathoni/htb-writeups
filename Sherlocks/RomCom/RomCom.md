
# HTB Sherlock — RomCom

**Category:** DFIR / Threat Intelligence
**Difficulty:** Beginner
**Author:** Djibril Gathoni
**Date:** July 2026

---

## Scenario

Susan works at the Research Lab in Forela International Hospital. A Microsoft Defender alert was received from her computer, and she also mentioned that while extracting a document from a received file, she received tons of errors, but the document opened just fine. According to the latest threat intel feeds, WinRAR is being exploited in the wild to gain initial access into networks, and WinRAR is one of the software programs the staff uses. As a threat intelligence analyst with a DFIR background, a lightweight triage image was provided to kick off the investigation while the SOC team sweeps the environment for other indicators.

The "errors but the document still opened" detail is really the whole case in miniature: it's the signature of a crafted archive exploiting a path-traversal flaw, dropping extra files outside the intended folder while still successfully extracting a decoy document so the victim doesn't get suspicious.

---

## Tools Used

- `qemu-nbd` — mounting the provided `.vhdx` triage image via NBD, after `guestmount`/libguestfs failed to launch the appliance in my Kali environment
- `ntfs-3g` — mounting the NTFS partition read-only (`show_sys_files`, `streams_interface=windows`) to preserve system files and ADS visibility
- `analyzeMFT` — parsing `$MFT` into CSV for filesystem timeline analysis (Python-native substitute for MFTECmd, which isn't natively available on Linux)
- Custom Python USN Journal parser (`usn_parse.py`) — `usnparser` failed to install on Kali due to a `setuptools`/`jaraco.functools` packaging incompatibility, so I wrote a purpose-built parser to decode `$UsnJrnl:$J` records (USN, timestamp, update reason flags, filename) directly from the raw journal bytes
- Custom MFT parent-path resolver (`resolve_path.py`) — automates walking an MFT record's parent-record chain to reconstruct its full path in one command, instead of manually grepping one parent record at a time

---

## Environment Setup

Before getting into the tasks, getting the evidence mounted took some troubleshooting worth documenting.

I extracted the provided `RomCom.zip`, which revealed a password-protected `.vhdx` triage image:

[![Extracting the archive](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Unzipped.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Unzipped.png)

My first instinct was to mount it with `guestmount` (libguestfs), since that's the standard tool for this. This kept crashing with `guestfs_launch failed` — the libguestfs appliance wouldn't boot in my Kali VM. Rather than fight it, I switched to mounting the VHDX via `qemu-nbd` instead:

```
sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 --read-only 2025-09-02T083211_pathology_department_incidentalert.vhdx
sudo fdisk -l /dev/nbd0
```

This exposed a single NTFS partition, `/dev/nbd0p1`. I mounted it with `ntfs-3g` specifically (not the in-kernel `ntfs3` driver, which doesn't support the options I needed):

```
sudo mount -t ntfs-3g -o ro,show_sys_files,streams_interface=windows /dev/nbd0p1 /mnt/romcom
```

`show_sys_files` and `streams_interface=windows` matter here because of the ADS angle in this exploit — I wanted Alternate Data Streams to actually be visible if I needed them.

[![Mounting the volume and finding CopyLog.csv](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Finding%20the%20CSV%20file%20according%20to%20the%20hint%20given..png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Finding%20the%20CSV%20file%20according%20to%20the%20hint%20given..png)

Listing the mounted volume showed a `CopyLog.csv`, confirming this is a KAPE-style triage collection — the log records every artifact copied from the source machine along with its original size. This turned out to be essential: the `$MFT` sitting at the root of the mount was only 65,536 bytes, far too small to be a real MFT. The CopyLog showed the actual collected `$MFT` should be 143,130,624 bytes. The real one was sitting at `/mnt/romcom/C/$MFT` — the root-level one belongs to the small triage-container volume itself, not Susan's machine. I nearly parsed the wrong file entirely before catching this size mismatch.

---

## Investigation

### Task 1 — What is the CVE assigned to the WinRAR vulnerability exploited by the RomCom threat group in 2025?

The scenario explicitly points at WinRAR exploitation in the wild, so I cross-referenced current threat intel against the NVD to find the exact CVE tied to RomCom's 2025 campaign.

[![NVD reference for CVE-2025-8088](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%201.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%201.png)

[![Task 1](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%201.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%201.png)

**Answer:** `CVE-2025-8088`

---

### Task 2 — What is the nature of this vulnerability?

Per the NVD description, the vulnerability affects the Windows version of WinRAR and allows attackers to execute arbitrary code by crafting malicious archive files that escape the intended extraction directory — a classic path traversal.

[![Task 2](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%202.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%202.png)

**Answer:** `Path Traversal`

---

### Task 3 — What is the name of the archive file under Susan's documents folder that exploits the vulnerability upon opening the archive file?

With the environment mounted and the correct `$MFT` identified, I copied it locally and parsed it with `analyzeMFT` since MFTECmd isn't available on Linux:

```
analyzemft -f mft_analysis/$MFT -o mft_analysis/mft_output.csv --csv
```

The parser threw a few non-fatal validation warnings on corrupted/oversized attribute records but completed successfully. I then searched the resulting CSV for `.rar` entries:

```
grep -ia "\.rar" mft_analysis/mft_output.csv
```

[![Filtering the MFT for .rar entries](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/2.rar%20found.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/2.rar%20found.png)

Buried among unrelated Windows component filenames containing "rar" as a substring (like `..rarydialog.appxmain...`), two MFT records for the same file stood out: both dated 2025-09-02, matching the incident window.

[![MFT records for the archive file](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%203.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%203.png)

[![Task 3](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%203.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%203.png)

**Answer:** `Pathology-Department-Research-Records.rar`

---

### Task 4 — When was the archive file created on the disk?

I deliberately avoided relying on the MFT's own Standard Information timestamps here, since those can be altered through timestomping. The USN Journal (`$UsnJrnl:$J`) is a much harder-to-tamper append-only log of every filesystem change, so I used that instead.

I copied the actual `$J` file from `C:\$Extend\$J` (cross-checking its size against both the CopyLog and the live mount to make sure I had the real one). Since `usnparser` failed to install on Kali, I wrote a small Python parser (`usn_parse.py`) that reads the raw USN record structure directly — decoding the USN number, FILETIME timestamp, update reason bitflags, and filename from each record.

```
python3 usn_parse.py mft_analysis/$J "Pathology-Department-Research-Records.rar"
```

[![USN Journal FILE_CREATE events for the archive](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%204.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%204.png)

[![Task 4](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%204.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%204.png)

The earliest `FILE_CREATE` reason for the archive gave me its true creation time.

**Answer:** `2025-09-02 08:13:50`

---

### Task 5 — When was the archive file opened?

Windows creates a `.lnk` shortcut in the user's Recent Items folder any time a file is opened through Explorer. Since the LNK didn't exist before that moment, its own `FILE_CREATE` timestamp is a reliable proxy for "this file was opened." I re-ran my USN parser without the `.rar` extension in the filter, so it would also catch the LNK variant:

```
python3 usn_parse.py mft_analysis/$J "Pathology-Department-Research-Records"
```

[![USN Journal showing the LNK creation](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%205.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%205.png)

[![Task 5](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%205.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%205.png)

`Pathology-Department-Research-Records.lnk` was created about 14 seconds after the archive itself — consistent with Susan opening it almost immediately after receiving it.

**Answer:** `2025-09-02 08:14:04`

---

### Task 6 — What is the name of the decoy document extracted from the archive file, meant to appear legitimate and distract the user?

I first checked the USN Journal for any document-extension `FILE_CREATE` events in the same window as the archive's opening, but nothing showed up there — likely because WinRAR's internal Webview preview doesn't always generate the same journal footprint as a normal extraction. So I went back to the MFT and filtered broadly for common document extensions:

```
grep -iaE "\.(docx|doc|pdf|xlsx|xls|pptx)" mft_analysis/mft_output.csv
```

[![Locating the decoy PDF in the MFT](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%206%20%28the%20file%29.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%206%20%28the%20file%29.png)

This was noisy — lots of legitimate Windows DLLs and manifests use these extensions as substrings. I narrowed it down by matching the parent record number against the archive's own parent record (they should share the same containing folder) and by matching the timestamp to right after the archive's opening. One entry matched both criteria exactly, with a filename clearly engineered to be an urgent, sensitive-sounding hospital lure that Susan would open without hesitation. Cross-checking against the USN Journal around this same timestamp also showed the decoy PDF, the persistence LNK, and the backdoor executable all being created within milliseconds of each other — the signature of the ADS exploit dropping everything simultaneously.

[![USN Journal burst showing the decoy, backdoor, and persistence files created together](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%206.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%206.png)

[![Task 6](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%206.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%206.png)

**Answer:** `Genotyping_Results_B57_Positive.pdf`

---

### Task 7 — What is the name and path of the actual backdoor executable dropped by the archive file?

Since this CVE abuses Alternate Data Streams for path traversal, the exploit writes multiple files in the same burst as the decoy document — some inside the intended folder, some escaping it entirely. The USN Journal burst above (Task 6) already showed `ApbxHelper.exe` and a shortcut named `Display Settings.lnk` created within milliseconds of the decoy PDF. Neither name matches anything a legitimate WinRAR extraction should produce.

To find where `ApbxHelper.exe` actually landed, I looked up its parent record number in the MFT, then manually walked the parent-record chain one grep at a time — each record pointing to its own parent, until I reached the volume root:

```
grep -ia "ApbxHelper.exe" mft_analysis/mft_output.csv | cut -d',' -f1-9
grep -a "^104988," mft_analysis/mft_output.csv | cut -d',' -f1-9
grep -a "^104966," mft_analysis/mft_output.csv | cut -d',' -f1-9
grep -a "^104955," mft_analysis/mft_output.csv | cut -d',' -f1-9
grep -a "^2066," mft_analysis/mft_output.csv | cut -d',' -f1-9
```

[![Manual parent record walk for ApbxHelper.exe](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%207.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%207.png)

That chain resolved as `Local` → `AppData` → `susan` → `Users`, giving the full path. After doing this manually once, I wrote `resolve_path.py` to automate it for any filename going forward — a single command instead of five separate greps.

[![Task 7](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%207.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%207.png)

**Answer:** `C:\Users\Susan\Appdata\Local\ApbxHelper.exe`

---

### Task 8 — The exploit also drops a file to facilitate the persistence and execution of the backdoor. What is the path and name of this file?

The second file I'd spotted in the same ADS write burst, `Display Settings.lnk`, was the obvious candidate — a shortcut with an innocuous name is a common way to hide a persistence mechanism in plain sight. I resolved its full path the same way, walking the MFT parent chain:

```
grep -ia "Display Settings.lnk" mft_analysis/mft_output.csv | cut -d',' -f1-9
```

followed by the same repeated parent lookups.

[![Manual parent record walk for Display Settings.lnk](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%208.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Answer%20to%20task%208.png)

[![Full parent chain resolution](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Path%20to%20task%207.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Path%20to%20task%207.png)

This time the chain resolved as `Startup` → `Programs` → `Start Menu` → `Windows` → `Microsoft` → `Roaming` → `AppData` → `susan` → `Users` — landing squarely in the Windows Startup folder, which auto-executes anything placed there at every user login.

[![Task 8](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%208.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%208.png)

**Answer:** `C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`

---

### Task 9 — What is the associated MITRE Technique ID discussed in the previous question?

My first instinct was T1547.001 (Registry Run Keys / Startup Folder), since that's the commonly cited technique for Startup-folder persistence. But since the actual artifact here is specifically a `.lnk` shortcut rather than a raw executable or a registry key, ATT&CK has a more precise sub-technique dedicated to shortcut abuse.

[![Task 9](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%209.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%209.png)

**Answer:** `T1547.009` — Boot or Logon Autostart Execution: Shortcut Modification

---

### Task 10 — When was the decoy document opened by the end user, thinking it to be a legitimate document?

Using the same logic as Task 5, I searched the USN Journal for the decoy PDF's own Recent Items LNK file and its `FILE_CREATE` event:

```
python3 usn_parse.py mft_analysis/$J "Genotyping"
```

`Genotyping_Results_B57_Positive.lnk` was created about 47 seconds after the PDF itself was extracted — the moment Susan actually opened the decoy, completing the deception described in the scenario.

**Answer:** `2025-09-02 08:15:05`

---

## Automating the Path Resolution

Manually walking the MFT parent-record chain (as done live in Tasks 7 and 8) works but doesn't scale well. I later wrote `resolve_path.py` to automate it — it walks the parent-record chain for any given filename and resolves the full path in one shot:

```
python3 resolve_path.py mft_output.csv --name "ApbxHelper.exe"
python3 resolve_path.py mft_output.csv --name "Display Settings.lnk"
```

[![Automated path resolution output, matching the manual results exactly](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Full%20path.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Full%20path.png)

Both outputs matched the manually-derived answers from Tasks 7 and 8 exactly, confirming the manual work was correct and giving me a reusable tool for future Sherlocks.

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| 08:13:50 | `Pathology-Department-Research-Records.rar` created (received) |
| 08:14:04 | Archive opened by Susan (LNK created in Recent Items) |
| 08:14:18 | Decoy `Genotyping_Results_B57_Positive.pdf` extracted |
| 08:14:18 | `ApbxHelper.exe` (backdoor) dropped via ADS path traversal |
| 08:14:18 | `Display Settings.lnk` (persistence) dropped via ADS path traversal |
| 08:15:05 | Decoy PDF opened by Susan, completing the deception |

---

## Key Takeaways

- **CVE-2025-8088** (WinRAR ADS path traversal) allows a single archive extraction to simultaneously write files outside the intended target directory — the "errors during extraction, but the document opened fine" behavior Susan reported is a direct symptom of this.
- Always verify collected artifacts against a CopyLog (or equivalent) before trusting file sizes — the tiny stub `$MFT` at the triage volume root nearly led me to parse the wrong file entirely.
- The **USN Journal is more forensically reliable than MFT timestamps** for establishing file creation order, since MFT `$SI` timestamps can be altered while the append-only USN Journal is much harder to tamper with.
- **`.lnk` files in Recent Items are a reliable proxy for "file opened via Explorer"** — their creation time marks first access even when no other access-time artifact survives.
- Persistence via a **Startup folder shortcut (T1547.009)** is distinct from the more commonly cited Registry Run Keys/Startup Folder technique (T1547.001) — the specific artifact type determines the correct sub-technique.
- When standard forensic tooling (`usnparser`, `guestmount`) breaks due to packaging or environment issues, understanding the underlying artifact structure (USN record layout, NTFS MFT parent-record chains) makes it possible to route around tooling failures rather than being blocked by them.

---

*Writeup by Djibril Gathoni | [LinkedIn](https://linkedin.com/in/djibrilgathoni) | [GitHub](https://github.com/Djibrilgathoni)*

