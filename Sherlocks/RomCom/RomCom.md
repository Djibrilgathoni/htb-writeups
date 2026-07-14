# HTB Sherlock — RomCom

**Category:** DFIR / Threat Intelligence
**Difficulty:** Beginner
**Author:** Djibril Gathoni
**Date:** July 2026

---

## Scenario

Susan works at the Research Lab in Forela International Hospital. A Microsoft Defender alert was received from her computer, and she also mentioned that while extracting a document from a received file, she received tons of errors, but the document opened just fine. According to the latest threat intel feeds, WinRAR is being exploited in the wild to gain initial access into networks, and WinRAR is one of the software programs the staff uses. As a threat intelligence analyst with a DFIR background, a lightweight triage image was provided to kick off the investigation while the SOC team sweeps the environment for other indicators.

---

## Tools Used

- `qemu-nbd` — mounting the provided `.vhdx` triage image via NBD, after `guestmount`/libguestfs failed to launch the appliance in the Kali environment
- `ntfs-3g` — mounting the NTFS partition read-only (`show_sys_files`, `streams_interface=windows`) to preserve system files and ADS visibility
- `analyzeMFT` — parsing `$MFT` into CSV for filesystem timeline analysis (Python-native substitute for MFTECmd)
- Custom Python USN Journal parser (`usn_parse.py`) — `usnparser` failed to install on Kali due to a `setuptools`/`jaraco.functools` packaging incompatibility, so a purpose-built parser was written to decode `$UsnJrnl:$J` records directly
- Custom MFT parent-path resolver (`resolve_path.py`) — automates walking an MFT record's parent-record chain to reconstruct its full path in one command

---

## Investigation

### Task 1 — What is the CVE assigned to the WinRAR vulnerability exploited by the RomCom threat group in 2025?

Cross-referenced current threat intel on WinRAR exploitation in the wild against the NVD.

[![Task 1](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%201.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%201.png)

**Answer:** `CVE-2025-8088`

---

### Task 2 — What is the nature of this vulnerability?

Per the NVD description, the vulnerability affects the Windows version of WinRAR and allows attackers to execute arbitrary code by crafting malicious archive files that escape the intended extraction directory.

[![Task 2](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%202.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%202.png)

**Answer:** `Path Traversal`

---

### Task 3 — What is the name of the archive file under Susan's documents folder that exploits the vulnerability upon opening the archive file?

Extracted the provided `.vhdx` triage image and mounted it via `qemu-nbd` and `ntfs-3g`, since `guestmount` failed to launch its appliance in this environment. Then parsed `$MFT` (collected from `C:\$MFT`, not the small triage-container `$MFT` at the volume root) with `analyzeMFT`, and searched the resulting CSV for `.rar` entries:

```
analyzemft -f mft_analysis/$MFT -o mft_analysis/mft_output.csv --csv
grep -ia "\.rar" mft_analysis/mft_output.csv
```

[![Task 3](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%203.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%203.png)

Two MFT records for the same file appeared, both dated 2025-09-02, matching the incident window.

**Answer:** `Pathology-Department-Research-Records.rar`

---

### Task 4 — When was the archive file created on the disk?

MFT timestamps can be altered (timestomping), so the USN Journal — a much harder to tamper append-only log — was used instead. Parsed `$UsnJrnl:$J` (collected separately from `C:\$Extend\$J`) with a custom Python parser and filtered for the archive's `FILE_CREATE` event:

```
python3 usn_parse.py mft_analysis/$J "Pathology-Department-Research-Records.rar"
```

[![Task 4](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%204.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%204.png)

**Answer:** `2025-09-02 08:13:50`

---

### Task 5 — When was the archive file opened?

Windows creates a `.lnk` shortcut in Recent Items whenever a file is opened via Explorer. Searched the USN Journal for the archive's corresponding LNK file and its `FILE_CREATE` event:

```
python3 usn_parse.py mft_analysis/$J "Pathology-Department-Research-Records"
```

[![Task 5](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%205.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%205.png)

Found `Pathology-Department-Research-Records.lnk` created ~14 seconds after the archive itself.

**Answer:** `2025-09-02 08:14:04`

---

### Task 6 — What is the name of the decoy document extracted from the archive file, meant to appear legitimate and distract the user?

Filtered the MFT for common document extensions and matched timestamps against the archive extraction window:

```
grep -iaE "\.(docx|doc|pdf|xlsx|xls|pptx)" mft_analysis/mft_output.csv
```

[![Task 6](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%206.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%206.png)

One entry stood out: same parent record number as the archive itself, timestamped immediately after the RAR's opening.

**Answer:** `Genotyping_Results_B57_Positive.pdf`

---

### Task 7 — What is the name and path of the actual backdoor executable dropped by the archive file?

Since the exploit abuses Alternate Data Streams, all files are created simultaneously as the decoy document. Searched the USN Journal for `FILE_CREATE` events in the seconds following the decoy PDF's creation, then resolved the full path by walking parent record numbers back through the MFT:

```
python3 usn_parse.py mft_analysis/$J
```

[![Task 7](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%207.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%207.png)

Found `ApbxHelper.exe` created within milliseconds of the decoy PDF. Walked its MFT parent chain (`Local` → `AppData` → `susan` → `Users`) to resolve the full path.

**Answer:** `C:\Users\Susan\Appdata\Local\ApbxHelper.exe`

---

### Task 8 — The exploit also drops a file to facilitate the persistence and execution of the backdoor. What is the path and name of this file?

A second file, `Display Settings.lnk`, was created in the same ADS write burst as the backdoor executable. Resolved its full path by walking the MFT parent chain:

```
grep -ia "Display Settings.lnk" mft_analysis/mft_output.csv | cut -d',' -f1-9
```

[![Task 8](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%208.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%208.png)

Parent chain: `Startup` → `Programs` → `Start Menu` → `Windows` → `Microsoft` → `Roaming` → `AppData` → `susan` → `Users`.

**Answer:** `C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`

---

### Task 9 — What is the associated MITRE Technique ID discussed in the previous question?

Since the persistence artifact is specifically a `.lnk` shortcut placed in the Startup folder, the applicable technique is the dedicated shortcut-abuse sub-technique rather than the general Registry Run Keys/Startup Folder one.

[![Task 9](https://github.com/Djibrilgathoni/htb-writeups/raw/main/Sherlocks/RomCom/screenshots/Task%209.png)](/Djibrilgathoni/htb-writeups/blob/main/Sherlocks/RomCom/screenshots/Task%209.png)

**Answer:** `T1547.009`

---

### Task 10 — When was the decoy document opened by the end user, thinking it to be a legitimate document?

Searched the USN Journal for the decoy PDF's corresponding `.lnk` (Recent Items) file and its `FILE_CREATE` timestamp:

```
python3 usn_parse.py mft_analysis/$J "Genotyping"
```

`Genotyping_Results_B57_Positive.lnk` was created ~47 seconds after the PDF's own extraction.

**Answer:** `2025-09-02 08:15:05`

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

- **CVE-2025-8088** (WinRAR ADS path traversal) allows a single archive extraction to simultaneously write files outside the intended target directory.
- The **USN Journal is more forensically reliable than MFT timestamps** for establishing file creation order, since MFT `$SI` timestamps can be altered while the append-only USN Journal is much harder to tamper with.
- **`.lnk` files in Recent Items are a reliable proxy for "file opened via Explorer"**.
- Persistence via a **Startup folder shortcut (T1547.009)** is distinct from the Registry Run Keys/Startup Folder technique (T1547.001).
- When standard forensic tooling breaks due to packaging or environment issues, understanding the underlying artifact structure makes it possible to route around tooling failures.

---

*Writeup by Djibril Gathoni | [LinkedIn](https://linkedin.com/in/djibrilgathoni) | [GitHub](https://github.com/Djibrilgathoni)*
