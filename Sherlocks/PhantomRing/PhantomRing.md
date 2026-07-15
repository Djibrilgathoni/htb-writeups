# HTB Sherlock: PhantomRing

**Category:** Digital Forensics & Incident Response (DFIR) — Malware Static Analysis
**Difficulty:** Beginner
**Tools Used:** `7z`, `file`, `md5sum`/`sha256sum`, `strings`, `objdump`, manual x86-64 disassembly analysis

---

## Scenario

Our organization's SOC team intercepted a suspicious binary during a routine threat hunting operation on a Linux server. The file was found in `/var/tmp` with an unusual name and was attempting to establish outbound connections. Initial analysis suggested this could be a post-exploitation agent. The objective was to perform static analysis on the binary to identify its capabilities, extract indicators of compromise (IOCs), and understand the threat actor's infrastructure — all without executing the sample.

---

## 1. Initial Triage

**Command:**
```bash
7z x PhantomRing.zip
ls -la phantom_ring
file phantom_ring/agent
```

**Breakdown:**
The archive was password-protected (standard HTB convention). Extraction revealed a single 31,192-byte executable named `agent`. Running `file` confirmed a 64-bit ELF binary — dynamically linked and, critically, **not stripped**, meaning the symbol table (`.symtab`) was intact. This was a significant break for analysis, since every function name (including custom `cmd_*` handlers) would be readable directly in disassembly rather than requiring manual reverse-engineering of unnamed functions.

**Result:** Confirmed target: an unstripped, dynamically linked x86-64 ELF binary posing as a post-exploitation implant.

---

## 2. Task 1 — Binary Hash

**Command:**
```bash
sha256sum phantom_ring/agent
```

**Breakdown:**
Hashing the sample provides a unique fingerprint for threat-intel correlation, blocklisting, and sharing with other defenders — standard first step in any malware triage workflow.

**Result:**
```
2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5
```

![Task 1](images/task01_hash.png)

---

## 3. Task 2 & 3 — C2 IP and Port

**Command:**
```bash
strings phantom_ring/agent | grep -Ei 'http|://|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
objdump -d phantom_ring/agent > agent.asm
grep -n "io_uring_prep_connect" agent.asm
sed -n '3100,3150p' agent.asm
```

**Breakdown:**
A `strings` sweep surfaced `192.168.56.1` sitting alongside `liburing` symbols (`io_uring_prep_connect`, `io_uring_queue_init`, etc.) — an immediate signal that networking in this binary was built entirely on **io_uring** rather than standard blocking socket calls.

IP addresses appear as literal strings when passed through `inet_pton()`, so `strings` catches them for free. Ports do **not** — they're stored as raw 16-bit integers inside a `sockaddr_in` struct, invisible to a plain string scan. To find the port, the call site for `io_uring_prep_connect` was located in the disassembly and traced backward to where the `sockaddr_in` struct is populated:

```asm
4200: mov    $0x115d,%edi
4205: call   1350 <htons@plt>
420a: mov    %ax,-0x100fe(%rbp)   ; sin_port
...
421f: lea    0x12f5(%rip),%rax   # "192.168.56.1"
422e: call   1400 <inet_pton@plt>
```

The immediate value `0x115d` is passed directly into `htons()`, which handles network-byte-order conversion — no manual byte-swapping needed since the pre-conversion host-order value is visible directly in the disassembly.

**Result:**
- C2 IP: `192.168.56.1`
- C2 Port: `0x115d` = **4445**

![Task 2](images/task02_ip.png)
![Task 3](images/task03_port.png)

---

## 4. Task 4 — Reconnect Interval

**Command:**
```bash
grep -n -E "sleep|nanosleep" agent.asm
sed -n '3170,3180p' agent.asm
sed -n '3206,3216p' agent.asm
```

**Breakdown:**
Two calls to `sleep@plt` were found, both immediately following a `close()` call on the socket and preceding a `jmp` back into the main connection loop — confirming this was the reconnect-retry logic (close failed socket → sleep → retry connect):

```asm
4342: mov    $0x78,%edi
4347: call   14e0 <sleep@plt>
434c: jmp    43f1 <main+0x28a>
```

`sleep()` takes its argument directly in `%edi`, no conversion required.

**Result:** `0x78` = **120 seconds** between reconnect attempts.

![Task 4](images/task04_reconnect.png)

---

## 5. Task 5 — Number of Supported Commands

**Command:**
```bash
grep -n "process_cmd" agent.asm
sed -n '2875,3075p' agent.asm
```

**Breakdown:**
Rather than trust the `cmd_*` symbol names surfaced by an initial `strings` pass (which returned 10 hits), the actual dispatcher function `process_cmd` was disassembled in full. It works via a chain of `strncmp`/`strcmp` comparisons against command keyword strings, each branching to a distinct handler on match:

| Branch | Handler | Match type |
|---|---|---|
| 1 | `cmd_get` | strncmp, len 4 |
| 2 | `cmd_recv` | strncmp, len 5 |
| 3 | `cmd_users` | strncmp, len 5 |
| 4 | `cmd_ss` | strncmp len 2 + strcmp fallback |
| 5 | `cmd_ps` | strncmp, len 2 |
| 6 | `cmd_me` | strncmp, len 2 |
| 7 | `cmd_kick` | strncmp, len 4 |
| 8 | `cmd_privesc` | strncmp, len 7 |
| 9 | `cmd_selfdestruct` | strcmp (exact) |
| 10 | `cmd_killbpf` | strncmp, len 7 |
| 11 | `cmd_exit` | strncmp, len 4 |

If none match, execution falls through to a `send_all` call returning a fixed 29-byte "invalid command" response — confirming there's no 12th hidden command.

`cmd_recv` was initially missed in the raw `strings` count since its name overlaps conceptually with internal receive-buffer plumbing, but tracing the dispatcher directly showed it's dispatched identically to every other command.

**Result:** **11 commands.**

![Task 5](images/task05_commands.png)

---

## 6. Task 6 — EDR Evasion via io_uring

**Breakdown:**
Every I/O operation across the binary — networking (`io_uring_prep_connect`, `io_uring_prep_send`, `io_uring_prep_recv`), file access (`io_uring_prep_openat`, `io_uring_prep_read`, `io_uring_prep_write`, `io_uring_prep_close`, `io_uring_prep_statx`), and deletion (`io_uring_prep_unlinkat`) — is routed through `io_uring_get_sqe` → `io_uring_prep_*` → `io_uring_submit`, never through direct libc syscall wrappers.

Most Linux EDR and monitoring tools hook or trace individual syscalls (`connect()`, `open()`, `unlink()`, etc.) via `ptrace`, seccomp-bpf, or kprobes at the syscall entry point. io_uring submits batched I/O operations into a shared ring buffer that the kernel executes asynchronously — often via kernel worker threads — bypassing the exact syscall-entry hook points that legacy monitoring expects. Any EDR that isn't specifically io_uring-aware is effectively blind to this binary's activity.

**Result:** **io_uring**

![Task 6](images/task06_iouring.png)

---

## 7. Task 7 — User Enumeration Source

**Command:**
```bash
grep -n "<cmd_users>:" agent.asm
sed -n '1114,1200p' agent.asm
strings -t x phantom_ring/agent | grep -i "utmp"
```

**Breakdown:**
`cmd_users` calls `read_file_uring` against a path loaded from `.rodata` offset `5008`. The function then manually parses the returned buffer in fixed 384-byte chunks — exactly `sizeof(struct utmp)` on x86-64 — filtering each record with `cmp $0x7,%ax`, which checks for `ut_type == USER_PROCESS` (value `7` in `<utmp.h>`). This is the same filtering logic tools like `who` use internally to show only active login sessions rather than boot records or dead processes.

**Result:** `/var/run/utmp`

![Task 7](images/task07_utmp.png)

---

## 8. Task 8 — SUID Privilege Escalation Scan Directory

**Command:**
```bash
sed -n '/<cmd_privesc>:/,+90p' agent.asm
strings -t x phantom_ring/agent | awk '$1=="527f"'
```

**Breakdown:**
`cmd_privesc` calls `opendir()` on a path at offset `527f`, then iterates entries, building full paths via `snprintf` and calling `io_uring_prep_statx` on each. The returned mode field is masked with `and $0x800,%eax` — `0x800` is `S_ISUID` (the SUID permission bit) — flagging any file where that bit is set.

**Result:** `/usr/bin`

![Task 8](images/task08_suid.png)

---

## 9. Task 9 — eBPF Monitoring Tool Detection

**Command:**
```bash
strings -t x phantom_ring/agent | grep -i "maps\|proc/%\|bpf\|ebpf"
```

**Breakdown:**
`cmd_killbpf` reads `/proc/%s/maps` (offset `5418`) for each running PID, then searches the returned content for the substring `anon_inode:bpf-map` (offset `5426`). This string is the kernel's own memory-mapping label for any process holding an active BPF map file descriptor — a footprint left behind by any eBPF-based security tool (Falco, Tetragon, Cilium, etc.) regardless of the tool's name or binary path. Rather than fingerprinting specific tool names, the malware fingerprints the unavoidable kernel-level artifact of *using* eBPF at all — then kills that PID outright.

**Result:** `anon_inode:bpf-map`

![Task 9](images/task09_ebpf.png)

---

## 10. Task 10 — First Tracing File Disabled

**Command:**
```bash
sed -n '/<cmd_killbpf>:/,+120p' agent.asm
strings -t x phantom_ring/agent | awk '$1=="5330" || $1=="5358" || $1=="5380"'
```

**Breakdown:**
Alongside killing eBPF-holding processes, `cmd_killbpf` also disables kernel-level ftrace by writing to three files stored in an array, in this load/iteration order:

1. `/sys/kernel/debug/tracing/tracing_on` (index 0 — loaded first)
2. `/sys/kernel/debug/tracing/set_event` (index 1)
3. `/sys/kernel/debug/tracing/current_tracer` (index 2)

`tracing_on` is the ftrace master switch — writing `0` disables all active tracing globally in a single write, making it the logical and most efficient first target before touching more granular settings.

**Result:** `/sys/kernel/debug/tracing/tracing_on`

![Task 10](images/task10_tracing.png)

---

## 11. Task 11 — Self-Location Before Deletion

**Command:**
```bash
sed -n '/<cmd_selfdestruct>:/,+80p' agent.asm
strings -t x phantom_ring/agent | awk '$1=="52e5"'
```

**Breakdown:**
`cmd_selfdestruct` calls `readlink@plt` against a path at offset `52e5`, storing the resolved result in a local buffer, null-terminating it, then passing that buffer directly into `io_uring_prep_unlinkat` to delete the file. `/proc/self/exe` is the canonical procfs symlink every Linux process can read to resolve its own on-disk binary path — necessary here since the agent has no hardcoded knowledge of where it was actually deployed.

**Result:** `/proc/self/exe`

![Task 11](images/task11_selfdestruct.png)

---

## 12. Task 12 — Self-Destruct Trigger Command

**Command:**
```bash
sed -n '2875,3075p' agent.asm    # process_cmd, branch preceding cmd_selfdestruct call
strings -t x phantom_ring/agent | awk '$1=="54cc"'
```

**Breakdown:**
Unlike most other commands (compared via `strncmp` on a fixed prefix length), the branch leading to `cmd_selfdestruct` uses an exact `strcmp` against a string at offset `54cc` — meaning this command requires a precise, full match with no partial/prefix tolerance, consistent with it being a deliberate, high-consequence operator action rather than a loosely-matched recon command. Notably, the operator-facing trigger keyword (`sdestruct`) is shorter than the internal function name (`cmd_selfdestruct`) — a small convenience shorthand for whoever is operating the C2 side.

**Result:** `sdestruct`

![Task 12](images/task12_trigger.png)

---

## Attack Chain Summary

| Stage | Technique | Detail |
|---|---|---|
| Deployment | Dropped to `/var/tmp` under an innocuous name | Post-exploitation staging |
| C2 Communication | Outbound connect via io_uring | `192.168.56.1:4445`, retries every 120s |
| Evasion (syscalls) | io_uring for all I/O | Bypasses syscall-hook-based EDR |
| Evasion (eBPF) | `anon_inode:bpf-map` detection in `/proc/[pid]/maps` | Kills processes running eBPF security tools |
| Evasion (kernel tracing) | Disables ftrace | `tracing_on`, `set_event`, `current_tracer` |
| Recon | `cmd_users`, `cmd_ps`, `cmd_ss`, `cmd_me` | Manual `utmp`/`proc` parsing, avoids shelling out |
| Privilege Escalation | `cmd_privesc` | SUID scan of `/usr/bin` via `statx` |
| Exfil/Control | `cmd_get`, `cmd_recv`, `cmd_kick`, `cmd_exit` | Full remote operator control |
| Anti-Forensics | `cmd_selfdestruct` (trigger: `sdestruct`) | `/proc/self/exe` → `unlinkat` |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observed Behavior |
|---|---|---|
| T1071.001 | Application Layer Protocol | Raw socket C2 over TCP to hardcoded IP:port |
| T1622 | Debugger/Analysis Evasion | eBPF process detection and termination |
| T1562.001 | Impair Defenses: Disable or Modify Tools | ftrace disabling via `tracing_on`/`set_event`/`current_tracer` |
| — | Kernel I/O interface evasion | io_uring used to bypass syscall-hooking monitors |
| T1033 | System Owner/User Discovery | `cmd_users` via `/var/run/utmp` |
| T1057 | Process Discovery | `cmd_ps` |
| T1049 | System Network Connections Discovery | `cmd_ss` |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid/Setgid | `cmd_privesc` SUID scan of `/usr/bin` |
| T1070.004 | Indicator Removal: File Deletion | `cmd_selfdestruct` via `/proc/self/exe` + `unlinkat` |
| T1105 | Ingress Tool Transfer | `cmd_get`/`cmd_recv` |

---

## Lessons Learned

- **io_uring is an emerging blind spot.** Most legacy EDR tooling was built around syscall-entry hooking assumptions that predate io_uring's mainstream adoption. Detection strategies need to account for io_uring submission-queue activity, not just traditional syscall traces.
- **eBPF-based monitoring isn't invisible.** Any process holding a BPF map leaves a detectable footprint (`anon_inode:bpf-map`) in its own `/proc/[pid]/maps` — attackers can and do fingerprint this generically rather than targeting specific tool names.
- **Unstripped malware is a gift to defenders.** The presence of readable symbol names (`cmd_privesc`, `cmd_killbpf`, etc.) made static analysis dramatically faster than it would be against a stripped or obfuscated sample.
- **Static analysis alone can fully characterize behavior.** Every IOC and capability in this Sherlock was extracted without ever executing the sample — disassembly plus careful string/offset correlation was sufficient.

## Remediation Recommendations

1. Deploy io_uring-aware monitoring (audit `io_uring_setup`/`io_uring_enter` syscalls themselves, since ring setup still goes through a traditional syscall).
2. Monitor and alert on writes to `/sys/kernel/debug/tracing/tracing_on` and related ftrace control files outside expected administrative activity.
3. Restrict or monitor unprivileged access to `io_uring_setup` via seccomp profiles or kernel io_uring restriction sysctls where operationally feasible.
4. Alert on anomalous `readlink(/proc/self/exe)` followed by immediate self-file deletion — a strong anti-forensics signature.
5. Baseline and alert on outbound connections to non-standard high ports on internal/RFC1918 address ranges from unexpected processes.

---

**HTB Profile:** [3131185](https://labs.hackthebox.com/achievement/sherlock/3131185/1296)

