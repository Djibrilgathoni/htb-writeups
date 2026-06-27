# HTB Sherlock — Vantage

**Category:** Cloud Forensics  
**Difficulty:** Easy  
**Author:** Djibril Gathoni  
**Date:** June 2026  

---

## Scenario

A small company moved some of its resources to a private cloud installation. The developers left a redirect to the dashboard on their web server. We are provided with two PCAP files captured on the day of the incident:

- `web-server.2025-07-01.pcap` — traffic to the company web server
- `controller.2025-07-01.pcap` — traffic to the OpenStack cloud controller

---

## Tools Used

- `tshark` — CLI packet analysis
- Basic knowledge of OpenStack architecture (Keystone, Swift, Horizon)
- MITRE ATT&CK Framework

---

## Investigation

### Task 1 — What tool did the attacker use to fuzz the web server?

I started by extracting all HTTP User-Agent strings from the web server PCAP:

```bash
tshark -r web-server.2025-07-01.pcap -Y "http.request" -T fields -e http.user_agent | sort | uniq -c | sort -rn | head -20
```

**Output:**
```
3696 Fuzz Faster U Fool v2.1.0-dev
  40 Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
```

The attacker sent 3,696 requests using ffuf — far outnumbering normal browser traffic.

**Answer:** `ffuf@2.1.0-dev`

---

### Task 2 — Which subdomain did the attacker discover?

I filtered for HTTP Host headers from the attacker's IP to see what subdomains were being fuzzed:

```bash
tshark -r web-server.2025-07-01.pcap -Y "http.request && ip.src == 117.200.21.26" -T fields -e http.host | sort | uniq -c | sort -rn | head -20
```

Most subdomains received only 2 requests (wordlist fuzzing). `cloud.vantage.tech` received 21 — meaning it responded differently and the attacker kept interacting with it.

**Answer:** `cloud.vantage.tech`

---

### Task 3 — How many login attempts did the attacker make before successfully logging in?

I filtered POST requests to the login endpoint:

```bash
tshark -r web-server.2025-07-01.pcap -Y "http.request.method == POST && ip.src == 117.200.21.26" -T fields -e http.host -e http.request.uri -e http.file_data
```

Four POST requests were made with the following credentials:
1. `admin:admin` — failed
2. `demo:demo` — failed
3. `root:root` — failed
4. `admin:StrongAdminSecret` — success (redirected to `/dashboard/`)

**Answer:** `3`

---

### Task 4 — When did the attacker download the OpenStack API remote access config file? (UTC)

After logging in, the attacker navigated to the API Access page and downloaded the OpenStack RC file:

```bash
tshark -r web-server.2025-07-01.pcap -Y "http.request.uri contains \"openrc\" && ip.src == 117.200.21.26" -T fields -e frame.time -e http.request.uri
```

**Answer:** `2025-07-01 09:40:29`

---

### Task 5 — When did the attacker first interact with the API on the controller node? (UTC)

Switching to the controller PCAP, I filtered for the first HTTP request from the attacker:

```bash
tshark -r controller.2025-07-01.pcap -Y "http.request && ip.src == 117.200.21.26" -T fields -e frame.time -e http.request.uri | head -5
```

Just 75 seconds after downloading the RC file, the attacker was already hitting the OpenStack Keystone identity API.

**Answer:** `2025-07-01 09:41:44`

---

### Task 6 — What is the project ID of the default project accessed by the attacker?

The attacker queried `/identity/v3/projects?domain_id=default&name=admin`. The project ID appeared directly in a subsequent API call URL:

```
/identity/v3/projects/9fb84977ff7c4a0baf0d5dbb57e235c7/users/...
```

**Answer:** `9fb84977ff7c4a0baf0d5dbb57e235c7`

---

### Task 7 — Which OpenStack service provides authentication and authorization?

All identity-related traffic went to `/identity/v3/...` endpoints. This is the Keystone service — OpenStack's dedicated identity, authentication, and authorization component.

**Answer:** `Keystone`

---

### Task 8 — What is the endpoint URL of the Swift service?

The Keystone token response contains a full service catalog. Filtering for HTTP response data and grepping for Swift revealed the object-store endpoint:

```bash
tshark -r controller.2025-07-01.pcap -Y "http" -T fields -e http.file_data | grep -i swift | head -10
```

**Answer:** `http://134.209.71.220:8080/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7`

---

### Task 9 — How many containers were discovered by the attacker?

I filtered for traffic on port 8080 (Swift):

```bash
tshark -r controller.2025-07-01.pcap -Y "tcp.port == 8080 && http.request" -T fields -e frame.time -e ip.src -e http.request.uri
```

The first request listed all containers. The response showed:
- `dev-files`
- `employee-data`
- `user-data`

**Answer:** `3`

---

### Task 10 — When did the attacker download the sensitive user data file? (UTC)

From the same Swift traffic, the attacker downloaded `user-details.csv` from the `user-data` container:

**Answer:** `2025-07-01 09:45:23`

---

### Task 11 — What is the username of the backdoor account created by the attacker?

I filtered for POST requests to the users endpoint:

```bash
tshark -r controller.2025-07-01.pcap -Y "http.request.method == POST && ip.src == 117.200.21.26" -T fields -e frame.time -e http.request.uri -e http.file_data | grep -i user
```

At `09:48:02`, the attacker POSTed to `/identity/v3/users` with:
```json
{"user": {"password": "P@$$word", "enabled": true, "default_project_id": "9fb84977ff7c4a0baf0d5dbb57e235c7", "name": "jellibean"}}
```

**Answer:** `jellibean`

---

### Task 12 — What is the password of the new user?

From the same request body above.

**Answer:** `P@$$word`

---

### Task 13 — What is the MITRE tactic ID of the technique used in Task 12?

Creating a cloud account for persistent access maps to:

- **Technique:** Create Account: Cloud Account
- **MITRE ID:** T1136.003
- **Tactic:** Persistence (TA0003)

**Answer:** `T1136.003`

---

### Task 14 — How many user records are in the sensitive user data file?

The `user-details.csv` content was captured in the PCAP response. Counting all data rows (excluding the header):

**Answer:** `28`

---

## Attack Timeline

| Time (UTC) | Action |
|---|---|
| 09:40:07 | Attacker begins subdomain fuzzing with ffuf |
| 09:40:29 | OpenStack RC file downloaded (API credentials stolen) |
| 09:41:44 | First API call to cloud controller (Keystone) |
| 09:43:27 | Swift object storage enumerated — 3 containers found |
| 09:45:23 | user-details.csv exfiltrated (28 records) |
| 09:45:47 | employee-details.csv exfiltrated (50 records) |
| 09:48:02 | Backdoor account `jellibean` created with admin privileges |

---

## Key Takeaways

- **Subdomain enumeration** can expose internal cloud dashboards accidentally left public
- **Weak credentials** on admin dashboards give attackers a foothold into the entire cloud environment
- **OpenStack RC files** contain all the credentials needed to interact with the cloud API directly — treat them like private keys
- **tshark** is far more efficient than Wireshark for PCAP analysis in resource-constrained environments
- Cloud attacker actions (enumeration, exfiltration, persistence) are fully visible in network traffic if you know what to look for

---

*Writeup by Djibril Gathoni | [LinkedIn](https://linkedin.com/in/djibrilgathoni) | [GitHub](https://github.com/Djibrilgathoni)*
