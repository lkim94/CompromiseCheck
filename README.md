# compromise_check.sh

A read-only compromise diagnostic for Ubuntu machines running Docker.

It answers the question **"has something been planted here?"** — on the host and
inside containers — without changing a single byte of your system.

---

## Safety first

The script **never modifies your system**. No cleanup, no kills, no quarantine,
no `docker prune`. Every command it runs is read-only:

| Command | What it reads |
|---|---|
| `readlink /proc/*/exe` | the real binary behind each process |
| `find` | hidden files in world-writable directories |
| `docker diff` / `inspect` / `ps` | container metadata and filesystem changes |
| `ps` | process names, users, CPU and memory |
| `ss` | listening ports and established connections |
| `systemctl list-*` | timers and running services |
| `ssh-keygen -l` | key **fingerprints** only, never key material |
| `sha256sum` | checksums of cron and sudoers files |

There is deliberately **no `docker exec`**. Containers are read from the host
side, so nothing is started or run inside them.

The one thing it writes is its own baseline file, under `--state`. Nothing else
on disk is touched.

---

## Install

```bash
sudo cp compromise_check.sh /usr/local/bin/
sudo chmod 700 /usr/local/bin/compromise_check.sh
```

No dependencies to install. Everything it uses ships with Ubuntu, except `ss`,
which is optional — that section is skipped and noted if missing.

---

## Usage

```bash
sudo compromise_check.sh [options]
```

Run it with `sudo`. Without root, `/proc` entries for other users, container
metadata, and key files are silently unreadable, and you get an incomplete
picture.

### First run

Establish a baseline **only when you believe the host is clean**. Everything
present at that moment becomes "normal" — baseline a compromised host and it
will hide its own intruder.

```bash
sudo compromise_check.sh --no-baseline    # look first
sudo compromise_check.sh --update-baseline
```

### Options

| Option | Default | What it does |
|---|---|---|
| `-j, --json` | off | Machine-readable output for automation |
| `-s, --state DIR` | `/var/lib/compromise-check` | Where the baseline lives |
| `--no-baseline` | off | Report everything, ignore the baseline |
| `--update-baseline` | — | Accept current state as normal, then exit |
| `--mem-threshold N` | 25 | Flag processes above N% memory |
| `--cpu-threshold N` | 80 | Flag processes above N% CPU |
| `-q, --quiet` | off | Output nothing unless something is found |
| `-h, --help` | — | Show help |

### Examples

```bash
sudo compromise_check.sh                          # normal run
sudo compromise_check.sh --no-baseline            # everything, no comparison
sudo compromise_check.sh --json | jq .            # for n8n or a webhook
sudo compromise_check.sh --mem-threshold 60       # busy host, fewer false hits
sudo compromise_check.sh -q                       # silent unless something found
sudo compromise_check.sh > report.txt             # save the output
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing found |
| 1 | Low or medium findings |
| 2 | **HIGH findings — investigate now** |
| 3 | Script error |

Exit code 2 is what automation should alert on.

---

## What the checks look for

| # | Check | Why it matters |
|---|---|---|
| 1 | Processes running from a **deleted binary** | The strongest single signal. Malware writes to `/tmp`, starts, then unlinks so the file can't be found or scanned. |
| 2 | **Hidden files** in `/tmp`, `/var/tmp`, `/dev/shm` | World-writable, and a leading dot keeps them out of a plain `ls`. |
| 3 | **Container `/tmp` changes** via `docker diff` | Payloads dropped inside a container never touch the host filesystem. |
| 4 | **Resource hogs** past CPU/memory thresholds | Miners are quiet in every way except consumption. |
| 5 | **Executing from `/tmp`**, process name vs. real binary | Malware routinely renames itself after something familiar. |
| 6 | **Outbound connections** to public addresses | Baselined, so only new destinations surface. |
| 7 | **Listening ports** | Baselined. A new one is a new door. |
| 8 | **Persistence** — crontabs, `cron.d`, timers, services | Where an attacker arranges to survive a reboot. |
| 9 | **Trust anchors** — SSH fingerprints, login accounts, sudoers | A new key in `authorized_keys` is unauthorised access. |
| 10 | **Recent writes** to `/etc/systemd/system`, `/usr/local/bin`, `/root` | |
| 11 | **Container inventory** and restart storms | |

Checks 6–9 and 11 record *state* and report only what's new since the baseline.
Checks 1–5 and 10 fire every run regardless.

---

## Reading the output

Findings are grouped by severity, most serious first:

```
==============================================================
 compromise_check  devtx  2026-09-09T11:24:19Z
==============================================================

-- HIGH (4) --
  [deleted_exe        ] pid=3005 comm=.kworkerd exe=/tmp/.kworkerd (deleted)
  [hidden_tmp_file    ] /tmp/.n (58 bytes)
  [exec_from_tmp      ] pid=3005 comm=.kworkerd exe=/tmp/.kworkerd (deleted)
  [new_cron_hash      ] /etc/cron.d/backdoor:d6808fe9c0ac0a98

-- LOW (1) --
  [tool_missing       ] ss not installed - connection check skipped

--------------------------------------------------------------
  high=4  medium=0  low=1
  HIGH findings present - investigate before acting on anything else.
```

The `new_` prefix means the item is absent from the baseline. Everything else
fires on its own merits.

---

## Speed and system impact

CPU and memory stay low. The cost is **reading `/proc` and querying Docker**.

The slow part is `docker diff`, which walks each container's writable layer.
With a dozen containers that's a few seconds; with many more it dominates the
runtime.

Rough timings: under a second on a host with no Docker, a few seconds on a
typical droplet.

On a busy production machine, run it politely:

```bash
sudo nice -n 19 ionice -c3 /usr/local/bin/compromise_check.sh
```

---

## Scheduling

Hourly, alerting only when something appears:

```bash
sudo tee /etc/cron.d/compromise-check >/dev/null <<'EOF'
0 * * * * root /usr/local/bin/compromise_check.sh -q >> /var/log/compromise-check.log 2>&1
EOF
```

For a Slack alert on HIGH findings only:

```bash
#!/usr/bin/env bash
OUT=$(/usr/local/bin/compromise_check.sh --json)
[ $? -eq 2 ] && curl -sX POST -H 'Content-type: application/json' \
  --data "{\"text\":\"🔴 $(hostname): \`\`\`$(echo "$OUT" | jq -c .)\`\`\`\"}" \
  "$SLACK_WEBHOOK"
```

### With an AI triage step

The script decides what is anomalous; a model only explains and prioritises.
Keeping detection deterministic makes it free, auditable, and free of false
negatives introduced by prompt drift.

```
Schedule (hourly)
  → SSH: compromise_check.sh --json
  → IF exit code 2
  → HTTP: api.anthropic.com/v1/messages
  → Slack
```

Prompt that works well:

> You are reviewing automated security scan output from a Linux droplet. For
> each finding, state what it is in plain language, whether it is likely benign
> or worth investigating, and the single next command to run. Be specific about
> which findings can be ignored — false positives cost attention. Do not
> recommend destructive actions. If a finding indicates active compromise, say
> so plainly at the top.

Give the SSH account read-only access, scoped in sudoers to this one command:

```
secscan ALL=(root) NOPASSWD: /usr/local/bin/compromise_check.sh
```

Never let the workflow run remediation.

---

## Common findings, and what to do next

The script only diagnoses — **you** decide what to remove. Frequent causes:

- **`deleted_exe`** — check the process start time and `/var/log/apt/history.log`
  first. A service upgraded but not yet restarted shows `(deleted)`
  legitimately. If it's not a package upgrade, treat it as malware: capture
  `ss -tnp` for the PID and copy `/proc/<pid>/exe` **before** killing anything.
  The binary exists only while the process lives.
- **`hidden_tmp_file`** — read it before assuming the worst. Some are build
  artifacts; some are a few lines of JavaScript opening a reverse shell.
- **`container_hidden_tmp`** — same, via
  `docker cp <container>:/tmp/. /root/check/` and check the file mtimes.
- **`new_ssh_key`** — ask the person named in the key comment. Silence is the
  answer you're looking for.
- **`high_mem` / `high_cpu`** — usually legitimate on a database or monitoring
  host. Raise the thresholds rather than ignoring the check.

---

## Tuning out the noise

A scanner nobody reads is worse than none.

**Re-baseline after legitimate changes.** New container, new teammate key, new
service? Run `--update-baseline` so they stop appearing.

**Raise thresholds** on hosts that legitimately run hot. Grafana, Prometheus,
Loki and headless Chrome will all trip the defaults.

---

## Limitations

- Detects **planted artifacts**, not the exploit that planted them. For entry
  vectors you need web server access logging — a separate fix.
- Only inspects containers Docker knows about. Podman and containerd-direct
  workloads are not covered.
- A careful attacker with root can hide from any host-based tool. This catches
  commodity malware, which is what actually turns up.
- `--update-baseline` on an already-compromised host bakes the intruder in as
  normal. Baseline from a known-good state.
- `comm` is truncated to 15 characters by the kernel, so name comparisons are
  prefix-based and a determined mimic can evade check 5.
