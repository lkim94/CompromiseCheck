#!/usr/bin/env bash
# compromise_check.sh - READ-ONLY compromise detection for Ubuntu + Docker hosts
#
# Detects the patterns behind real intrusions: processes running from deleted
# binaries, hidden files in world-writable dirs, unexpected container
# filesystem changes, new persistence, and changed trust anchors.
#
# Only reads. The single exception is its own state directory, used to store a
# baseline so it can report CHANGES rather than the same list every night.
# It never touches Docker containers, never runs docker exec, never remediates.
#
# Usage:
#   sudo ./compromise_check.sh [options]
#
#   -j, --json            emit JSON instead of text (for n8n / automation)
#   -s, --state DIR       baseline directory (default /var/lib/compromise-check)
#       --no-baseline     report everything, don't compare against baseline
#       --update-baseline accept current state as the new normal, then exit
#       --mem-threshold N flag processes above N% memory (default 25)
#       --cpu-threshold N flag processes above N% CPU (default 80)
#   -q, --quiet           only output if something was found
#   -h, --help            show this help
#
# Exit codes:
#   0  nothing found
#   1  low/medium findings
#   2  HIGH findings - investigate now
#   3  script error

set -uo pipefail

STATE_DIR="/var/lib/compromise-check"
FORMAT="text"
USE_BASELINE=1
UPDATE_BASELINE=0
QUIET=0
MEM_THRESHOLD=25
CPU_THRESHOLD=80
HOSTNAME_S="$(hostname 2>/dev/null || echo unknown)"
NOW="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    -j|--json)          FORMAT="json";        shift ;;
    -s|--state)         STATE_DIR="${2:?}";   shift 2 ;;
    --no-baseline)      USE_BASELINE=0;       shift ;;
    --update-baseline)  UPDATE_BASELINE=1;    shift ;;
    --mem-threshold)    MEM_THRESHOLD="${2:?}"; shift 2 ;;
    --cpu-threshold)    CPU_THRESHOLD="${2:?}"; shift 2 ;;
    -q|--quiet)         QUIET=1;              shift ;;
    -h|--help)          usage ;;
    *) echo "unknown option: $1" >&2; exit 3 ;;
  esac
done

[ "$(id -u)" -ne 0 ] && {
  echo "!! Not root. Most checks need root. Try: sudo $0" >&2
}

# ---------------------------------------------------------------- findings
# Findings accumulate as TAB-separated: SEVERITY \t CHECK \t DETAIL
FINDINGS_FILE="$(mktemp)"
CURRENT_STATE="$(mktemp)"
trap 'rm -f "$FINDINGS_FILE" "$CURRENT_STATE"' EXIT

finding() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$FINDINGS_FILE"; }

# state lines are compared against the baseline; format: CHECK \t VALUE
state()   { printf '%s\t%s\n' "$1" "$2" >> "$CURRENT_STATE"; }

have() { command -v "$1" >/dev/null 2>&1; }

docker_ok=0
if have docker && docker info >/dev/null 2>&1; then docker_ok=1; fi

# ===========================================================================
# CHECK 1 - processes running from a deleted binary
# ===========================================================================
# The single strongest signal. Malware writes a binary, starts it, then
# unlinks it so nothing can find or scan the file. Legitimate software does
# not do this. Package upgrades can leave a short-lived exception, so the
# process start time is reported for context.
check_deleted_exe() {
  local pid exe comm start
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    case "$exe" in
      *"(deleted)")
        comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo '?')
        start=$(stat -c %y "/proc/$pid" 2>/dev/null | cut -d'.' -f1)
        finding HIGH deleted_exe "pid=$pid comm=$comm exe=$exe seen=$start"
        ;;
    esac
  done
}

# ===========================================================================
# CHECK 2 - hidden files in world-writable directories (host)
# ===========================================================================
# Attackers favour /tmp, /var/tmp and /dev/shm because any process can write
# there. A leading dot keeps the file out of a plain `ls`.
check_hidden_tmp() {
  local d f sz
  for d in /tmp /var/tmp /dev/shm; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      case "$f" in
        */.ICE-unix*|*/.X11-unix*|*/.XIM-unix*|*/.font-unix*|*/.Test-unix*) continue ;;
      esac
      sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
      finding HIGH hidden_tmp_file "$f (${sz} bytes)"
    done < <(find "$d" -maxdepth 2 -name '.*' -type f 2>/dev/null)
  done
}

# ===========================================================================
# CHECK 3 - container writable-layer changes under /tmp
# ===========================================================================
# Reads container metadata from the host. No docker exec, nothing is started
# or run inside any container. This is what surfaced both real intrusions.
check_container_tmp() {
  [ "$docker_ok" -eq 1 ] || return 0
  local cid name line path
  for cid in $(docker ps -aq 2>/dev/null); do
    name=$(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | tr -d '/')
    [ -z "$name" ] && name="$cid"
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      path="${line#? }"
      case "$path" in
        /tmp) continue ;;                       # dir itself changing is normal
        /tmp/.*) finding HIGH container_hidden_tmp "$name: $line" ;;
        /tmp/*)  finding LOW  container_tmp_file   "$name: $line" ;;
      esac
    done < <(docker diff "$cid" 2>/dev/null | grep -E '^[ACD] /tmp')
  done
}

# ===========================================================================
# CHECK 4 - resource hogs
# ===========================================================================
# Miners are quiet in every way except consumption. Thresholds are tunable
# because a legitimate database or build box will trip low ones.
check_resource_hogs() {
  local pid pcpu pmem user cmd
  while read -r pid pcpu pmem user cmd; do
    [ -z "$pid" ] && continue
    awk -v c="$pcpu" -v t="$CPU_THRESHOLD" 'BEGIN{exit !(c+0 > t+0)}' \
      && finding MEDIUM high_cpu "pid=$pid cpu=${pcpu}% user=$user cmd=$(echo "$cmd" | cut -c1-80)"
    awk -v m="$pmem" -v t="$MEM_THRESHOLD" 'BEGIN{exit !(m+0 > t+0)}' \
      && finding MEDIUM high_mem "pid=$pid mem=${pmem}% user=$user cmd=$(echo "$cmd" | cut -c1-80)"
  done < <(ps -eo pid=,pcpu=,pmem=,user=,args= --sort=-pmem 2>/dev/null | head -25)
}

# ===========================================================================
# CHECK 5 - name/binary mismatch
# ===========================================================================
# A process calling itself one thing while running another. The devtx miner
# advertised "redis-server" while executing /tmp/.kworkerd.
check_name_mismatch() {
  local pid comm exe base
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    comm=$(cat "/proc/$pid/comm" 2>/dev/null) || continue
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    [ -z "$exe" ] && continue
    base=$(basename "${exe% (deleted)}")
    # kernel threads have no exe and are already skipped by the readlink test
    case "$exe" in
      /tmp/*|/var/tmp/*|/dev/shm/*)
        finding HIGH exec_from_tmp "pid=$pid comm=$comm exe=$exe" ;;
    esac
    # comm is truncated to 15 chars by the kernel, so compare prefixes
    if [ "${base:0:15}" != "${comm:0:15}" ] \
       && [ "${comm:0:15}" != "${base:0:15}" ]; then
      case "$comm" in
        node|python3|sh|bash|java|ruby|perl|php|dotnet|mono|electron|deno|bun) ;;
        *) state name_mismatch "$comm:$base" ;;
      esac
    fi
  done
}

# ===========================================================================
# CHECK 6 - outbound connections
# ===========================================================================
# Recorded as state, so the baseline learns what is normal and only new
# destinations are reported. Private ranges are ignored.
check_connections() {
  have ss || { finding LOW tool_missing "ss not installed - connection check skipped"; return 0; }
  local line raddr rip
  while read -r line; do
    rip=$(echo "$line" | awk '{print $5}' | sed 's/:[0-9]*$//' | tr -d '[]')
    [ -z "$rip" ] && continue
    case "$rip" in
      127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|169.254.*|::1|fe80:*|*"*"*) continue ;;
    esac
    raddr=$(echo "$line" | awk '{print $5}')
    state outbound_peer "$raddr"
  done < <(ss -tn state established 2>/dev/null | tail -n +2)
}

# ===========================================================================
# CHECK 7 - listening ports
# ===========================================================================
check_listening() {
  have ss || return 0
  local line
  while read -r line; do
    [ -z "$line" ] && continue
    state listening "$(echo "$line" | awk '{print $4}')"
  done < <(ss -lntu 2>/dev/null | tail -n +2)
}

# ===========================================================================
# CHECK 8 - persistence: cron, timers, services
# ===========================================================================
check_persistence() {
  local f
  for f in /var/spool/cron/crontabs/* /etc/cron.d/* /etc/crontab; do
    [ -f "$f" ] || continue
    state cron_hash "$f:$(sha256sum "$f" 2>/dev/null | cut -c1-16)"
  done
  for f in /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [ -f "$f" ] || continue
    case "$f" in *.placeholder) continue ;; esac
    state cron_script "$(basename "$f")"
  done
  if have systemctl; then
    while read -r unit; do
      [ -z "$unit" ] && continue
      state timer "$unit"
    done < <(systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $(NF-1)}' | grep -E '\.timer$' | sort -u)
    while read -r unit; do
      [ -z "$unit" ] && continue
      state service "$unit"
    done < <(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | sort -u)
  fi
}

# ===========================================================================
# CHECK 9 - trust anchors: SSH keys, accounts, sudoers
# ===========================================================================
# Fingerprints, not key material. Nothing secret is written to the state file.
check_trust() {
  local f fp
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$f" ] || continue
    while read -r _ fp comment _; do
      [ -z "$fp" ] && continue
      state ssh_key "$f:$fp:${comment:-nocomment}"
    done < <(ssh-keygen -lf "$f" 2>/dev/null)
  done
  [ -f /etc/passwd ] && \
    while IFS=: read -r user _ uid _ _ _ shell; do
      case "$shell" in
        */nologin|*/false|"") continue ;;
      esac
      state login_account "$user:$uid:$shell"
    done < /etc/passwd
  [ -f /etc/sudoers ] && state sudoers_hash "$(sha256sum /etc/sudoers 2>/dev/null | cut -c1-16)"
  for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    state sudoers_hash "$(basename "$f"):$(sha256sum "$f" 2>/dev/null | cut -c1-16)"
  done
}

# ===========================================================================
# CHECK 10 - recently modified files in sensitive locations
# ===========================================================================
check_recent_writes() {
  local f
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    finding MEDIUM recent_write "$f modified in last 24h"
  done < <(find /etc/systemd/system /usr/local/bin /root -maxdepth 2 -type f -mtime -1 2>/dev/null | head -20)
}

# ===========================================================================
# CHECK 11 - container inventory and restart storms
# ===========================================================================
check_containers() {
  [ "$docker_ok" -eq 1 ] || return 0
  local cid name image restarts
  for cid in $(docker ps -aq 2>/dev/null); do
    name=$(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | tr -d '/')
    image=$(docker inspect -f '{{.Config.Image}}' "$cid" 2>/dev/null)
    restarts=$(docker inspect -f '{{.RestartCount}}' "$cid" 2>/dev/null)
    state container "$name:$image"
    if [ "${restarts:-0}" -gt 20 ] 2>/dev/null; then
      finding MEDIUM restart_storm "$name has restarted $restarts times"
    fi
  done
}

# ===========================================================================
# run checks
# ===========================================================================
check_deleted_exe
check_hidden_tmp
check_container_tmp
check_resource_hogs
check_name_mismatch
check_connections
check_listening
check_persistence
check_trust
check_recent_writes
check_containers

sort -u -o "$CURRENT_STATE" "$CURRENT_STATE"

# ===========================================================================
# baseline comparison
# ===========================================================================
BASELINE="$STATE_DIR/baseline.tsv"

if [ "$UPDATE_BASELINE" -eq 1 ]; then
  mkdir -p "$STATE_DIR" || { echo "cannot write $STATE_DIR" >&2; exit 3; }
  cp "$CURRENT_STATE" "$BASELINE"
  chmod 600 "$BASELINE"
  echo "Baseline updated: $BASELINE ($(wc -l < "$BASELINE") entries)"
  exit 0
fi

if [ "$USE_BASELINE" -eq 1 ] && [ -f "$BASELINE" ]; then
  while IFS=$'\t' read -r check value; do
    [ -z "$check" ] && continue
    case "$check" in
      ssh_key|login_account|sudoers_hash|cron_hash|cron_script|timer|service)
        finding HIGH "new_$check" "$value" ;;
      outbound_peer|listening|container|name_mismatch)
        finding MEDIUM "new_$check" "$value" ;;
      *) finding LOW "new_$check" "$value" ;;
    esac
  done < <(comm -13 "$BASELINE" "$CURRENT_STATE")
elif [ "$USE_BASELINE" -eq 1 ]; then
  finding LOW no_baseline "no baseline at $BASELINE - run with --update-baseline once the host is known good"
fi

# ===========================================================================
# output
# ===========================================================================
# grep -c prints 0 and exits 1 on no match; `|| echo 0` would emit a second line
HIGH_N=$(grep -c '^HIGH' "$FINDINGS_FILE" 2>/dev/null) || HIGH_N=0
MED_N=$(grep -c '^MEDIUM' "$FINDINGS_FILE" 2>/dev/null) || MED_N=0
LOW_N=$(grep -c '^LOW' "$FINDINGS_FILE" 2>/dev/null) || LOW_N=0
HIGH_N=${HIGH_N:-0}; MED_N=${MED_N:-0}; LOW_N=${LOW_N:-0}
TOTAL_N=$((HIGH_N + MED_N + LOW_N))

if [ "$QUIET" -eq 1 ] && [ "$TOTAL_N" -eq 0 ]; then exit 0; fi

if [ "$FORMAT" = "json" ]; then
  printf '{"host":"%s","timestamp":"%s","summary":{"high":%d,"medium":%d,"low":%d},"findings":[' \
    "$HOSTNAME_S" "$NOW" "$HIGH_N" "$MED_N" "$LOW_N"
  first=1
  while IFS=$'\t' read -r sev check detail; do
    [ -z "$sev" ] && continue
    detail=$(printf '%s' "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g')
    [ "$first" -eq 0 ] && printf ','
    printf '{"severity":"%s","check":"%s","detail":"%s"}' "$sev" "$check" "$detail"
    first=0
  done < <(sort "$FINDINGS_FILE")
  printf ']}\n'
else
  echo "=============================================================="
  echo " compromise_check  $HOSTNAME_S  $NOW"
  echo "=============================================================="
  if [ "$TOTAL_N" -eq 0 ]; then
    echo "  Nothing found. $( [ -f "$BASELINE" ] && echo "Matches baseline." )"
  else
    for sev in HIGH MEDIUM LOW; do
      n=$(grep -c "^$sev" "$FINDINGS_FILE" 2>/dev/null) || n=0
      [ "$n" -eq 0 ] && continue
      echo
      echo "-- $sev ($n) --"
      grep "^$sev" "$FINDINGS_FILE" | while IFS=$'\t' read -r _ check detail; do
        printf '  [%-24s] %s\n' "$check" "$detail"
      done
    done
    echo
    echo "--------------------------------------------------------------"
    echo "  high=$HIGH_N  medium=$MED_N  low=$LOW_N"
    if [ "$HIGH_N" -gt 0 ]; then
      echo "  HIGH findings present - investigate before acting on anything else."
    fi
  fi
  echo
  echo "Read-only. Nothing was modified."
fi

if [ "$HIGH_N" -gt 0 ]; then exit 2; fi
if [ "$TOTAL_N" -gt 0 ]; then exit 1; fi
exit 0
