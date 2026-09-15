#!/usr/bin/env bash
# Read-only discovery for Tencent Cloud agents on a Linux host.
# It writes nothing on the inspected host and prints a line-oriented report.

set -u

section() {
    printf '\n===== %s =====\n' "$1"
}

run_if_available() {
    local command_name="$1"
    shift
    if command -v "$command_name" >/dev/null 2>&1; then
        "$command_name" "$@" 2>&1 || true
    else
        printf 'UNAVAILABLE: %s\n' "$command_name"
    fi
}

agent_pattern='tencent|qcloud|tat_agent|tat-agent|barad|ydservice|stargate|sgagent|agenttools|cloudmonitor'

section "COLLECTION METADATA"
printf 'collected_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'hostname=%s\n' "$(hostname 2>/dev/null || printf unknown)"
printf 'collector_user=%s\n' "$(id -un 2>/dev/null || printf unknown)"
printf 'kernel=%s\n' "$(uname -srmo 2>/dev/null || printf unknown)"

section "OS RELEASE"
if [[ -r /etc/os-release ]]; then
    sed -n 's/^\(ID\|VERSION_ID\|PRETTY_NAME\)=/\1=/p' /etc/os-release
fi

section "MATCHING PROCESSES"
ps -eo user=,uid=,pid=,ppid=,lstart=,etimes=,stat=,comm=,args= 2>/dev/null \
    | grep -Eia "$agent_pattern" \
    | grep -Ev 'grep|discover-tencent-agents' || true

section "MATCHING SYSTEMD UNITS"
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null \
        | grep -Eia "$agent_pattern" || true
    printf '%s\n' '-- installed unit files --'
    systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null \
        | grep -Eia "$agent_pattern" || true
else
    printf 'UNAVAILABLE: systemctl\n'
fi

section "MATCHING INSTALLED PACKAGES"
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | grep -Eia "$agent_pattern" || true
elif command -v rpm >/dev/null 2>&1; then
    rpm -qa 2>/dev/null | grep -Eia "$agent_pattern" || true
else
    printf 'UNAVAILABLE: dpkg-query/rpm\n'
fi

section "PROCESS IDENTITIES"
matched_pids="$(pgrep -f "$agent_pattern" 2>/dev/null || true)"
if [[ -z "$matched_pids" ]]; then
    printf 'NO_MATCHING_PIDS\n'
else
    while IFS= read -r pid; do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        [[ -r "/proc/$pid/status" ]] || continue
        printf '\n--- pid=%s ---\n' "$pid"
        printf 'exe=%s\n' "$(readlink -f "/proc/$pid/exe" 2>/dev/null || printf unavailable)"
        printf 'cwd=%s\n' "$(readlink -f "/proc/$pid/cwd" 2>/dev/null || printf unavailable)"
        tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true
        printf '\n'
        grep -E '^(Name|State|Pid|PPid|Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp|Threads):' \
            "/proc/$pid/status" 2>/dev/null || true
        printf 'cgroup='; tr '\n' ';' < "/proc/$pid/cgroup" 2>/dev/null || true; printf '\n'
        executable="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
        if [[ -n "$executable" && -r "$executable" ]]; then
            sha256sum "$executable" 2>/dev/null || true
            stat -Lc 'mode=%A owner=%U group=%G size=%s mtime=%y path=%n' "$executable" 2>/dev/null || true
        fi
        printf '%s\n' '-- open file paths (metadata only) --'
        find "/proc/$pid/fd" -maxdepth 1 -type l -printf '%f\t%l\n' 2>/dev/null | sort -n || true
    done <<< "$matched_pids"
fi

section "NETWORK SOCKETS"
if command -v ss >/dev/null 2>&1; then
    ss -H -tunap 2>/dev/null | grep -Eia "$agent_pattern" || true
else
    printf 'UNAVAILABLE: ss\n'
fi

section "AGENTREINS KERNEL SENSOR STATUS"
ps -eo user=,pid=,ppid=,args= 2>/dev/null | grep -Ei '[k]ubearmor' || true
run_if_available karmor probe

section "COLLECTION LIMITATIONS"
printf '%s\n' \
    'This snapshot does not capture historical exec events.' \
    'TLS payload content is not inspected.' \
    'Root privileges may be required to resolve all file descriptors and sockets.'
