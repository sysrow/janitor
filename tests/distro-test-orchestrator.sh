#!/bin/bash
# Orchestrator: deploy janitor + tests to a set of remote hosts and run them.
#
# Host addresses are NOT stored in this repository. Copy tests/hosts.env.example
# to tests/hosts.env (git-ignored) and fill in your own targets.
#
# Run from the repo root, after `cargo build --release`.
set -uo pipefail

BINARY="target/release/janitor"
SMOKE="tests/smoke-test.sh"
XDIST="tests/cross-distro-test.sh"
RESULTS="test-results"
HOSTS_ENV="${JANITOR_HOSTS_ENV:-tests/hosts.env}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
SSH_USER="${JANITOR_SSH_USER:-root}"

declare -A HOSTS=()
declare -A FAMILY=()

if [[ ! -f "$HOSTS_ENV" ]]; then
    cat >&2 <<EOF
ERROR: $HOSTS_ENV not found.

Copy tests/hosts.env.example to $HOSTS_ENV and list your own test hosts.
That file is git-ignored on purpose: host addresses do not belong in the
repository. Override its location with \$JANITOR_HOSTS_ENV.
EOF
    exit 1
fi
# shellcheck disable=SC1090
source "$HOSTS_ENV"

if [[ ${#HOSTS[@]} -eq 0 ]]; then
    echo "ERROR: $HOSTS_ENV defines no hosts." >&2
    exit 1
fi

if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: $BINARY not found. Run 'cargo build --release' first." >&2
    exit 1
fi

# Stale results from an earlier run would otherwise be counted as this run's,
# turning a host that never reported into a silent pass.
rm -rf "${RESULTS:?}"
mkdir -p "$RESULTS"

# Stable ordering so the summary table is comparable between runs.
mapfile -t NAMES < <(printf '%s\n' "${!HOSTS[@]}" | sort)

# Run a phase across every host in parallel and fail the script if any job
# fails. `wait` without capturing per-job status was how an SSH error used to
# vanish from the final verdict.
run_phase() {
    local label=$1 fn=$2
    local -a pids=() jobnames=()
    local rc=0
    for name in "${NAMES[@]}"; do
        "$fn" "$name" &
        pids+=($!)
        jobnames+=("$name")
    done
    local i
    for i in "${!pids[@]}"; do
        if ! wait "${pids[$i]}"; then
            echo "  [${jobnames[$i]}] $label FAILED"
            rc=1
        fi
    done
    return $rc
}

ssh_host() {
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$1" "$2"
}

# ── Phase 1: Deploy ──────────────────────────────────────────────
deploy() {
    local name=$1 ip="${HOSTS[$1]}"
    echo "  [$name] deploying ..."
    ssh_host "$ip" 'mkdir -p /opt/janitor-test' || return 1
    scp "${SSH_OPTS[@]}" "$BINARY" "$SSH_USER@$ip:/usr/local/bin/janitor" || return 1
    scp "${SSH_OPTS[@]}" "$SMOKE" "$SSH_USER@$ip:/opt/janitor-test/smoke-test.sh" || return 1
    scp "${SSH_OPTS[@]}" "$XDIST" "$SSH_USER@$ip:/opt/janitor-test/cross-distro-test.sh" || return 1
    ssh_host "$ip" 'chmod +x /usr/local/bin/janitor /opt/janitor-test/*.sh' || return 1
    echo "  [$name] deployed."
}

# ── Phase 2: Provision ───────────────────────────────────────────
provision() {
    local name=$1 ip="${HOSTS[$1]}" fam="${FAMILY[$1]:-debian}"
    echo "  [$name] provisioning ($fam) ..."
    if [[ "$fam" == "rhel" ]]; then
        ssh_host "$ip" 'dnf install -y acl shadow-utils util-linux e2fsprogs jq bash coreutils 2>&1 | tail -1' || return 1
    else
        ssh_host "$ip" 'apt-get update -qq && apt-get install -y -qq acl bsdextrautils util-linux passwd e2fsprogs jq bash coreutils 2>&1 | tail -1' || return 1
    fi
    ssh_host "$ip" 'echo "verify:"; rc=0; for c in setfacl getfacl lsattr chattr groupadd gpasswd runuser script jq; do command -v $c >/dev/null && echo "  ok $c" || { echo "  MISSING $c"; rc=1; }; done; exit $rc' || return 1
    echo "  [$name] provisioned."
}

# ── Phases 3 & 4: Run the suites ────────────────────────────────
run_suite() {
    local name=$1 suite=$2 script=$3 ip="${HOSTS[$1]}"
    echo "  [$name] running $script ..."
    ssh_host "$ip" "bash /opt/janitor-test/$script" > "$RESULTS/${name}-${suite}.txt" 2>&1
    local rc=$?
    local summary
    summary=$(tail -5 "$RESULTS/${name}-${suite}.txt" | grep -E 'PASSED|FAILED|RESULTS|passed|failed' || echo "unknown")
    if [[ $rc -eq 0 ]]; then
        echo "  [$name] ${suite^^} OK — $summary"
    else
        echo "  [$name] ${suite^^} FAIL (exit $rc) — $summary"
    fi
    return $rc
}

run_smoke() { run_suite "$1" smoke smoke-test.sh; }
run_xdist() { run_suite "$1" xdist cross-distro-test.sh; }

OVERALL=0

echo "═══ Phase 1: Deploy to ${#NAMES[@]} host(s) ═══"
run_phase deploy deploy || OVERALL=1
echo

echo "═══ Phase 2: Install dependencies ═══"
run_phase provision provision || OVERALL=1
echo

echo "═══ Phase 3: Smoke tests ═══"
run_phase smoke run_smoke || OVERALL=1
echo

echo "═══ Phase 4: Cross-distro tests ═══"
run_phase xdist run_xdist || OVERALL=1
echo

# ── Phase 5: Summary ────────────────────────────────────────────
echo "═══ Phase 5: Results Summary ═══"
echo
printf "%-14s %-8s %s\n" "HOST" "SUITE" "RESULT"
printf "%-14s %-8s %s\n" "──────────" "──────" "──────────────────────"
TOTAL_FAIL=0
for name in "${NAMES[@]}"; do
    for suite in smoke xdist; do
        f="$RESULTS/${name}-${suite}.txt"
        if [[ ! -f "$f" ]]; then
            # No output at all means the run never happened. That is a
            # failure, not an absence of failures.
            printf "%-14s %-8s \e[33m%s\e[0m\n" "$name" "$suite" "no results (counted as failure)"
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
            OVERALL=1
            continue
        fi
        P=$(grep -c '^\s*PASS ' "$f" || true)
        F=$(grep -c '^\s*FAIL ' "$f" || true)
        TOTAL_FAIL=$((TOTAL_FAIL + F))
        if [[ $P -eq 0 ]]; then
            # A run that asserted nothing proves nothing.
            printf "%-14s %-8s \e[31m%s\e[0m\n" "$name" "$suite" "0 assertions ran (counted as failure)"
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
            OVERALL=1
        elif [[ $F -eq 0 ]]; then
            printf "%-14s %-8s \e[32m%s passed, %s failed\e[0m\n" "$name" "$suite" "$P" "$F"
        else
            printf "%-14s %-8s \e[31m%s passed, %s failed\e[0m\n" "$name" "$suite" "$P" "$F"
        fi
    done
done
echo
echo "Full results in $RESULTS/"

# ── Phase 6: Show any failures ───────────────────────────────────
if [[ $TOTAL_FAIL -gt 0 ]]; then
    echo
    echo "═══ FAILURES ═══"
    for f in "$RESULTS"/*.txt; do
        [[ -f "$f" ]] || continue
        FAILS=$(grep '^\s*FAIL ' "$f" || true)
        if [[ -n "$FAILS" ]]; then
            echo
            echo "--- $(basename "$f") ---"
            echo "$FAILS"
        fi
    done
    echo
    echo "Total failures across all hosts: $TOTAL_FAIL"
    exit 1
fi

if [[ $OVERALL -ne 0 ]]; then
    echo
    echo "Tests reported no failures, but at least one phase errored out — see above."
    exit 1
fi

echo
echo "ALL TESTS PASSED on ${#NAMES[@]} host(s)."
exit 0
