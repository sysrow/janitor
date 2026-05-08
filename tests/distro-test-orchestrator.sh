#!/bin/bash
# Orchestrator: deploy janitor + tests to 6 DigitalOcean droplets and run them.
# Execute from the repo root on tristram.civ.zcu.cz.
set -uo pipefail

BINARY="target/release/janitor"
SMOKE="tests/smoke-test.sh"
XDIST="tests/cross-distro-test.sh"
RESULTS="test-results"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"

declare -A HOSTS=(
    [centos]="161.35.216.10"
    [alma]="198.211.97.90"
    [rocky1]="147.182.134.185"
    [ubuntu-new]="157.230.10.168"
    [ubuntu-lts]="165.227.132.147"
    [rocky2]="161.35.31.160"
)

declare -A FAMILY=(
    [centos]="rhel"
    [alma]="rhel"
    [rocky1]="rhel"
    [ubuntu-new]="debian"
    [ubuntu-lts]="debian"
    [rocky2]="rhel"
)

if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: $BINARY not found. Run 'cargo build --release' first."
    exit 1
fi

mkdir -p "$RESULTS"

run_on() {
    local name=$1 ip=$2
    ssh $SSH_OPTS root@"$ip" "$3"
}

# ── Phase 1: Deploy ──────────────────────────────────────────────
echo "═══ Phase 1: Deploy to all hosts ═══"
for name in "${!HOSTS[@]}"; do
    ip="${HOSTS[$name]}"
    (
        echo "  [$name] deploying to $ip ..."
        ssh $SSH_OPTS root@"$ip" 'mkdir -p /opt/janitor-test'
        scp $SSH_OPTS "$BINARY" root@"$ip":/usr/local/bin/janitor
        scp $SSH_OPTS "$SMOKE" root@"$ip":/opt/janitor-test/smoke-test.sh
        scp $SSH_OPTS "$XDIST" root@"$ip":/opt/janitor-test/cross-distro-test.sh
        ssh $SSH_OPTS root@"$ip" 'chmod +x /usr/local/bin/janitor /opt/janitor-test/*.sh'
        echo "  [$name] deployed."
    ) &
done
wait
echo

# ── Phase 2: Provision ───────────────────────────────────────────
echo "═══ Phase 2: Install dependencies ═══"
for name in "${!HOSTS[@]}"; do
    ip="${HOSTS[$name]}"
    fam="${FAMILY[$name]}"
    (
        echo "  [$name] provisioning ($fam) ..."
        if [[ "$fam" == "rhel" ]]; then
            ssh $SSH_OPTS root@"$ip" 'dnf install -y acl shadow-utils util-linux e2fsprogs jq bash coreutils 2>&1 | tail -1'
        else
            ssh $SSH_OPTS root@"$ip" 'apt-get update -qq && apt-get install -y -qq acl bsdextrautils util-linux passwd e2fsprogs jq bash coreutils 2>&1 | tail -1'
        fi
        # verify
        ssh $SSH_OPTS root@"$ip" 'echo "verify:"; for c in setfacl getfacl lsattr chattr groupadd gpasswd runuser script jq; do command -v $c >/dev/null && echo "  ok $c" || echo "  MISSING $c"; done'
        echo "  [$name] provisioned."
    ) &
done
wait
echo

# ── Phase 3: Run smoke tests ────────────────────────────────────
echo "═══ Phase 3: Smoke tests ═══"
for name in "${!HOSTS[@]}"; do
    ip="${HOSTS[$name]}"
    (
        echo "  [$name] running smoke-test.sh ..."
        ssh $SSH_OPTS root@"$ip" 'bash /opt/janitor-test/smoke-test.sh' \
            > "$RESULTS/${name}-smoke.txt" 2>&1
        RC=$?
        SUMMARY=$(tail -5 "$RESULTS/${name}-smoke.txt" | grep -E 'PASSED|FAILED' || echo "unknown")
        if [[ $RC -eq 0 ]]; then
            echo "  [$name] SMOKE OK — $SUMMARY"
        else
            echo "  [$name] SMOKE FAIL (exit $RC) — $SUMMARY"
        fi
    ) &
done
wait
echo

# ── Phase 4: Run cross-distro tests ─────────────────────────────
echo "═══ Phase 4: Cross-distro tests ═══"
for name in "${!HOSTS[@]}"; do
    ip="${HOSTS[$name]}"
    (
        echo "  [$name] running cross-distro-test.sh ..."
        ssh $SSH_OPTS root@"$ip" 'bash /opt/janitor-test/cross-distro-test.sh' \
            > "$RESULTS/${name}-xdist.txt" 2>&1
        RC=$?
        SUMMARY=$(tail -5 "$RESULTS/${name}-xdist.txt" | grep -E 'RESULTS|passed|failed' || echo "unknown")
        if [[ $RC -eq 0 ]]; then
            echo "  [$name] XDIST OK — $SUMMARY"
        else
            echo "  [$name] XDIST FAIL (exit $RC) — $SUMMARY"
        fi
    ) &
done
wait
echo

# ── Phase 5: Summary ────────────────────────────────────────────
echo "═══ Phase 5: Results Summary ═══"
echo
printf "%-14s %-8s %s\n" "HOST" "SUITE" "RESULT"
printf "%-14s %-8s %s\n" "──────────" "──────" "──────────────────────"
for name in centos alma rocky1 ubuntu-new ubuntu-lts rocky2; do
    for suite in smoke xdist; do
        f="$RESULTS/${name}-${suite}.txt"
        if [[ -f "$f" ]]; then
            P=$(grep -c '^\s*PASS ' "$f" || true)
            F=$(grep -c '^\s*FAIL ' "$f" || true)
            if [[ $F -eq 0 ]]; then
                printf "%-14s %-8s \e[32m%s passed, %s failed\e[0m\n" "$name" "$suite" "$P" "$F"
            else
                printf "%-14s %-8s \e[31m%s passed, %s failed\e[0m\n" "$name" "$suite" "$P" "$F"
            fi
        else
            printf "%-14s %-8s \e[33mno results\e[0m\n" "$name" "$suite"
        fi
    done
done
echo
echo "Full results in $RESULTS/"

# ── Phase 6: Show any failures ───────────────────────────────────
TOTAL_FAIL=0
for f in "$RESULTS"/*.txt; do
    FC=$(grep -c '^\s*FAIL ' "$f" 2>/dev/null || true)
    TOTAL_FAIL=$((TOTAL_FAIL + FC))
done

if [[ $TOTAL_FAIL -gt 0 ]]; then
    echo
    echo "═══ FAILURES ═══"
    for f in "$RESULTS"/*.txt; do
        FAILS=$(grep '^\s*FAIL ' "$f" 2>/dev/null || true)
        if [[ -n "$FAILS" ]]; then
            echo
            echo "--- $(basename "$f") ---"
            echo "$FAILS"
        fi
    done
    echo
    echo "Total failures across all hosts: $TOTAL_FAIL"
    exit 1
else
    echo
    echo "ALL TESTS PASSED on all 6 hosts."
    exit 0
fi
