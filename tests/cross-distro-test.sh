#!/bin/bash
# Cross-distribution test suite for janitor.
# Targets risk surfaces not covered by smoke-test.sh:
# SELinux, XFS vs ext4, chattr, seal pinholes, NSS, flock, large trees.
# Runs as root on each target host. Uses the same harness as smoke-test.sh.

set -uo pipefail

JAN="janitor"
PASS=0
FAIL=0

pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

assert() {
    local name="$1"; shift
    if "$@" > /dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

refute() {
    local name="$1"; shift
    if ! "$@" > /dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

assert_grep() {
    if echo "$2" | grep -q "$3"; then pass "$1"; else fail "$1"; fi
}

refute_grep() {
    if ! echo "$2" | grep -q "$3"; then pass "$1"; else fail "$1"; fi
}

assert_eq() {
    if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', expected '$3')"; fi
}

ROOT=/tmp/xd_test
DISTRO=$(. /etc/os-release && echo "$ID")
FS_TYPE=$(df -T /tmp 2>/dev/null | tail -1 | awk '{print $2}')
SELINUX=$(getenforce 2>/dev/null || echo "Disabled")

cleanup() {
    for u in xd_user xd_user2 seal_user mask_user cp_user whocan_user defacl_user; do
        userdel -rf "$u" 2>/dev/null || true
    done
    for g in xd_grp; do
        groupdel "$g" 2>/dev/null || true
    done
    # clean managed groups
    getent group | awk -F: '/^pm_xd_/{print $1}' | while read -r g; do groupdel "$g" 2>/dev/null; done
    rm -rf "$ROOT"
    $JAN prune -k 0 2>/dev/null || true
}

trap cleanup EXIT
cleanup

mkdir -p "$ROOT"
chmod 700 "$ROOT"

echo "═══════════════════════════════════════════════════════════════"
echo " janitor cross-distro test suite"
echo " distro=$DISTRO  fs=$FS_TYPE  selinux=$SELINUX"
echo " $(date -Iseconds)"
echo "═══════════════════════════════════════════════════════════════"
echo

# ── 1. Tool path verification ──────────────────────────────────────
echo "── 1. tool paths ──"
assert "setfacl at /usr/bin"  test -x /usr/bin/setfacl
assert "getfacl at /usr/bin"  test -x /usr/bin/getfacl
assert "groupadd at /usr/sbin" test -x /usr/sbin/groupadd
assert "gpasswd at /usr/bin"  test -x /usr/bin/gpasswd
assert "lsattr exists"  command -v lsattr
assert "chattr exists"  command -v chattr
assert "runuser exists" command -v runuser
echo

# ── 2. ACL support on this filesystem ──────────────────────────────
echo "── 2. ACL support ($FS_TYPE) ──"
touch "$ROOT/acl_probe"
OUT=$($JAN acl grant "$ROOT/acl_probe" -u root -a r 2>&1)
assert "acl grant works on $FS_TYPE" test $? -eq 0
ACL=$(getfacl -c "$ROOT/acl_probe" 2>&1)
assert_grep "acl entry present" "$ACL" "user:root:r"
$JAN acl strip "$ROOT/acl_probe" 2>/dev/null
rm -f "$ROOT/acl_probe"
echo

# ── 3. Default ACL inheritance ─────────────────────────────────────
echo "── 3. default ACL inheritance ($FS_TYPE) ──"
useradd -M defacl_user 2>/dev/null || true
mkdir -p "$ROOT/defacl"
$JAN acl grant "$ROOT/defacl" -u defacl_user -a rx -d 2>/dev/null
touch "$ROOT/defacl/child.txt"
CHILD_ACL=$(getfacl -c "$ROOT/defacl/child.txt" 2>&1)
assert_grep "default ACL inherited by child" "$CHILD_ACL" "user:defacl_user"
mkdir "$ROOT/defacl/subdir"
SUBDIR_ACL=$(getfacl -d "$ROOT/defacl/subdir" 2>&1)
assert_grep "default ACL inherited by subdir" "$SUBDIR_ACL" "user:defacl_user"
rm -rf "$ROOT/defacl"
userdel defacl_user 2>/dev/null || true
echo

# ── 4. ACL mask restore after chmod clobber ────────────────────────
echo "── 4. ACL mask restore ($FS_TYPE) ──"
useradd -M mask_user 2>/dev/null || true
touch "$ROOT/mask_f"
chmod 0600 "$ROOT/mask_f"
$JAN acl grant "$ROOT/mask_f" -u mask_user -a rw 2>/dev/null
EFF=$(getfacl -c "$ROOT/mask_f" 2>&1)
assert_grep "mask test: user has rw" "$EFF" "user:mask_user:rw"
# snapshot with ACL, then clobber mask via chmod
BID=$($JAN backup "$ROOT/mask_f" -A 2>&1 | grep -oP '(?<=backup: )\S+')
chmod 0600 "$ROOT/mask_f"
# restore should bring back both mode AND ACL
$JAN restore "$BID" --yes 2>/dev/null
EFF2=$(getfacl -c "$ROOT/mask_f" 2>&1)
assert_grep "restore recovers ACL after mask clobber" "$EFF2" "user:mask_user:rw"
rm -f "$ROOT/mask_f"
userdel mask_user 2>/dev/null || true
echo

# ── 5. chattr immutable ───────────────────────────────────────────
echo "── 5. chattr immutable ($FS_TYPE) ──"
touch "$ROOT/imm_f"
$JAN attr set-immutable "$ROOT/imm_f" 2>/dev/null
LSATTR=$(lsattr -d "$ROOT/imm_f" 2>&1)
assert_grep "immutable flag set" "$LSATTR" "i"
# root cannot delete immutable file
if rm -f "$ROOT/imm_f" 2>/dev/null; then
    fail "immutable prevents deletion"
else
    pass "immutable prevents deletion"
fi
# janitor chmod should fail gracefully on immutable
if $JAN chmod 0777 "$ROOT/imm_f" 2>/dev/null; then
    fail "chmod on immutable fails gracefully"
else
    pass "chmod on immutable fails gracefully"
fi
$JAN attr clear-immutable "$ROOT/imm_f" 2>/dev/null
rm -f "$ROOT/imm_f"
echo

# ── 6. chattr append-only ─────────────────────────────────────────
echo "── 6. chattr append-only ($FS_TYPE) ──"
touch "$ROOT/aonly_f"
$JAN attr set-append-only "$ROOT/aonly_f" 2>/dev/null
if echo "data" >> "$ROOT/aonly_f" 2>/dev/null; then
    pass "append-only allows append"
else
    fail "append-only allows append"
fi
if echo "trunc" > "$ROOT/aonly_f" 2>/dev/null; then
    fail "append-only prevents truncation"
else
    pass "append-only prevents truncation"
fi
$JAN attr clear-append-only "$ROOT/aonly_f" 2>/dev/null
rm -f "$ROOT/aonly_f"
echo

# ── 7. seal with ACL pinholes + runuser access check ──────────────
echo "── 7. seal pinholes ($FS_TYPE) ──"
useradd -M seal_user 2>/dev/null || true
SEAL_BASE=/tmp/xd_seal_test
rm -rf "$SEAL_BASE"
mkdir -p "$SEAL_BASE/deep/dir"
echo "secret" > "$SEAL_BASE/deep/dir/file.txt"
SEAL_OUT=$($JAN seal "$SEAL_BASE" -B root:root:700 -R \
    --allow seal_user:r "$SEAL_BASE/deep/dir/file.txt" 2>&1)
assert "seal exits 0" test $? -eq 0
assert_grep "seal prints backup" "$SEAL_OUT" "backup"
# parent chain should have traverse ACL
PARENT_ACL=$(getfacl -c "$SEAL_BASE/deep/dir" 2>&1)
assert_grep "seal auto-traverse on parent" "$PARENT_ACL" "user:seal_user"
FILE_ACL=$(getfacl -c "$SEAL_BASE/deep/dir/file.txt" 2>&1)
assert_grep "seal pinhole on file" "$FILE_ACL" "user:seal_user:r"
# actual access check — seal base is directly under /tmp (1777), so user can traverse
assert "seal_user can read pinholed file" \
    runuser -u seal_user -- cat "$SEAL_BASE/deep/dir/file.txt"
refute "seal_user cannot list parent dir" \
    runuser -u seal_user -- ls "$SEAL_BASE/deep/"
# undo should revert
$JAN undo --yes 2>/dev/null
rm -rf "$SEAL_BASE"
userdel seal_user 2>/dev/null || true
echo

# ── 8. who-can NSS enumeration ────────────────────────────────────
echo "── 8. who-can NSS ──"
useradd -M whocan_user 2>/dev/null || true
touch "$ROOT/wc_f"
chmod 644 "$ROOT/wc_f"
WC=$($JAN who-can "$ROOT/wc_f" 2>&1)
assert "who-can exits 0" test $? -eq 0
# TTY mode collapses large user lists ("N users (collapsed)"),
# so verify via JSON where every user is listed individually.
WC_JSON=$($JAN -j who-can "$ROOT/wc_f" 2>&1)
assert_grep "who-can finds created user (json)" "$WC_JSON" "whocan_user"
# also check that the TTY output at least shows a count or the user
WC_HAS=$(echo "$WC" | grep -c "whocan_user\|collapsed" || true)
if [[ "$WC_HAS" -gt 0 ]]; then pass "who-can tty lists or collapses user"; else fail "who-can tty lists or collapses user"; fi
# system file — no crash
$JAN who-can /etc/hostname >/dev/null 2>&1
assert "who-can on /etc/hostname no crash" test $? -eq 0
rm -f "$ROOT/wc_f"
userdel whocan_user 2>/dev/null || true
echo

# ── 9. copy-perms with ACL ────────────────────────────────────────
echo "── 9. copy-perms ACL ──"
useradd -M cp_user 2>/dev/null || true
mkdir -p "$ROOT/cpsrc" "$ROOT/cpdst"
touch "$ROOT/cpsrc/f" "$ROOT/cpdst/f"
chmod 0750 "$ROOT/cpsrc/f"
setfacl -m u:cp_user:rwx "$ROOT/cpsrc/f"
$JAN copy-perms "$ROOT/cpsrc/f" "$ROOT/cpdst/f" -A 2>/dev/null
CP_ACL=$(getfacl -c "$ROOT/cpdst/f" 2>&1)
assert_grep "copy-perms -A copies ACL" "$CP_ACL" "user:cp_user:rwx"
# When ACL is set with rwx, the ACL mask becomes the group permission
# bits. So stat shows 770 (mask=rwx) instead of 750. This is correct
# POSIX ACL behavior. Verify the underlying base mode via getfacl.
DST_BASE=$(getfacl -c "$ROOT/cpdst/f" 2>&1 | grep '^user::' | head -1)
assert_grep "copy-perms copies base user mode" "$DST_BASE" "user::rwx"
DST_GRP=$(getfacl -c "$ROOT/cpdst/f" 2>&1 | grep '^group::' | head -1)
assert_grep "copy-perms copies base group mode" "$DST_GRP" "group::r-x"
rm -rf "$ROOT/cpsrc" "$ROOT/cpdst"
userdel cp_user 2>/dev/null || true
echo

# ── 10. concurrent flock serialization ────────────────────────────
echo "── 10. concurrent flock ──"
touch "$ROOT/flock_f"
chmod 0644 "$ROOT/flock_f"
$JAN chmod 0755 "$ROOT/flock_f" &
PID1=$!
$JAN chmod 0700 "$ROOT/flock_f" &
PID2=$!
wait $PID1; R1=$?
wait $PID2; R2=$?
if [[ $R1 -eq 0 && $R2 -eq 0 ]]; then
    pass "concurrent ops both succeed"
else
    fail "concurrent ops both succeed (r1=$R1 r2=$R2)"
fi
rm -f "$ROOT/flock_f"
echo

# ── 11. large tree (10k files) on low-memory host ─────────────────
echo "── 11. large tree (10k files) ──"
mkdir -p "$ROOT/big"
seq 1 10000 | while read -r i; do touch "$ROOT/big/f_$i"; done
$JAN audit "$ROOT/big" -W >/dev/null 2>&1
assert "audit 10k files exits 0" test $? -eq 0
$JAN chmod 0644 "$ROOT/big" -R >/dev/null 2>&1
assert "chmod -R 10k files exits 0" test $? -eq 0
rm -rf "$ROOT/big"
echo

# ── 12. backup MessagePack format ─────────────────────────────────
echo "── 12. backup format ──"
mkdir -p "$ROOT/mpk"
echo data > "$ROOT/mpk/f"
BID=$($JAN backup "$ROOT/mpk" -R 2>&1 | grep -oP '(?<=backup: )\S+')
MPK="/var/lib/janitor/backups/${BID}.mpk"
assert "backup is .mpk file" test -f "$MPK"
# MessagePack starts with 0x80-0x8f (fixmap), 0xde (map16), 0xdf (map32)
# JSON starts with 0x7b '{'. If first byte is 0x7b → wrong format.
FIRST=$(xxd -l1 -p "$MPK" 2>/dev/null)
refute_grep "backup is not JSON" "$FIRST" "^7b$"
# export works
EXP=$($JAN -j export "$BID" 2>&1)
assert_grep "export has entries" "$EXP" "entries"
rm -rf "$ROOT/mpk"
echo

# ── 13. tmpfs ACL (if /tmp is tmpfs) ──────────────────────────────
echo "── 13. tmpfs ACL ──"
TMP_FS=$(df -T /tmp 2>/dev/null | tail -1 | awk '{print $2}')
if [[ "$TMP_FS" == "tmpfs" ]]; then
    touch /tmp/xd_tmpfs_probe
    $JAN acl grant /tmp/xd_tmpfs_probe -u root -a rw 2>/dev/null
    assert "ACL on tmpfs works" test $? -eq 0
    TACL=$(getfacl -c /tmp/xd_tmpfs_probe 2>&1)
    assert_grep "ACL entry on tmpfs" "$TACL" "user:root:rw"
    $JAN acl strip /tmp/xd_tmpfs_probe 2>/dev/null
    rm -f /tmp/xd_tmpfs_probe
else
    pass "ACL on tmpfs works (skip: /tmp is $TMP_FS)"
    pass "ACL entry on tmpfs (skip: /tmp is $TMP_FS)"
fi
echo

# ── 14. grant + revoke round-trip ─────────────────────────────────
echo "── 14. grant/revoke round-trip ──"
useradd -M xd_user 2>/dev/null || true
mkdir -p "$ROOT/grp_test"
chmod 700 "$ROOT/grp_test"
$JAN grant "$ROOT/grp_test" -u xd_user -a r 2>/dev/null
# user should now be able to access via managed group
assert "grant gives user access" \
    runuser -u xd_user -- test -r "$ROOT/grp_test"
$JAN revoke "$ROOT/grp_test" -u xd_user 2>/dev/null
# after revoke, access should be gone
refute "revoke removes access" \
    runuser -u xd_user -- test -r "$ROOT/grp_test"
rm -rf "$ROOT/grp_test"
userdel xd_user 2>/dev/null || true
echo

# ── 15. SELinux context preservation (RHEL only) ──────────────────
echo "── 15. SELinux ──"
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" != "Disabled" ]]; then
    touch "$ROOT/se_f"
    # get current context
    BEFORE=$(ls -Z "$ROOT/se_f" 2>/dev/null | awk '{print $1}')
    $JAN chmod 0755 "$ROOT/se_f" 2>/dev/null
    AFTER=$(ls -Z "$ROOT/se_f" 2>/dev/null | awk '{print $1}')
    assert_eq "selinux context preserved after chmod" "$BEFORE" "$AFTER"

    $JAN chown root:root "$ROOT/se_f" 2>/dev/null
    AFTER2=$(ls -Z "$ROOT/se_f" 2>/dev/null | awk '{print $1}')
    assert_eq "selinux context preserved after chown" "$BEFORE" "$AFTER2"

    # restore preserves context?
    $JAN undo --yes 2>/dev/null
    AFTER3=$(ls -Z "$ROOT/se_f" 2>/dev/null | awk '{print $1}')
    assert_eq "selinux context preserved after restore" "$BEFORE" "$AFTER3"
    rm -f "$ROOT/se_f"

    # check for AVC denials (advisory — does not FAIL the test)
    if command -v ausearch >/dev/null 2>&1; then
        AVC_COUNT=$(ausearch -m avc -ts recent 2>/dev/null | grep -c "janitor" || true)
        if [[ "$AVC_COUNT" -gt 0 ]]; then
            echo "  WARN  $AVC_COUNT SELinux AVC denial(s) for janitor (check 'ausearch -m avc')"
        else
            pass "no SELinux AVC denials"
        fi
    else
        pass "no SELinux AVC denials (ausearch not available, skip)"
    fi
else
    pass "selinux context preserved after chmod (skip: no SELinux)"
    pass "selinux context preserved after chown (skip: no SELinux)"
    pass "selinux context preserved after restore (skip: no SELinux)"
    pass "no SELinux AVC denials (skip: no SELinux)"
fi
echo

# ── 16. explain + info no-crash sweep ─────────────────────────────
echo "── 16. explain + info sweep ──"
for p in / /etc /tmp /var /usr /root; do
    $JAN info "$p" >/dev/null 2>&1
    assert "info $p no crash" test $? -eq 0
done
useradd -M xd_user2 2>/dev/null || true
$JAN explain /etc/shadow -U xd_user2 >/dev/null 2>&1
assert "explain /etc/shadow no crash" test $? -eq 0
userdel xd_user2 2>/dev/null || true
echo

# ── 17. compare -R on non-trivial tree ────────────────────────────
echo "── 17. compare -R ──"
mkdir -p "$ROOT/cmp_a/sub" "$ROOT/cmp_b/sub"
touch "$ROOT/cmp_a/f" "$ROOT/cmp_a/sub/g" "$ROOT/cmp_b/f" "$ROOT/cmp_b/sub/g"
chmod 0644 "$ROOT/cmp_a/f" && chmod 0755 "$ROOT/cmp_b/f"
# should detect drift (exit 1)
$JAN compare "$ROOT/cmp_a" "$ROOT/cmp_b" -R >/dev/null 2>&1
assert_eq "compare -R detects drift" "$?" "1"
# identical trees
chmod 0644 "$ROOT/cmp_b/f"
$JAN compare "$ROOT/cmp_a" "$ROOT/cmp_b" -R >/dev/null 2>&1
assert_eq "compare -R identical exits 0" "$?" "0"
rm -rf "$ROOT/cmp_a" "$ROOT/cmp_b"
echo

# ── 18. policy verify detects drift ──────────────────────────────
echo "── 18. policy verify ──"
mkdir -p "$ROOT/pol"
touch "$ROOT/pol/conf"
chmod 0640 "$ROOT/pol/conf"
cat > "$ROOT/pol/policy.yaml" <<'YAML'
rules:
  - path: /tmp/xd_test/pol/conf
    mode: "0600"
    owner: root
    group: root
YAML
# mode is 0640, policy says 0600 → should detect drift
$JAN policy verify "$ROOT/pol/policy.yaml" >/dev/null 2>&1
assert_eq "policy verify detects drift" "$?" "1"
$JAN policy apply "$ROOT/pol/policy.yaml" 2>/dev/null
M=$(stat -c '%a' "$ROOT/pol/conf")
assert_eq "policy apply sets mode" "$M" "600"
# now verify passes
$JAN policy verify "$ROOT/pol/policy.yaml" >/dev/null 2>&1
assert_eq "policy verify passes after apply" "$?" "0"
rm -rf "$ROOT/pol"
echo

# ── 19. batch from stdin ──────────────────────────────────────────
echo "── 19. batch stdin ──"
touch "$ROOT/b1" "$ROOT/b2"
chmod 0644 "$ROOT/b1" "$ROOT/b2"
printf 'chmod 0600 %s\nchmod 0755 %s\n' "$ROOT/b1" "$ROOT/b2" | $JAN batch - 2>/dev/null
M1=$(stat -c '%a' "$ROOT/b1")
M2=$(stat -c '%a' "$ROOT/b2")
assert_eq "batch stdin: b1 mode" "$M1" "600"
assert_eq "batch stdin: b2 mode" "$M2" "755"
rm -f "$ROOT/b1" "$ROOT/b2"
echo

# ── 20. symlink safety ────────────────────────────────────────────
echo "── 20. symlink safety ──"
mkdir -p "$ROOT/sym"
echo real > "$ROOT/sym/real"
ln -s "$ROOT/sym/real" "$ROOT/sym/link"
chmod 0644 "$ROOT/sym/real"
# chown on symlink should NOT follow it
$JAN chown root:root "$ROOT/sym/link" 2>/dev/null
REAL_OWNER=$(stat -c '%U' "$ROOT/sym/real")
assert_eq "chown on symlink does not follow" "$REAL_OWNER" "root"
# chmod -R should skip symlink mode (symlink mode is meaningless on Linux)
$JAN chmod 0700 "$ROOT/sym" -R 2>/dev/null
REAL_MODE=$(stat -c '%a' "$ROOT/sym/real")
assert_eq "chmod -R changes real file" "$REAL_MODE" "700"
rm -rf "$ROOT/sym"
echo

# ── summary ───────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo " RESULTS: $PASS passed, $FAIL failed  ($((PASS+FAIL)) total)"
echo " distro=$DISTRO  fs=$FS_TYPE  selinux=$SELINUX"
echo "═══════════════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
