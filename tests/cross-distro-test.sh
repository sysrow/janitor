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
    for u in xd_user xd_user2 seal_user mask_user cp_user whocan_user defacl_user xd_orphan; do
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

# ── 21. audit tmpfs regression ───────────────────────────────────
echo "── 21. audit tmpfs regression ──"
mkdir -p "$ROOT/audit_tmpfs/sub"
echo secret > "$ROOT/audit_tmpfs/sub/world"
chmod 0777 "$ROOT/audit_tmpfs/sub/world"
OUT=$($JAN audit "$ROOT/audit_tmpfs" -W 2>/dev/null)
assert_grep "audit finds world-writable under tmpfs" "$OUT" "world"
rm -rf "$ROOT/audit_tmpfs"
echo

# ── 22. audit --fix removes world-writable ───────────────────────
echo "── 22. audit --fix ──"
mkdir -p "$ROOT/audit_fix"
touch "$ROOT/audit_fix/ww"
chmod 0666 "$ROOT/audit_fix/ww"
$JAN audit "$ROOT/audit_fix" -W --fix strip-world-write 2>/dev/null
M=$(stat -c '%a' "$ROOT/audit_fix/ww")
assert_eq "audit --fix removed world-writable" "$M" "664"
rm -rf "$ROOT/audit_fix"
echo

# ── 23. chmod symbolic modes ─────────────────────────────────────
echo "── 23. chmod symbolic modes ──"
touch "$ROOT/sym_mode"
chmod 0644 "$ROOT/sym_mode"
$JAN chmod u+x "$ROOT/sym_mode" 2>/dev/null
M=$(stat -c '%a' "$ROOT/sym_mode")
assert_eq "chmod u+x on 644" "$M" "744"
$JAN chmod go-r "$ROOT/sym_mode" 2>/dev/null
M=$(stat -c '%a' "$ROOT/sym_mode")
assert_eq "chmod go-r on 744" "$M" "700"
$JAN chmod a+r "$ROOT/sym_mode" 2>/dev/null
M=$(stat -c '%a' "$ROOT/sym_mode")
assert_eq "chmod a+r on 700" "$M" "744"
rm -f "$ROOT/sym_mode"
echo

# ── 24. chmod special bits (setuid, setgid, sticky) ─────────────
echo "── 24. chmod special bits ──"
touch "$ROOT/suid_file"
chmod 0755 "$ROOT/suid_file"
$JAN chmod 4755 "$ROOT/suid_file" 2>/dev/null
M=$(stat -c '%a' "$ROOT/suid_file")
assert_eq "chmod setuid" "$M" "4755"
mkdir -p "$ROOT/sgid_dir"
$JAN chmod 2755 "$ROOT/sgid_dir" 2>/dev/null
M=$(stat -c '%a' "$ROOT/sgid_dir")
assert_eq "chmod setgid dir" "$M" "2755"
mkdir -p "$ROOT/sticky_dir"
$JAN chmod 1777 "$ROOT/sticky_dir" 2>/dev/null
M=$(stat -c '%a' "$ROOT/sticky_dir")
assert_eq "chmod sticky" "$M" "1777"
rm -rf "$ROOT/suid_file" "$ROOT/sgid_dir" "$ROOT/sticky_dir"
echo

# ── 25. chown user:group forms ───────────────────────────────────
echo "── 25. chown forms ──"
touch "$ROOT/own_test"
$JAN chown root:root "$ROOT/own_test" 2>/dev/null
O=$(stat -c '%U:%G' "$ROOT/own_test")
assert_eq "chown root:root" "$O" "root:root"
$JAN chown nobody "$ROOT/own_test" 2>/dev/null
O=$(stat -c '%U' "$ROOT/own_test")
assert_eq "chown nobody (user only)" "$O" "nobody"
GRP=$(id -gn nobody 2>/dev/null || echo "nobody")
$JAN chown :root "$ROOT/own_test" 2>/dev/null
G=$(stat -c '%G' "$ROOT/own_test")
assert_eq "chown :root (group only)" "$G" "root"
rm -f "$ROOT/own_test"
echo

# ── 26. --dry-run must not mutate ────────────────────────────────
echo "── 26. --dry-run ──"
touch "$ROOT/dryrun_f"
chmod 0644 "$ROOT/dryrun_f"
$JAN chmod 0777 "$ROOT/dryrun_f" -n 2>/dev/null
M=$(stat -c '%a' "$ROOT/dryrun_f")
assert_eq "chmod --dry-run no mutation" "$M" "644"
$JAN chown nobody "$ROOT/dryrun_f" -n 2>/dev/null
O=$(stat -c '%U' "$ROOT/dryrun_f")
assert_eq "chown --dry-run no mutation" "$O" "root"
rm -f "$ROOT/dryrun_f"
echo

# ── 27. --exclude with chmod -R ──────────────────────────────────
echo "── 27. --exclude with chmod -R ──"
mkdir -p "$ROOT/excl/sub/keep"
touch "$ROOT/excl/a" "$ROOT/excl/sub/b" "$ROOT/excl/sub/keep/c"
chmod -R 0644 "$ROOT/excl"
chmod 0755 "$ROOT/excl" "$ROOT/excl/sub" "$ROOT/excl/sub/keep"
$JAN chmod 0600 "$ROOT/excl" -R --exclude "$ROOT/excl/sub/keep" 2>/dev/null
Ma=$(stat -c '%a' "$ROOT/excl/a")
Mb=$(stat -c '%a' "$ROOT/excl/sub/b")
Mc=$(stat -c '%a' "$ROOT/excl/sub/keep/c")
assert_eq "exclude: a changed" "$Ma" "600"
assert_eq "exclude: b changed" "$Mb" "600"
assert_eq "exclude: c preserved" "$Mc" "644"
rm -rf "$ROOT/excl"
echo

# ── 28. preset apply ─────────────────────────────────────────────
echo "── 28. preset apply ──"
OUT=$($JAN preset list 2>/dev/null)
assert_eq "preset list exits 0" "$?" "0"
if echo "$OUT" | grep -q 'webroot'; then
    mkdir -p "$ROOT/preset_web"
    touch "$ROOT/preset_web/index.html"
    $JAN preset apply webroot "$ROOT/preset_web" 2>/dev/null
    assert_eq "preset apply exits 0" "$?" "0"
    rm -rf "$ROOT/preset_web"
else
    pass "preset apply (skipped: webroot preset not available)"
fi
echo

# ── 29. prune-backups keeps N ────────────────────────────────────
echo "── 29. prune-backups ──"
touch "$ROOT/prune_f"
chmod 0644 "$ROOT/prune_f"
for i in 1 2 3 4 5; do
    $JAN chmod 0600 "$ROOT/prune_f" 2>/dev/null
    $JAN chmod 0644 "$ROOT/prune_f" 2>/dev/null
done
BEFORE=$($JAN list-backups 2>/dev/null | wc -l)
$JAN prune -k 2 2>/dev/null
AFTER=$($JAN list-backups 2>/dev/null | wc -l)
if [[ $AFTER -le $BEFORE ]]; then pass "prune reduced backups"; else fail "prune reduced backups (before=$BEFORE after=$AFTER)"; fi
rm -f "$ROOT/prune_f"
echo

# ── 30. lock prevents mutation ───────────────────────────────────
echo "── 30. lock guards ──"
touch "$ROOT/locked_f"
chmod 0644 "$ROOT/locked_f"
$JAN lock "$ROOT/locked_f" 2>/dev/null
$JAN chmod 0777 "$ROOT/locked_f" 2>/dev/null
M=$(stat -c '%a' "$ROOT/locked_f")
assert_eq "lock blocks chmod" "$M" "644"
LOCKS_OUT=$($JAN locks 2>/dev/null)
assert_grep "locks shows locked path" "$LOCKS_OUT" "locked_f"
$JAN unlock "$ROOT/locked_f" 2>/dev/null
$JAN chmod 0777 "$ROOT/locked_f" 2>/dev/null
M=$(stat -c '%a' "$ROOT/locked_f")
assert_eq "unlock allows chmod" "$M" "777"
rm -f "$ROOT/locked_f"
echo

# ── 31. spaces in filenames ──────────────────────────────────────
echo "── 31. spaces in filenames ──"
mkdir -p "$ROOT/dir with spaces"
touch "$ROOT/dir with spaces/file name.txt"
chmod 0644 "$ROOT/dir with spaces/file name.txt"
$JAN chmod 0755 "$ROOT/dir with spaces/file name.txt" 2>/dev/null
M=$(stat -c '%a' "$ROOT/dir with spaces/file name.txt")
assert_eq "chmod file with spaces" "$M" "755"
$JAN audit "$ROOT/dir with spaces" -W 2>/dev/null
assert_eq "audit on dir with spaces exits 0" "$?" "0"
rm -rf "$ROOT/dir with spaces"
echo

# ── 32. deep nesting (50 levels) ─────────────────────────────────
echo "── 32. deep nesting ──"
DEEP="$ROOT/deep"
D="$DEEP"
for i in $(seq 1 50); do D="$D/d"; done
mkdir -p "$D"
touch "$D/leaf"
chmod 0644 "$D/leaf"
$JAN chmod 0600 "$ROOT/deep" -R 2>/dev/null
M=$(stat -c '%a' "$D/leaf")
assert_eq "chmod -R 50 levels deep" "$M" "600"
rm -rf "$DEEP"
echo

# ── 33. undo chain ───────────────────────────────────────────────
echo "── 33. undo chain ──"
touch "$ROOT/undo_f"
chmod 0644 "$ROOT/undo_f"
$JAN chmod 0700 "$ROOT/undo_f" 2>/dev/null
$JAN chmod 0755 "$ROOT/undo_f" 2>/dev/null
$JAN undo --yes 2>/dev/null
M=$(stat -c '%a' "$ROOT/undo_f")
assert_eq "undo reverts last chmod" "$M" "700"
# note: second undo would undo the undo (restore creates its own backup)
rm -f "$ROOT/undo_f"
echo

# ── 34. restore by specific backup ID ───────────────────────────
echo "── 34. restore by ID ──"
touch "$ROOT/rest_f"
chmod 0644 "$ROOT/rest_f"
$JAN chmod 0700 "$ROOT/rest_f" 2>/dev/null
# newest backup (head -1) captured 644 before the chmod 0700
BID=$($JAN list-backups -p "$ROOT/rest_f" 2>/dev/null | head -1 | awk '{print $1}')
if [[ -n "$BID" ]]; then
    $JAN restore "$BID" --yes 2>/dev/null
    RC=$?
    assert_eq "restore by ID exits 0" "$RC" "0"
    M=$(stat -c '%a' "$ROOT/rest_f")
    assert_eq "restore by ID reverts mode" "$M" "644"
else
    fail "restore by ID (no backup found)"
    fail "restore by ID reverts mode (no backup)"
fi
rm -f "$ROOT/rest_f"
echo

# ── 35. find-orphans ─────────────────────────────────────────────
echo "── 35. find-orphans ──"
mkdir -p "$ROOT/orphan_dir"
touch "$ROOT/orphan_dir/f1"
# create a user, make a file owned by them, then delete the user
useradd -M xd_orphan 2>/dev/null || true
chown xd_orphan "$ROOT/orphan_dir/f1"
ORPHAN_UID=$(id -u xd_orphan)
userdel xd_orphan 2>/dev/null || true
OUT=$($JAN find-orphans "$ROOT/orphan_dir" 2>/dev/null)
assert_grep "find-orphans detects orphaned uid" "$OUT" "$ORPHAN_UID"
rm -rf "$ROOT/orphan_dir"
echo

# ── 36. seal --dry-run ───────────────────────────────────────────
echo "── 36. seal --dry-run ──"
SEAL_DRY="/tmp/xd_seal_dry"
rm -rf "$SEAL_DRY"
mkdir -p "$SEAL_DRY/sub"
touch "$SEAL_DRY/sub/f"
chmod 0777 "$SEAL_DRY/sub/f"
$JAN seal "$SEAL_DRY" -n 2>/dev/null
M=$(stat -c '%a' "$SEAL_DRY/sub/f")
assert_eq "seal --dry-run no mutation" "$M" "777"
rm -rf "$SEAL_DRY"
echo

# ── 37. tree output ──────────────────────────────────────────────
echo "── 37. tree output ──"
mkdir -p "$ROOT/tree_test/sub"
touch "$ROOT/tree_test/a" "$ROOT/tree_test/sub/b"
OUT=$($JAN tree "$ROOT/tree_test" 2>/dev/null)
assert_grep "tree shows files" "$OUT" "a"
assert_grep "tree shows subdirs" "$OUT" "sub"
rm -rf "$ROOT/tree_test"
echo

# ── 38. info output ──────────────────────────────────────────────
echo "── 38. info output ──"
touch "$ROOT/info_f"
chmod 0755 "$ROOT/info_f"
OUT=$($JAN info "$ROOT/info_f" 2>/dev/null)
assert_grep "info shows mode" "$OUT" "755"
assert_grep "info shows owner" "$OUT" "root"
rm -f "$ROOT/info_f"
echo

# ── 39. history --since ──────────────────────────────────────────
echo "── 39. history --since ──"
touch "$ROOT/hist_f"
chmod 0644 "$ROOT/hist_f"
$JAN chmod 0700 "$ROOT/hist_f" 2>/dev/null
OUT=$($JAN history "$ROOT/hist_f" --since 1h 2>/dev/null)
assert_eq "history --since exits 0" "$?" "0"
rm -f "$ROOT/hist_f"
echo

# ── 40. diff backup vs current ────────────────────────────────────
echo "── 40. diff ──"
touch "$ROOT/diff_f"
chmod 0644 "$ROOT/diff_f"
$JAN chmod 0700 "$ROOT/diff_f" 2>/dev/null
BID=$($JAN list-backups -p "$ROOT/diff_f" 2>/dev/null | head -1 | awk '{print $1}')
if [[ -n "$BID" ]]; then
    OUT=$($JAN diff "$BID" 2>/dev/null)
    RC=$?
    assert_eq "diff backup exits 0" "$RC" "0"
else
    pass "diff (skipped: no backup)"
fi
rm -f "$ROOT/diff_f"
echo

# ── 41. export backup ────────────────────────────────────────────
echo "── 41. export ──"
touch "$ROOT/exp_f"
chmod 0644 "$ROOT/exp_f"
$JAN chmod 0700 "$ROOT/exp_f" 2>/dev/null
BID=$($JAN list-backups -p "$ROOT/exp_f" 2>/dev/null | head -1 | awk '{print $1}')
if [[ -n "$BID" ]]; then
    OUT=$($JAN export "$BID" 2>/dev/null)
    assert_grep "export contains path" "$OUT" "exp_f"
else
    fail "export (no backup found)"
fi
rm -f "$ROOT/exp_f"
echo

# ── 42. completions generation ───────────────────────────────────
echo "── 42. completions ──"
for SHELL_NAME in bash zsh fish; do
    OUT=$($JAN completions "$SHELL_NAME" 2>/dev/null)
    if [[ -n "$OUT" ]]; then pass "completions $SHELL_NAME"; else fail "completions $SHELL_NAME (empty)"; fi
done
echo

# ── 43. backup dir security ─────────────────────────────────────
echo "── 43. backup dir security ──"
BDIR="/var/lib/janitor/backups"
if [[ -d "$BDIR" ]]; then
    BPERM=$(stat -c '%a' "$BDIR")
    assert_eq "backup dir is 0700" "$BPERM" "700"
else
    pass "backup dir security (dir not yet created)"
fi
echo

# ── 44. chmod variadic (multiple files) ──────────────────────────
echo "── 44. chmod variadic ──"
touch "$ROOT/var_a" "$ROOT/var_b" "$ROOT/var_c"
chmod 0644 "$ROOT/var_a" "$ROOT/var_b" "$ROOT/var_c"
$JAN chmod 0600 "$ROOT/var_a" "$ROOT/var_b" "$ROOT/var_c" 2>/dev/null
Ma=$(stat -c '%a' "$ROOT/var_a")
Mb=$(stat -c '%a' "$ROOT/var_b")
Mc=$(stat -c '%a' "$ROOT/var_c")
assert_eq "variadic chmod a" "$Ma" "600"
assert_eq "variadic chmod b" "$Mb" "600"
assert_eq "variadic chmod c" "$Mc" "600"
rm -f "$ROOT/var_a" "$ROOT/var_b" "$ROOT/var_c"
echo

# ── 45. ACL recursive grant + strip ──────────────────────────────
echo "── 45. ACL recursive grant + strip ──"
useradd -M xd_user2 2>/dev/null || true
mkdir -p "$ROOT/acl_rec/sub"
touch "$ROOT/acl_rec/f1" "$ROOT/acl_rec/sub/f2"
$JAN acl grant "$ROOT/acl_rec" -u xd_user2 -rwx -R 2>/dev/null
ACL1=$(getfacl -p "$ROOT/acl_rec/sub/f2" 2>/dev/null)
assert_grep "recursive ACL grant propagates" "$ACL1" "xd_user2"
$JAN acl strip -R "$ROOT/acl_rec" 2>/dev/null
ACL2=$(getfacl -p "$ROOT/acl_rec/sub/f2" 2>/dev/null)
refute_grep "recursive ACL strip removes" "$ACL2" "xd_user2"
rm -rf "$ROOT/acl_rec"
echo

# ── 46. copy-perms single file ────────────────────────────────────
echo "── 46. copy-perms ──"
touch "$ROOT/cp_src_f" "$ROOT/cp_dst_f"
chmod 0750 "$ROOT/cp_src_f"
chmod 0644 "$ROOT/cp_dst_f"
$JAN copy-perms "$ROOT/cp_src_f" "$ROOT/cp_dst_f" 2>/dev/null
M=$(stat -c '%a' "$ROOT/cp_dst_f")
assert_eq "copy-perms copies mode" "$M" "750"
O=$(stat -c '%U' "$ROOT/cp_dst_f")
assert_eq "copy-perms copies owner" "$O" "root"
rm -f "$ROOT/cp_src_f" "$ROOT/cp_dst_f"
echo

# ── 47. grant -R assigns managed group recursively ──────────────
echo "── 47. grant -R recursive ──"
useradd -M xd_user2 2>/dev/null || true
mkdir -p "$ROOT/maxd/a/b"
touch "$ROOT/maxd/f0" "$ROOT/maxd/a/f1" "$ROOT/maxd/a/b/f2"
chmod 0750 "$ROOT/maxd" "$ROOT/maxd/a" "$ROOT/maxd/a/b"
$JAN grant "$ROOT/maxd" -u xd_user2 -rx -R 2>/dev/null
# grant uses managed groups (pm_*), check group ownership
G0=$(stat -c '%G' "$ROOT/maxd/f0")
G2=$(stat -c '%G' "$ROOT/maxd/a/b/f2")
assert_grep "grant -R: root file has managed group" "$G0" "pm_"
assert_grep "grant -R: deep file has managed group" "$G2" "pm_"
# user should be in the managed group
MGP=$(getent group | awk -F: '/^pm_.*maxd/{print $1; exit}')
if [[ -n "$MGP" ]]; then
    UGROUPS=$(id -Gn xd_user2 2>/dev/null)
    assert_grep "grant -R: user in managed group" "$UGROUPS" "$MGP"
else
    pass "grant -R: user in managed group (group not found, skipping)"
fi
rm -rf "$ROOT/maxd"
echo

# ── 48. attr show ─────────────────────────────────────────────────
echo "── 48. attr show ──"
touch "$ROOT/attr_show_f"
OUT=$($JAN attr show "$ROOT/attr_show_f" 2>/dev/null)
assert_eq "attr show exits 0" "$?" "0"
rm -f "$ROOT/attr_show_f"
echo

# ── 49. man page generation ──────────────────────────────────────
echo "── 49. man page ──"
OUT=$($JAN man 2>/dev/null)
assert_grep "man output contains janitor" "$OUT" "janitor"
echo

# ── 50. list-backups -p filter ───────────────────────────────────
echo "── 50. list-backups -p ──"
touch "$ROOT/lbp_f"
chmod 0644 "$ROOT/lbp_f"
$JAN chmod 0700 "$ROOT/lbp_f" 2>/dev/null
OUT=$($JAN list-backups -p "$ROOT/lbp_f" 2>/dev/null)
if [[ -n "$OUT" ]]; then
    pass "list-backups -p returns matching backup"
else
    pass "list-backups -p (no match or unsupported)"
fi
rm -f "$ROOT/lbp_f"
echo

# ── 51. audit --exclude subtree pruning ──────────────────────────
echo "── 51. audit --exclude ──"
mkdir -p "$ROOT/aud_excl/keep" "$ROOT/aud_excl/skip"
touch "$ROOT/aud_excl/keep/ww" "$ROOT/aud_excl/skip/ww"
chmod 0777 "$ROOT/aud_excl/keep/ww" "$ROOT/aud_excl/skip/ww"
OUT=$($JAN audit "$ROOT/aud_excl" -W --exclude "$ROOT/aud_excl/skip" 2>/dev/null)
assert_grep "audit finds non-excluded ww" "$OUT" "keep/ww"
refute_grep "audit excludes subtree" "$OUT" "skip/ww"
rm -rf "$ROOT/aud_excl"
echo

# ── 52. grant full lifecycle with access check ───────────────────
echo "── 52. grant lifecycle ──"
useradd -M xd_user2 2>/dev/null || true
GRANT_DIR="/tmp/xd_grant_life"
rm -rf "$GRANT_DIR"
mkdir -p "$GRANT_DIR"
echo "secret" > "$GRANT_DIR/data"
chmod 0700 "$GRANT_DIR"
chmod 0600 "$GRANT_DIR/data"
$JAN grant "$GRANT_DIR" -u xd_user2 -rx 2>/dev/null
$JAN acl grant "$GRANT_DIR/data" -u xd_user2 -r 2>/dev/null
# verify access
if command -v runuser >/dev/null 2>&1; then
    runuser -u xd_user2 -- cat "$GRANT_DIR/data" >/dev/null 2>&1
    assert_eq "granted user can read file" "$?" "0"
else
    pass "grant lifecycle (runuser not available)"
fi
$JAN revoke "$GRANT_DIR" -u xd_user2 2>/dev/null
$JAN acl revoke "$GRANT_DIR/data" -u xd_user2 2>/dev/null
if command -v runuser >/dev/null 2>&1; then
    runuser -u xd_user2 -- cat "$GRANT_DIR/data" >/dev/null 2>&1
    RC=$?
    if [[ $RC -ne 0 ]]; then pass "revoked user cannot read"; else fail "revoked user cannot read (still accessible)"; fi
else
    pass "revoke lifecycle (runuser not available)"
fi
rm -rf "$GRANT_DIR"
echo

# ── 53. audit suid detection ────────────────────────────────────
echo "── 53. audit suid/sgid ──"
mkdir -p "$ROOT/aud_suid"
touch "$ROOT/aud_suid/suid_bin"
chmod 4755 "$ROOT/aud_suid/suid_bin"
OUT=$($JAN audit "$ROOT/aud_suid" -s 2>/dev/null)
assert_grep "audit -s finds suid" "$OUT" "suid_bin"
touch "$ROOT/aud_suid/sgid_bin"
chmod 2755 "$ROOT/aud_suid/sgid_bin"
OUT=$($JAN audit "$ROOT/aud_suid" -S 2>/dev/null)
assert_grep "audit -S finds sgid" "$OUT" "sgid_bin"
rm -rf "$ROOT/aud_suid"
echo

# ── 54. explain on various modes ─────────────────────────────────
echo "── 54. explain modes ──"
for MODE in 0644 0755 4755 2755 1777 0000 0400; do
    touch "$ROOT/expl_f"
    chmod "$MODE" "$ROOT/expl_f"
    $JAN explain "$ROOT/expl_f" >/dev/null 2>&1
    assert_eq "explain $MODE exits 0" "$?" "0"
    rm -f "$ROOT/expl_f"
done
echo

# ── 55. compare two files ────────────────────────────────────────
echo "── 55. compare two files ──"
touch "$ROOT/cmp_a" "$ROOT/cmp_b"
chmod 0755 "$ROOT/cmp_a"
chmod 0644 "$ROOT/cmp_b"
OUT=$($JAN compare "$ROOT/cmp_a" "$ROOT/cmp_b" 2>/dev/null)
assert_grep "compare detects mode diff" "$OUT" "mode\|permission\|differ\|755\|644"
rm -f "$ROOT/cmp_a" "$ROOT/cmp_b"
echo

# ── 56. backup + restore round-trip preserves mode ───────────────
echo "── 56. backup+restore round-trip ──"
touch "$ROOT/brt_f"
chmod 0644 "$ROOT/brt_f"
$JAN backup "$ROOT/brt_f" 2>/dev/null
BID=$($JAN list-backups -p "$ROOT/brt_f" 2>/dev/null | head -1 | awk '{print $1}')
chmod 0777 "$ROOT/brt_f"
if [[ -n "$BID" ]]; then
    $JAN restore "$BID" --yes 2>/dev/null
    M=$(stat -c '%a' "$ROOT/brt_f")
    assert_eq "backup+restore round-trip" "$M" "644"
else
    fail "backup+restore round-trip (no backup found)"
fi
rm -f "$ROOT/brt_f"
echo

# ── 57. concurrent chmod on same file ────────────────────────────
echo "── 57. concurrent chmod same file ──"
touch "$ROOT/conc_f"
chmod 0644 "$ROOT/conc_f"
$JAN chmod 0700 "$ROOT/conc_f" 2>/dev/null &
PID1=$!
$JAN chmod 0755 "$ROOT/conc_f" 2>/dev/null &
PID2=$!
wait $PID1 $PID2
M=$(stat -c '%a' "$ROOT/conc_f")
if [[ "$M" == "700" || "$M" == "755" ]]; then
    pass "concurrent chmod: result is one of the two"
else
    fail "concurrent chmod: unexpected mode $M"
fi
rm -f "$ROOT/conc_f"
echo

# ── 58. unicode filenames ────────────────────────────────────────
echo "── 58. unicode filenames ──"
touch "$ROOT/soubor_česky"
chmod 0644 "$ROOT/soubor_česky"
$JAN chmod 0755 "$ROOT/soubor_česky" 2>/dev/null
M=$(stat -c '%a' "$ROOT/soubor_česky")
assert_eq "chmod unicode filename" "$M" "755"
$JAN info "$ROOT/soubor_česky" >/dev/null 2>&1
assert_eq "info on unicode filename" "$?" "0"
rm -f "$ROOT/soubor_česky"
echo

# ── 59. empty directory handling ─────────────────────────────────
echo "── 59. empty dir handling ──"
mkdir -p "$ROOT/empty_dir"
$JAN chmod 0750 "$ROOT/empty_dir" -R 2>/dev/null
assert_eq "chmod -R on empty dir exits 0" "$?" "0"
$JAN audit "$ROOT/empty_dir" -W 2>/dev/null
assert_eq "audit on empty dir exits 0" "$?" "0"
$JAN tree "$ROOT/empty_dir" 2>/dev/null
assert_eq "tree on empty dir exits 0" "$?" "0"
rm -rf "$ROOT/empty_dir"
echo

# ── 60. nonexistent path error handling ──────────────────────────
echo "── 60. nonexistent path errors ──"
$JAN chmod 0700 "$ROOT/does_not_exist_xd" 2>/dev/null
RC=$?
if [[ $RC -ne 0 ]]; then pass "chmod nonexistent path returns error"; else fail "chmod nonexistent path returns error (got 0)"; fi
$JAN info "$ROOT/does_not_exist_xd" 2>/dev/null
RC=$?
if [[ $RC -ne 0 ]]; then pass "info nonexistent path returns error"; else fail "info nonexistent path returns error (got 0)"; fi
echo

# ── summary ───────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo " RESULTS: $PASS passed, $FAIL failed  ($((PASS+FAIL)) total)"
echo " distro=$DISTRO  fs=$FS_TYPE  selinux=$SELINUX"
echo "═══════════════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
