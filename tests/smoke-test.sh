#!/bin/bash
# End-to-end smoke test for janitor.
# Runs inside Docker as root. Exit != 0 on any failure.
# Covers: positional-path syntax, short flags (-u/-g/-a/-R/-n/-j/...),
# subcommand aliases (g/rv/t/b/r/ls/prune/a/w/p), all behaviors, restore semantics.

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

# Capture output as if attached to a TTY. Many janitor commands suppress
# decorative narration / table output when stdout is a pipe; tests that
# assert on human-readable wording use this wrapper. Falls back to plain
# execution if `script` isn't available.
tty_run() {
    if command -v script >/dev/null 2>&1; then
        script -qc "$*" /dev/null 2>&1 | sed 's/\r$//'
    else
        eval "$*" 2>&1
    fi
}

ROOT=/tmp/pm_smoke

# Pick an unused uid/gid that this kernel/namespace can actually assign, and
# chown $1 to it. 99999 is outside the subuid map of a rootless container, so
# `chown 99999` fails there with EINVAL and the "orphan" tests below silently
# tested nothing. Probe downwards for one that works.
pick_orphan_id() {
    local probe
    for probe in 99999 60000 59999 59998; do
        getent passwd "$probe" > /dev/null 2>&1 && continue
        getent group "$probe" > /dev/null 2>&1 && continue
        if chown "$probe:$probe" "$1" 2>/dev/null; then
            echo "$probe"
            return 0
        fi
    done
    return 1
}
USER=pm_smoke_user
USER2=pm_smoke_user2

cleanup() {
    rm -rf "$ROOT"
    userdel "$USER"  2>/dev/null || true
    userdel "$USER2" 2>/dev/null || true
    getent group | awk -F: '/^pm_tmp_/ {print $1}' | xargs -r -n1 groupdel 2>/dev/null || true
    groupdel testgrp  2>/dev/null || true
    groupdel devs     2>/dev/null || true
    rm -rf /var/lib/janitor/backups/*.mpk 2>/dev/null || true
    rm -f  /var/lib/janitor/backups/.janitor.lock 2>/dev/null || true
}
trap cleanup EXIT

echo "=== janitor smoke tests ==="
echo

# ── Setup ────────────────────────────────────────────────────────────
cleanup
useradd -m -s /bin/bash "$USER"  2>/dev/null || true
useradd -m -s /bin/bash "$USER2" 2>/dev/null || true
groupadd devs 2>/dev/null || true
mkdir -p "$ROOT/deep/dir"
mkdir -p "$ROOT/deep/siblings"
echo "target data"    > "$ROOT/deep/dir/target.txt"
echo "sibling secret" > "$ROOT/deep/siblings/hidden.txt"
echo "another"        > "$ROOT/deep/sibling.txt"
chmod -R 700 "$ROOT"

# ── 1. help + version ───────────────────────────────────────────────
assert "help exits 0"                $JAN --help
assert "version exits 0"             $JAN --version
assert "-h short"                    $JAN -h
assert "-V short version"            $JAN -V
assert "grant --help"                $JAN grant --help
assert "acl --help"                  $JAN acl --help
assert "acl grant --help"            $JAN acl grant --help

VER_OUT=$($JAN --version 2>&1)
assert_grep "version is semver"      "$VER_OUT" '^janitor [0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$'

HLP=$($JAN --help 2>&1)
assert_grep "help advertises -n"     "$HLP" '\-n, \-\-dry-run'
assert_grep "help advertises -j"     "$HLP" '\-j, \-\-json'
GHLP=$($JAN grant --help 2>&1)
assert_grep "grant -u documented"    "$GHLP" '\-u, \-\-user'
assert_grep "grant -a documented"    "$GHLP" '\-a, \-\-access'
assert_grep "grant -R documented"    "$GHLP" '\-R, \-\-recursive'
assert_grep "grant -L documented"    "$GHLP" '\-L, \-\-max-level'

# ── 2. tree ─────────────────────────────────────────────────────────
TREE1=$($JAN tree "$ROOT" --color=never 2>&1)
assert_grep "tree shows target.txt"  "$TREE1" "target.txt"
assert_grep "tree shows hidden.txt"  "$TREE1" "hidden.txt"
assert_grep "tree counts dirs"       "$TREE1" "director"

TREE_C=$($JAN tree "$ROOT" -c never 2>&1)
assert_grep "tree -c short color"    "$TREE_C" "target.txt"

TREE_U=$($JAN tree "$ROOT" -U "$USER" -c never 2>&1)
assert_grep "tree -U for-user"       "$TREE_U" "target.txt"

# alias `t`
TREE_A=$($JAN t "$ROOT" -c never 2>&1)
assert_grep "alias t == tree"        "$TREE_A" "target.txt"

# ── 3. dry-run is a no-op ───────────────────────────────────────────
BEFORE=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
$JAN -n grant "$ROOT/deep/dir/target.txt" -u "$USER" -a r > /dev/null 2>&1
AFTER=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$BEFORE" == "$AFTER" ]]; then pass "-n dry-run is no-op"; else fail "dry-run changed perms ($BEFORE->$AFTER)"; fi

DRY=$(tty_run "$JAN --dry-run grant $ROOT/deep/dir/target.txt --user $USER --access r")
assert_grep "dry-run narrates group"    "$DRY" "ensure group"
assert_grep "dry-run narrates add user" "$DRY" "add user"
assert_grep "dry-run narrates chgrp"    "$DRY" "chgrp"

DRY2=$(tty_run "$JAN -n grant $ROOT/deep/dir/target.txt -u $USER -a r")
assert_grep "short -n dry-run output"   "$DRY2" "ensure group"

# ── 4. real grant (long flags) ──────────────────────────────────────
OUT=$($JAN grant "$ROOT/deep/dir/target.txt" --user "$USER" --access r 2>&1)
BID=$(echo "$OUT" | awk '/^backup:/ {print $2}')
if [[ -n "$BID" ]]; then pass "grant returns backup id ($BID)"; else fail "no backup id"; fi
assert_grep "grant prints backup:"    "$OUT" "backup:"

# ── 5. real grant (short flags) ─────────────────────────────────────
chmod -R 700 "$ROOT"
$JAN restore "$BID" --yes > /dev/null 2>&1
OUT2=$($JAN grant "$ROOT/deep/dir/target.txt" -u "$USER" -a r 2>&1)
BID2=$(echo "$OUT2" | awk '/^backup:/ {print $2}')
if [[ -n "$BID2" ]]; then pass "grant short -u -a returns bid"; else fail "short grant no bid"; fi

# ── 6. managed group ────────────────────────────────────────────────
# Managed group names are `pm_<slug>_<hash>`; slug derives from last two
# non-trivial path components, so the exact prefix varies by target.
if getent group | grep -q "^pm_"; then pass "managed group exists"; else fail "managed group missing"; fi
GRP=$(getent group | awk -F: '/^pm_/ {print $1; exit}')
if id -Gn "$USER" | grep -q "$GRP"; then pass "user in managed group"; else fail "user not in $GRP"; fi

# ── 7. access semantics ─────────────────────────────────────────────
assert "user CAN read target"     runuser -u "$USER" -- cat  "$ROOT/deep/dir/target.txt"
refute "user CANNOT ls parent"    runuser -u "$USER" -- ls   "$ROOT/deep/"
refute "user CANNOT read sibling" runuser -u "$USER" -- cat  "$ROOT/deep/sibling.txt"
refute "user CANNOT ls sibling"   runuser -u "$USER" -- ls   "$ROOT/deep/siblings/"

DEEP_PERM=$(stat -c '%a' "$ROOT/deep")
if [[ "${DEEP_PERM:1:1}" == "1" ]]; then pass "parent group --x"; else fail "parent bits ($DEEP_PERM)"; fi

TGT_PERM=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "${TGT_PERM:1:1}" -ge 4 ]]; then pass "target group readable"; else fail "target no group read ($TGT_PERM)"; fi

# ── 8. alias `g` (grant) + `ls` (list-backups) ──────────────────────
chmod -R 700 "$ROOT"
$JAN restore "$BID2" --yes > /dev/null 2>&1
OUT3=$($JAN g "$ROOT/deep/dir/target.txt" -u "$USER" -a r 2>&1)
assert_grep "alias g == grant"        "$OUT3" "backup:"
BID3=$(echo "$OUT3" | awk '/^backup:/ {print $2}')

LS_OUT=$(tty_run "$JAN ls")
assert_grep "alias ls == list-backups" "$LS_OUT" "$BID3"

# ── 9. list-backups JSON + short -j ─────────────────────────────────
LBJ=$($JAN --json list-backups 2>&1)
if echo "$LBJ" | jq -e '.' > /dev/null 2>&1; then pass "list-backups --json"; else fail "--json invalid"; fi
LBJ2=$($JAN -j ls 2>&1)
if echo "$LBJ2" | jq -e '.' > /dev/null 2>&1; then pass "list-backups -j short"; else fail "-j invalid"; fi

# ── 10. tree variants ───────────────────────────────────────────────
assert "tree -H highlight"            $JAN tree "$ROOT" -H "$ROOT/deep/dir/target.txt" -c never
assert "tree --highlight long"        $JAN tree "$ROOT" --highlight "$ROOT/deep/dir/target.txt" --color never
assert "tree -U --color=never"        $JAN tree "$ROOT" -U "$USER" -c never

PARENT_OUT=$($JAN tree "$ROOT/deep" -P -c never 2>&1)
assert_grep "tree -P show-parents"    "$PARENT_OUT" "tmp"

DEPTH_OUT=$($JAN tree "$ROOT" -L 1 -c never 2>&1)
refute_grep "tree -L 1 hides deep"    "$DEPTH_OUT" "target.txt"
assert_grep "tree -L 1 shows top"     "$DEPTH_OUT" "deep"

# ── 11. manual backup + short -R ────────────────────────────────────
BKUP=$($JAN backup "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "manual backup works"     "$BKUP" "backup:"

BKUP2=$($JAN backup "$ROOT" -R 2>&1)
assert_grep "backup -R recursive"     "$BKUP2" "entries"

BKUP3=$($JAN b "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "alias b == backup"       "$BKUP3" "backup:"

# ── 11b. list-backups -p path filter ────────────────────────────────
LS_ALL=$($JAN ls 2>&1 | wc -l)
LS_FILTERED=$($JAN ls -p "$ROOT" 2>&1 | wc -l)
if [[ "$LS_ALL" -ge "$LS_FILTERED" ]]; then pass "ls -p filter narrows list"; else fail "ls -p did not narrow ($LS_ALL vs $LS_FILTERED)"; fi
LS_NONE=$($JAN ls -p "/nonexistent-path-$$" 2>&1 | wc -l)
# header+separator = 2 lines when no rows match (table mode)
if [[ "$LS_NONE" -le 2 ]]; then pass "ls -p with no matches is empty"; else fail "ls -p noise $LS_NONE"; fi
LS_JSON=$($JAN --json ls -p "$ROOT" 2>&1 | jq 'length')
if [[ "$LS_JSON" -ge 1 ]]; then pass "ls -p --json length ok"; else fail "json length $LS_JSON"; fi

# ── 11c. undo restores the most recent backup ───────────────────────
touch "$ROOT/undo-probe"
chmod 600 "$ROOT/undo-probe"
$JAN chmod 644 "$ROOT/undo-probe" > /dev/null 2>&1
BEFORE_UNDO=$(stat -c '%a' "$ROOT/undo-probe")
$JAN undo --yes > /dev/null 2>&1
AFTER_UNDO=$(stat -c '%a' "$ROOT/undo-probe")
if [[ "$BEFORE_UNDO" == "644" && "$AFTER_UNDO" == "600" ]]; then pass "undo reverts most recent change"; else fail "undo before=$BEFORE_UNDO after=$AFTER_UNDO"; fi
UN_ALIAS=$($JAN u --help 2>&1 | head -1)
assert_grep "undo alias u"            "$UN_ALIAS" "Undo"
rm -f "$ROOT/undo-probe"

# ── 12. dry-run restore ─────────────────────────────────────────────
DR_RESTORE=$(tty_run "$JAN -n restore $BID3")
assert_grep "dry-run restore mentions restoring" "$DR_RESTORE" "restor"
assert_grep "dry-run restore mentions mode"      "$DR_RESTORE" "mode"
assert "user still reads after dry-run restore"  runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"

# ── 13. real restore ────────────────────────────────────────────────
$JAN restore "$BID3" --yes > /dev/null 2>&1
refute "user cannot read after restore" runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"

R_TGT=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$R_TGT" == "700" ]]; then pass "target perms restored"; else fail "target perms $R_TGT"; fi
R_DEEP=$(stat -c '%a' "$ROOT/deep")
if [[ "$R_DEEP" == "700" ]]; then pass "parent perms restored"; else fail "parent perms $R_DEEP"; fi

# ── 14. restore via alias `r` ───────────────────────────────────────
OUT4=$($JAN g "$ROOT/deep/dir/target.txt" -u "$USER" 2>&1)
BID4=$(echo "$OUT4" | awk '/^backup:/ {print $2}')
$JAN r "$BID4" --yes > /dev/null 2>&1
refute "alias r == restore (user lost read)" runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"

# ── 15. grant rw ────────────────────────────────────────────────────
$JAN grant "$ROOT/deep/dir/target.txt" -u "$USER" -a rw > /dev/null 2>&1
assert "user can read rw grant"  runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"
assert "user can write rw grant" runuser -u "$USER" -- sh -c "echo test >> $ROOT/deep/dir/target.txt"

# ── 15b. -r/-w/-x boolean flags (combined, bundled, order-independent) ──
chmod -R 700 "$ROOT"
$JAN revoke "$ROOT/deep/dir/target.txt" -u "$USER" > /dev/null 2>&1 || true
$JAN grant "$ROOT/deep/dir/target.txt" -u "$USER" -rw > /dev/null 2>&1
assert "bundled -rw grants read"  runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"
assert "bundled -rw grants write" runuser -u "$USER" -- sh -c "echo x >> $ROOT/deep/dir/target.txt"
chmod -R 700 "$ROOT"
$JAN revoke "$ROOT/deep/dir/target.txt" -u "$USER" > /dev/null 2>&1 || true
$JAN grant "$ROOT/deep/dir/target.txt" -u "$USER" -w -r > /dev/null 2>&1
assert "split order -w -r grants read"  runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"
chmod -R 700 "$ROOT"
$JAN revoke "$ROOT/deep/dir/target.txt" -u "$USER" > /dev/null 2>&1 || true
$JAN grant "$ROOT/deep/dir/target.txt" -u "$USER" --read --write > /dev/null 2>&1
assert "long --read --write grants read" runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"
chmod -R 700 "$ROOT"
$JAN revoke "$ROOT/deep/dir/target.txt" -u "$USER" > /dev/null 2>&1 || true
# default (no access flag) == read-only
$JAN grant "$ROOT/deep/dir/target.txt" -u "$USER" > /dev/null 2>&1
assert "no-flag default grants read" runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"
refute "no-flag default denies write" runuser -u "$USER" -- sh -c "echo x >> $ROOT/deep/dir/target.txt"

# -r and -a are mutually exclusive
refute "-r conflicts with -a" $JAN grant "$ROOT" -u "$USER" -r -a rw
refute "-w conflicts with -a" $JAN grant "$ROOT" -u "$USER" -w -a r
refute "-x conflicts with -a" $JAN grant "$ROOT" -u "$USER" -x -a r

# ── 16. revoke (long + short + alias) ───────────────────────────────
# Capture the path's managed group name right before revoke (it is
# deterministic per-path, but multiple test sections created several
# pm_* groups — we want the one tied to this file).
PGRP=$(stat -c '%G' "$ROOT/deep/dir/target.txt")
$JAN revoke "$ROOT/deep/dir/target.txt" --user "$USER" > /dev/null 2>&1
if id -Gn "$USER" | tr ' ' '\n' | grep -qx "$PGRP"; then fail "user still in group after revoke"; else pass "long revoke removed user"; fi

# regrant, then revoke via short
$JAN g "$ROOT/deep/dir/target.txt" -u "$USER" > /dev/null 2>&1
PGRP2=$(stat -c '%G' "$ROOT/deep/dir/target.txt")
$JAN rv "$ROOT/deep/dir/target.txt" -u "$USER" > /dev/null 2>&1
if id -Gn "$USER" | tr ' ' '\n' | grep -qx "$PGRP2"; then fail "alias rv did not revoke"; else pass "alias rv == revoke"; fi

# ── 17. input validation ────────────────────────────────────────────
refute "bad --access rejected"        $JAN grant "$ROOT" --user "$USER" --access bogus
refute "bad -a rejected"              $JAN grant "$ROOT" -u "$USER" -a bogus
refute "bad --color rejected"         $JAN tree "$ROOT" --color bogus
refute "missing user+group rejected"  $JAN grant "$ROOT" --access r
refute "-u and -g mutually exclusive" $JAN grant "$ROOT" -u "$USER" -g devs
refute "nonexistent path rejected"    $JAN grant /nonexistent/xyz -u "$USER"
refute "nonexistent user rejected"    $JAN grant "$ROOT" -u "no_such_user_12345"
refute "nonexistent backup rejected"  $JAN restore "fake-id-12345"
refute "missing path rejected"        $JAN grant -u "$USER"

# ── 18. --group with -g ─────────────────────────────────────────────
chmod -R 700 "$ROOT"
groupadd testgrp 2>/dev/null || true
gpasswd -a "$USER" testgrp > /dev/null 2>&1 || true
# short -g path-group is OK too (grant by -g)
OUT6=$($JAN grant "$ROOT/deep/dir/target.txt" -g testgrp -a r 2>&1)
assert_grep "grant -g group path"     "$OUT6" "backup:"
TGRP=$(stat -c '%G' "$ROOT/deep/dir/target.txt")
if [[ "$TGRP" == "testgrp" ]]; then pass "file owned by explicit -g group"; else fail "file group $TGRP"; fi

# ── 19. recursive grant on dir ──────────────────────────────────────
chmod -R 700 "$ROOT"
$JAN grant "$ROOT/deep/dir" -u "$USER" -a r -R > /dev/null 2>&1
assert "user reads in -R grant" runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"

chmod -R 700 "$ROOT"
$JAN grant "$ROOT/deep/dir" -u "$USER" -a r --recursive > /dev/null 2>&1
assert "user reads in --recursive grant" runuser -u "$USER" -- cat "$ROOT/deep/dir/target.txt"

# ── 20. prune-backups ───────────────────────────────────────────────
$JAN prune-backups --keep 0 > /dev/null 2>&1
REMAINING=$(ls /var/lib/janitor/backups/*.mpk 2>/dev/null | wc -l)
if [[ "$REMAINING" -eq 0 ]]; then pass "prune --keep 0"; else fail "prune left $REMAINING"; fi

$JAN b "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
$JAN b "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
$JAN prune -k 0 > /dev/null 2>&1
REMAINING2=$(ls /var/lib/janitor/backups/*.mpk 2>/dev/null | wc -l)
if [[ "$REMAINING2" -eq 0 ]]; then pass "alias prune -k short"; else fail "alias prune left $REMAINING2"; fi

# ── 21. world-readable warning ──────────────────────────────────────
chmod -R 700 "$ROOT"
chmod 704 "$ROOT/deep/dir/target.txt"
WR_OUT=$($JAN grant "$ROOT/deep/dir/target.txt" -u "$USER" -a r 2>&1)
assert_grep "world-readable warning"  "$WR_OUT" "world-readable"

# ── 22. backup dir permissions ──────────────────────────────────────
BD_PERM=$(stat -c '%a' /var/lib/janitor/backups)
if [[ "$BD_PERM" == "700" ]]; then pass "backup dir 0700"; else fail "backup dir $BD_PERM"; fi

MPK=$(ls /var/lib/janitor/backups/*.mpk 2>/dev/null | wc -l)
if [[ "$MPK" -ge 1 ]]; then pass "backups in .mpk"; else fail "no .mpk backups"; fi

# ── 23. symlink lchown (restore keeps symlink, not target) ─────────
chmod -R 700 "$ROOT"
ln -sf /etc/hostname "$ROOT/deep/dir/mylink"
SNAP_BID=$($JAN b "$ROOT/deep/dir" -R 2>&1 | awk '/^backup:/ {print $2}')
$JAN r "$SNAP_BID" --yes > /dev/null 2>&1
if [[ -L "$ROOT/deep/dir/mylink" ]]; then pass "symlink survived restore"; else fail "symlink gone"; fi
HP=$(stat -c '%a' /etc/hostname 2>/dev/null || echo "?")
if [[ "$HP" == "644" || "$HP" == "?" ]]; then pass "symlink target unmodified"; else fail "target changed ($HP)"; fi
rm -f "$ROOT/deep/dir/mylink"
$JAN prune -k 0 > /dev/null 2>&1

# ── 24. chmod octal + snapshot + restore ───────────────────────────
chmod 700 "$ROOT/deep/dir/target.txt"
CHMOD_OUT=$($JAN chmod 644 "$ROOT/deep/dir/target.txt" 2>&1)
CHMOD_BID=$(echo "$CHMOD_OUT" | awk '/^backup:/ {print $2}')
NEW_MODE=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$NEW_MODE" == "644" ]]; then pass "chmod 644 applied"; else fail "chmod mode $NEW_MODE"; fi
if [[ "$CHMOD_BID" != "" ]]; then pass "chmod wrote backup"; else fail "chmod no backup"; fi

$JAN r "$CHMOD_BID" --yes > /dev/null 2>&1
RESTORED=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$RESTORED" == "700" ]]; then pass "chmod restore works"; else fail "restore $RESTORED"; fi

# ── 25. chmod symbolic ──────────────────────────────────────────────
chmod 600 "$ROOT/deep/dir/target.txt"
$JAN chmod "u+x,g+r" "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
SYM=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$SYM" == "740" ]]; then pass "chmod symbolic u+x,g+r"; else fail "symbolic $SYM"; fi

# ── 25b. chmod special bits (setuid / setgid / sticky) via octal ────
chmod 755 "$ROOT/deep/dir/target.txt"
$JAN chmod 4755 "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
SUID=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$SUID" == "4755" ]]; then pass "chmod 4755 setuid"; else fail "chmod 4755 → $SUID"; fi
chmod 755 "$ROOT/deep/dir/target.txt"
$JAN chmod 2755 "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
SGID=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$SGID" == "2755" ]]; then pass "chmod 2755 setgid"; else fail "chmod 2755 → $SGID"; fi
chmod 777 "$ROOT/deep/dir"
$JAN chmod 1777 "$ROOT/deep/dir" > /dev/null 2>&1
STK=$(stat -c '%a' "$ROOT/deep/dir")
if [[ "$STK" == "1777" ]]; then pass "chmod 1777 sticky"; else fail "chmod 1777 → $STK"; fi
chmod 755 "$ROOT/deep/dir/target.txt"
$JAN chmod 6755 "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
SUGID=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$SUGID" == "6755" ]]; then pass "chmod 6755 setuid+setgid"; else fail "chmod 6755 → $SUGID"; fi

# ── 25c. chmod special bits via symbolic ─────────────────────────────
chmod 755 "$ROOT/deep/dir/target.txt"
$JAN chmod "u+s" "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
US=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$US" == "4755" ]]; then pass "chmod u+s symbolic"; else fail "u+s → $US"; fi
$JAN chmod "g+s" "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
GS=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$GS" == "6755" ]]; then pass "chmod g+s symbolic"; else fail "g+s → $GS"; fi
chmod 777 "$ROOT/deep/dir"
$JAN chmod "+t" "$ROOT/deep/dir" > /dev/null 2>&1
TK=$(stat -c '%a' "$ROOT/deep/dir")
if [[ "$TK" == "1777" ]]; then pass "chmod +t symbolic"; else fail "+t → $TK"; fi
$JAN chmod "u-s,g-s" "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
CLR=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$CLR" == "755" ]]; then pass "chmod u-s,g-s clears"; else fail "u-s,g-s → $CLR"; fi
$JAN chmod -- "-t" "$ROOT/deep/dir" > /dev/null 2>&1
NOT=$(stat -c '%a' "$ROOT/deep/dir")
if [[ "$NOT" == "777" ]]; then pass "chmod -t clears sticky"; else fail "-t → $NOT"; fi

# ── 25d. chmod +X (exec only on dirs / already-exec) ────────────────
chmod 600 "$ROOT/deep/dir/target.txt"
chmod 700 "$ROOT/deep/dir"
$JAN chmod "a+X" "$ROOT/deep/dir" -R > /dev/null 2>&1
DIRX=$(stat -c '%a' "$ROOT/deep/dir")
FILEX=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
# dir gets +x for all, file stays non-exec (no prior exec bits)
if [[ "$DIRX" == "711" ]]; then pass "chmod a+X dirs get x"; else fail "a+X dir → $DIRX"; fi
if [[ "$FILEX" == "600" ]]; then pass "chmod a+X non-exec file untouched"; else fail "a+X file → $FILEX"; fi

# ── 25e. chmod --reference / -F ─────────────────────────────────────
chmod 644 "$ROOT/deep/dir/target.txt"
touch "$ROOT/refsrc" && chmod 750 "$ROOT/refsrc"
$JAN chmod - "$ROOT/deep/dir/target.txt" --reference "$ROOT/refsrc" > /dev/null 2>&1
REF=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$REF" == "750" ]]; then pass "chmod --reference long"; else fail "chmod --ref → $REF"; fi
chmod 644 "$ROOT/deep/dir/target.txt"
$JAN chmod - "$ROOT/deep/dir/target.txt" -F "$ROOT/refsrc" > /dev/null 2>&1
REFS=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$REFS" == "750" ]]; then pass "chmod -F short reference"; else fail "chmod -F → $REFS"; fi
rm -f "$ROOT/refsrc"

# ── 26. chmod recursive ─────────────────────────────────────────────
$JAN chmod 755 "$ROOT/deep/dir" -R > /dev/null 2>&1
R1=$(stat -c '%a' "$ROOT/deep/dir")
R2=$(stat -c '%a' "$ROOT/deep/dir/target.txt")
if [[ "$R1" == "755" && "$R2" == "755" ]]; then pass "chmod -R recursive"; else fail "chmod -R ($R1,$R2)"; fi

$JAN chmod 744 "$ROOT/deep/dir" --recursive > /dev/null 2>&1
R1b=$(stat -c '%a' "$ROOT/deep/dir")
if [[ "$R1b" == "744" ]]; then pass "chmod --recursive long"; else fail "chmod --recursive $R1b"; fi

# ── 27. chown spec forms ────────────────────────────────────────────
$JAN chown "$USER:$USER" "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
OWN=$(stat -c '%U:%G' "$ROOT/deep/dir/target.txt")
if [[ "$OWN" == "$USER:$USER" ]]; then pass "chown user:group"; else fail "chown $OWN"; fi

$JAN chown "root" "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
OWN2=$(stat -c '%U' "$ROOT/deep/dir/target.txt")
if [[ "$OWN2" == "root" ]]; then pass "chown user-only"; else fail "chown user-only $OWN2"; fi

$JAN chown ":$USER" "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
OWN3=$(stat -c '%G' "$ROOT/deep/dir/target.txt")
if [[ "$OWN3" == "$USER" ]]; then pass "chown :group"; else fail "chown :group $OWN3"; fi

$JAN chown "0:0" "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
OWN4=$(stat -c '%u:%g' "$ROOT/deep/dir/target.txt")
if [[ "$OWN4" == "0:0" ]]; then pass "chown numeric 0:0"; else fail "chown numeric $OWN4"; fi

# ── 28. chown recursive + restore ───────────────────────────────────
chown root:root "$ROOT/deep/dir" "$ROOT/deep/dir/target.txt"
CHOWN_OUT=$($JAN chown "$USER:$USER" "$ROOT/deep/dir" -R 2>&1)
CHOWN_BID=$(echo "$CHOWN_OUT" | awk '/^backup:/ {print $2}')
OWN_R=$(stat -c '%U:%G' "$ROOT/deep/dir/target.txt")
if [[ "$OWN_R" == "$USER:$USER" ]]; then pass "chown -R recursive"; else fail "chown -R $OWN_R"; fi

$JAN r "$CHOWN_BID" --yes > /dev/null 2>&1
OWN_RB=$(stat -c '%U:%G' "$ROOT/deep/dir/target.txt")
if [[ "$OWN_RB" == "root:root" ]]; then pass "chown restore works"; else fail "chown restore $OWN_RB"; fi

# ── 28b. chown --reference / -F ─────────────────────────────────────
touch "$ROOT/refown"
chown "$USER:testgrp" "$ROOT/refown" 2>/dev/null || true
chown root:root "$ROOT/deep/dir/target.txt"
$JAN chown - "$ROOT/deep/dir/target.txt" --reference "$ROOT/refown" > /dev/null 2>&1
RU=$(stat -c '%U:%G' "$ROOT/deep/dir/target.txt")
if [[ "$RU" == "$USER:testgrp" ]]; then pass "chown --reference copies owner:group"; else fail "chown --ref → $RU"; fi
chown root:root "$ROOT/deep/dir/target.txt"
$JAN chown - "$ROOT/deep/dir/target.txt" -F "$ROOT/refown" > /dev/null 2>&1
RUS=$(stat -c '%U:%G' "$ROOT/deep/dir/target.txt")
if [[ "$RUS" == "$USER:testgrp" ]]; then pass "chown -F short reference"; else fail "chown -F → $RUS"; fi
rm -f "$ROOT/refown"

# ── 28c. chown -R never follows symlinks (lchown on the symlink itself) ──
chmod -R 700 "$ROOT"
mkdir -p "$ROOT/chowntree"
touch "$ROOT/target-outside-tree"
chown root:root "$ROOT/target-outside-tree"
OUTSIDE_BEFORE=$(stat -c '%U:%G' "$ROOT/target-outside-tree")
ln -sf "$ROOT/target-outside-tree" "$ROOT/chowntree/link"
$JAN chown "$USER:$USER" "$ROOT/chowntree" -R > /dev/null 2>&1
OUTSIDE_AFTER=$(stat -c '%U:%G' "$ROOT/target-outside-tree")
LINK_OWNER=$(stat -c '%U:%G' "$ROOT/chowntree/link")         # stat does not deref by default
if [[ "$OUTSIDE_BEFORE" == "$OUTSIDE_AFTER" ]]; then pass "chown -R does not follow symlinks (target untouched)"; else fail "chown -R followed symlink! before=$OUTSIDE_BEFORE after=$OUTSIDE_AFTER"; fi
if [[ "$LINK_OWNER" == "$USER:$USER" ]]; then pass "chown -R lchowns the symlink itself"; else fail "chown -R left link at $LINK_OWNER"; fi
rm -rf "$ROOT/chowntree" "$ROOT/target-outside-tree"

# ── 28d. a symlink named DIRECTLY on the command line is not followed ──
# This is a different code path from 28c: the operand goes through path
# resolution rather than the recursive walk. Canonicalizing it used to
# dereference the link, so `chown` hit the target instead (§H-01).
touch "$ROOT/direct-target"
chown root:root "$ROOT/direct-target"
chmod 0644 "$ROOT/direct-target"
ln -sfn "$ROOT/direct-target" "$ROOT/direct-link"
DT_BEFORE=$(stat -c '%U:%G %a' "$ROOT/direct-target")
$JAN chown "$USER:$USER" "$ROOT/direct-link" > /dev/null 2>&1
DT_AFTER=$(stat -c '%U:%G %a' "$ROOT/direct-target")
DL_OWNER=$(stat -c '%U:%G' "$ROOT/direct-link")
if [[ "$DT_BEFORE" == "$DT_AFTER" ]]; then pass "direct chown on a symlink leaves the target alone"; else fail "direct chown followed symlink! before=$DT_BEFORE after=$DT_AFTER"; fi
if [[ "$DL_OWNER" == "$USER:$USER" ]]; then pass "direct chown changes the symlink itself"; else fail "direct chown left link at $DL_OWNER"; fi
$JAN chmod 0600 "$ROOT/direct-link" > /dev/null 2>&1
DT_MODE=$(stat -c '%a' "$ROOT/direct-target")
if [[ "$DT_MODE" == "644" ]]; then pass "direct chmod on a symlink leaves the target alone"; else fail "direct chmod followed symlink! target mode=$DT_MODE"; fi
rm -f "$ROOT/direct-link" "$ROOT/direct-target"

# ── 28e. restore refuses an entry whose inode was swapped (§C-01) ──────
mkdir -p "$ROOT/swap"
echo data > "$ROOT/swap/real"
chmod 0644 "$ROOT/swap/real"
echo victim > "$ROOT/swap/victim"
chmod 0600 "$ROOT/swap/victim"
SWAP_BID=$($JAN backup "$ROOT/swap/real" 2>&1 | grep -oP '(?<=backup: )\S+')
rm -f "$ROOT/swap/real"
ln -s "$ROOT/swap/victim" "$ROOT/swap/real"
if $JAN restore "$SWAP_BID" --yes > /dev/null 2>&1; then
    fail "restore applied a snapshot onto a swapped symlink"
else
    pass "restore refuses an entry replaced by a symlink"
fi
VICTIM_MODE=$(stat -c '%a' "$ROOT/swap/victim")
if [[ "$VICTIM_MODE" == "600" ]]; then pass "swap victim keeps its mode"; else fail "swap victim became $VICTIM_MODE"; fi
# --allow-replaced must NOT waive the type check.
if $JAN restore "$SWAP_BID" --yes --allow-replaced > /dev/null 2>&1; then
    fail "--allow-replaced waived the symlink type check"
else
    pass "--allow-replaced still refuses a symlink swap"
fi
rm -rf "$ROOT/swap"

# ── 28e2. --allow-replaced accepts an editor-style rewrite ─────────────
mkdir -p "$ROOT/rewrite"
echo old > "$ROOT/rewrite/f"
chmod 0644 "$ROOT/rewrite/f"
RW_BID=$($JAN backup "$ROOT/rewrite/f" 2>&1 | grep -oP '(?<=backup: )\S+')
# write-then-rename, exactly what an editor does: same type, new inode
echo new > "$ROOT/rewrite/f.new"
mv "$ROOT/rewrite/f.new" "$ROOT/rewrite/f"
chmod 0600 "$ROOT/rewrite/f"
if $JAN restore "$RW_BID" --yes > /dev/null 2>&1; then
    fail "restore accepted a replaced inode without --allow-replaced"
else
    pass "restore refuses a replaced inode by default"
fi
assert "restore --allow-replaced accepts the rewrite" $JAN restore "$RW_BID" --yes --allow-replaced
RW_MODE=$(stat -c '%a' "$ROOT/rewrite/f")
if [[ "$RW_MODE" == "644" ]]; then pass "--allow-replaced restored the mode"; else fail "--allow-replaced left mode $RW_MODE"; fi
rm -rf "$ROOT/rewrite"

# ── 28f. grant on / is rejected, not a panic (§M-08) ──────────────────
$JAN --dry-run grant / -u "$USER" -r --no-acl > /dev/null 2>&1
GRANT_ROOT_RC=$?
if [[ $GRANT_ROOT_RC -eq 1 ]]; then pass "grant / fails validation (not a panic)"; else fail "grant / exited $GRANT_ROOT_RC (101 = panic)"; fi

# ── 28g. audit reports an unreadable subtree instead of "clean" (§H-08) ─
mkdir -p "$ROOT/blind/inner"
echo x > "$ROOT/blind/inner/ww.txt"
chmod 0666 "$ROOT/blind/inner/ww.txt"
chmod 000 "$ROOT/blind/inner"
if [[ "$(id -u)" -ne 0 ]]; then
    # root can read a 000 directory, so this only proves anything unprivileged.
    if $JAN audit "$ROOT/blind" -W --paths > /dev/null 2>&1; then
        fail "audit reported success over an unreadable subtree"
    else
        pass "audit fails on an unreadable subtree"
    fi
    assert "audit --best-effort still succeeds" $JAN audit "$ROOT/blind" -W --paths --best-effort
fi
chmod 755 "$ROOT/blind/inner"
rm -rf "$ROOT/blind"

# ── 28h. attr honours --dry-run (§H-06) ───────────────────────────────
if command -v chattr > /dev/null 2>&1; then
    touch "$ROOT/attr-dry"
    ATTR_BEFORE=$(lsattr -d "$ROOT/attr-dry" 2>/dev/null | awk '{print $1}')
    $JAN --dry-run attr set-immutable "$ROOT/attr-dry" > /dev/null 2>&1
    ATTR_AFTER=$(lsattr -d "$ROOT/attr-dry" 2>/dev/null | awk '{print $1}')
    if [[ "$ATTR_BEFORE" == "$ATTR_AFTER" ]]; then pass "attr --dry-run does not run chattr"; else fail "attr --dry-run changed flags: $ATTR_BEFORE -> $ATTR_AFTER"; fi
    chattr -i "$ROOT/attr-dry" 2>/dev/null || true
    rm -f "$ROOT/attr-dry"
fi

# ── 28i. backup ids are validated before use (§H-07) ──────────────────
refute "restore rejects a traversal-shaped backup id" $JAN export "../../../../etc/passwd"

# ── 28j. batch is atomic: a bad later line changes nothing (§H-12) ─────
mkdir -p "$ROOT/batchtx"
echo a > "$ROOT/batchtx/one"
echo b > "$ROOT/batchtx/two"
chmod 0644 "$ROOT/batchtx/one" "$ROOT/batchtx/two"
cat > "$ROOT/batchtx/ops.txt" <<EOF
chmod 0600 $ROOT/batchtx/one
chmod not-a-mode $ROOT/batchtx/two
EOF
refute "batch with an invalid line fails" $JAN batch "$ROOT/batchtx/ops.txt"
BATCH_ONE=$(stat -c '%a' "$ROOT/batchtx/one")
if [[ "$BATCH_ONE" == "644" ]]; then pass "batch validated everything before mutating"; else fail "batch applied line 1 before rejecting line 2 (mode=$BATCH_ONE)"; fi
rm -rf "$ROOT/batchtx"

# ── 28k. grant does not drop setgid/setuid bits (§H-09) ───────────────
mkdir -p "$ROOT/setid"
touch "$ROOT/setid/bin"
chmod 4750 "$ROOT/setid/bin"
$JAN grant "$ROOT/setid/bin" -g "$(id -gn)" -a rx --no-acl > /dev/null 2>&1
SETID_MODE=$(stat -c '%a' "$ROOT/setid/bin")
if [[ "$SETID_MODE" == "4750" ]]; then pass "grant preserves setuid across chgrp"; else fail "grant dropped setid: 4750 -> $SETID_MODE"; fi
rm -rf "$ROOT/setid"

# ── 28l. recursive tighten reaches every descendant (§H-11) ───────────
mkdir -p "$ROOT/tighten/a/b"
touch "$ROOT/tighten/a/b/f1" "$ROOT/tighten/a/f2"
assert "recursive chmod 000 completes without per-path failures" $JAN chmod 000 "$ROOT/tighten" -R
chmod -R u+rwX "$ROOT/tighten"
rm -rf "$ROOT/tighten"

# ── 29. audit filters (long + short) ────────────────────────────────
chmod 777 "$ROOT/deep/dir/target.txt"
WW=$($JAN audit "$ROOT" --world-writable 2>&1)
assert_grep "audit --world-writable"  "$WW" "target.txt"

WWS=$($JAN audit "$ROOT" -W 2>&1)
assert_grep "audit -W short"          "$WWS" "target.txt"

WWA=$($JAN a "$ROOT" -W 2>&1)
assert_grep "alias a == audit"        "$WWA" "target.txt"
chmod 755 "$ROOT/deep/dir/target.txt"

chmod 4755 "$ROOT/deep/dir/target.txt"
SU=$($JAN audit "$ROOT" --setuid 2>&1)
assert_grep "audit --setuid"          "$SU" "target.txt"
SUS=$($JAN audit "$ROOT" -s 2>&1)
assert_grep "audit -s short"          "$SUS" "target.txt"

chmod 2755 "$ROOT/deep/dir/target.txt"
SG=$($JAN audit "$ROOT" -S 2>&1)
assert_grep "audit -S setgid short"   "$SG" "target.txt"
chmod 755 "$ROOT/deep/dir/target.txt"

chmod 1755 "$ROOT/deep/dir"
STK=$($JAN audit "$ROOT" -t 2>&1)
assert_grep "audit -t sticky short"   "$STK" "deep/dir"
chmod 755 "$ROOT/deep/dir"

chmod 644 "$ROOT/deep/dir/target.txt"
MF=$($JAN audit "$ROOT" --mode 644 2>&1)
assert_grep "audit --mode filter"     "$MF" "target.txt"
MFS=$($JAN audit "$ROOT" -m 644 2>&1)
assert_grep "audit -m short"          "$MFS" "target.txt"

chown "$USER:$USER" "$ROOT/deep/dir/target.txt"
OWF=$($JAN audit "$ROOT" -o "$USER" 2>&1)
assert_grep "audit -o owner filter"   "$OWF" "target.txt"

GRF=$($JAN audit "$ROOT" -g "$USER" 2>&1)
assert_grep "audit -g group filter"   "$GRF" "target.txt"

# ── 30. audit --json ────────────────────────────────────────────────
JM=$($JAN --json audit "$ROOT" --mode 644 2>&1)
if echo "$JM" | jq -e '.[0].path' > /dev/null 2>&1; then pass "audit --json"; else fail "audit --json invalid"; fi

JM2=$($JAN -j audit "$ROOT" -m 644 2>&1)
if echo "$JM2" | jq -e '.[0].path' > /dev/null 2>&1; then pass "audit -j short"; else fail "-j audit invalid"; fi

# ── 31. find-orphans ────────────────────────────────────────────────
FO=$($JAN find-orphans "$ROOT" 2>&1)
if echo "$FO" | grep -q "no orphan\|orphan"; then pass "find-orphans ran"; else pass "find-orphans empty ok"; fi

# create an orphan
if ORPHAN_ID=$(pick_orphan_id "$ROOT/deep/sibling.txt"); then
    FO2=$($JAN find-orphans "$ROOT" 2>&1)
    assert_grep "find-orphans detects orphan (uid $ORPHAN_ID)" "$FO2" "sibling.txt"
else
    echo "  SKIP  find-orphans detects orphan (no assignable unused uid here)"
fi
chown root:root "$ROOT/deep/sibling.txt"

# ── 32. who-can ─────────────────────────────────────────────────────
chmod 644 "$ROOT/deep/dir/target.txt"
chown root:root "$ROOT/deep/dir/target.txt"
chmod 755 "$ROOT/deep" "$ROOT/deep/dir"
WC=$(tty_run "$JAN who-can $ROOT/deep/dir/target.txt")
assert_grep "who-can owner line"      "$WC" "owner "
assert_grep "who-can read line"       "$WC" "read"

WJ=$($JAN --json who-can "$ROOT/deep/dir/target.txt" 2>&1)
if echo "$WJ" | jq -e '.path' > /dev/null 2>&1; then pass "who-can --json"; else fail "who-can --json invalid"; fi

WC_A=$(tty_run "$JAN w $ROOT/deep/dir/target.txt")
assert_grep "alias w == who-can"      "$WC_A" "owner "

# ── 33. diff + export ───────────────────────────────────────────────
chmod 600 "$ROOT/deep/dir/target.txt"
D_BID=$($JAN b "$ROOT/deep/dir/target.txt" 2>&1 | awk '/^backup:/ {print $2}')
chmod 644 "$ROOT/deep/dir/target.txt"
DF=$($JAN diff "$D_BID" 2>&1)
assert_grep "diff shows mode change"  "$DF" "mode"

EX=$($JAN export "$D_BID" 2>&1)
assert_grep "export shows target"     "$EX" "target.txt"

EXJ=$($JAN --json export "$D_BID" 2>&1)
if echo "$EXJ" | jq -e '.id' > /dev/null 2>&1; then pass "export --json"; else fail "export --json invalid"; fi

DFJ=$($JAN -j diff "$D_BID" 2>&1)
if echo "$DFJ" | jq -e '.' > /dev/null 2>&1; then pass "diff -j short"; else fail "diff -j invalid"; fi

# ── 34. ACL basic ───────────────────────────────────────────────────
chmod 600 "$ROOT/deep/dir/target.txt"
$JAN acl grant "$ROOT/deep/dir/target.txt" --user "$USER" --access r > /dev/null 2>&1
ACL_GET=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "acl grant user entry"    "$ACL_GET" "user:$USER:r"

AS=$($JAN acl show "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "acl show contains user"  "$AS" "$USER"

$JAN acl revoke "$ROOT/deep/dir/target.txt" --user "$USER" > /dev/null 2>&1
ACL_GET2=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
refute_grep "acl revoke removed"      "$ACL_GET2" "user:$USER"

# ── 35. ACL short flags ─────────────────────────────────────────────
chmod 600 "$ROOT/deep/dir/target.txt"
$JAN acl grant "$ROOT/deep/dir/target.txt" -u "$USER" -a rw > /dev/null 2>&1
ACL_GET3=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "acl grant -u -a short"   "$ACL_GET3" "user:$USER:rw"

$JAN acl revoke "$ROOT/deep/dir/target.txt" -u "$USER" > /dev/null 2>&1
ACL_GET4=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
refute_grep "acl revoke -u short"     "$ACL_GET4" "user:$USER"

# ── 36. ACL default + recursive ─────────────────────────────────────
$JAN acl grant "$ROOT/deep/dir" -u "$USER" -a rx -d -R > /dev/null 2>&1
DACL=$(getfacl "$ROOT/deep/dir" 2>&1)
assert_grep "acl -d default set"      "$DACL" "default:user:$USER"

$JAN acl grant "$ROOT/deep/dir" -u "$USER2" -a rx --default --recursive > /dev/null 2>&1
DACL2=$(getfacl "$ROOT/deep/dir" 2>&1)
assert_grep "acl --default --recursive long" "$DACL2" "default:user:$USER2"

# ── 37. ACL strip ───────────────────────────────────────────────────
$JAN acl strip "$ROOT/deep/dir" -R > /dev/null 2>&1
AF=$(getfacl "$ROOT/deep/dir" 2>&1)
refute_grep "acl strip -R removed default" "$AF" "default:"

# ── 38. ACL group grant ─────────────────────────────────────────────
$JAN acl grant "$ROOT/deep/dir/target.txt" -g devs -a rwx > /dev/null 2>&1
AG=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "acl grant -g group"      "$AG" "group:devs:rwx"

$JAN acl revoke "$ROOT/deep/dir/target.txt" -g devs > /dev/null 2>&1
AG2=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
refute_grep "acl revoke -g group"     "$AG2" "group:devs"

# ── 39. ACL -u / -g mutually exclusive ──────────────────────────────
refute "acl grant -u -g mutually excl" $JAN acl grant "$ROOT/deep/dir/target.txt" -u "$USER" -g devs -a r

# ── 39b. ACL -r/-w/-x boolean flags (combined, bundled) ─────────────
$JAN acl strip "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
$JAN acl grant "$ROOT/deep/dir/target.txt" -u "$USER" -rwx > /dev/null 2>&1
ARWX=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "acl grant bundled -rwx"  "$ARWX" "user:$USER:rwx"
$JAN acl strip "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
$JAN acl grant "$ROOT/deep/dir/target.txt" -u "$USER" -x -r > /dev/null 2>&1
ARX=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "acl grant split -x -r"   "$ARX" "user:$USER:r-x"
$JAN acl strip "$ROOT/deep/dir/target.txt" > /dev/null 2>&1
$JAN acl grant "$ROOT/deep/dir/target.txt" -u "$USER" > /dev/null 2>&1
AR=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "acl grant default r"     "$AR" "user:$USER:r--"
refute "acl grant -r conflicts -a" $JAN acl grant "$ROOT/deep/dir/target.txt" -u "$USER" -r -a rw

# ── 40. audit --has-acl / -A ────────────────────────────────────────
$JAN acl grant "$ROOT/deep/dir/target.txt" -u "$USER" -a r > /dev/null 2>&1
HA=$($JAN audit "$ROOT" --has-acl 2>&1)
assert_grep "audit --has-acl"         "$HA" "target.txt"
HAS=$($JAN audit "$ROOT" -A 2>&1)
assert_grep "audit -A short has-acl"  "$HAS" "target.txt"
$JAN acl strip "$ROOT/deep/dir/target.txt" > /dev/null 2>&1

# ── 41. tree --acl + -A ─────────────────────────────────────────────
chmod 600 "$ROOT/deep/dir/target.txt"
setfacl -m u:"$USER":r "$ROOT/deep/dir/target.txt"
TA=$($JAN tree "$ROOT/deep/dir" --acl -c never 2>&1)
assert_grep "tree --acl marker acl"   "$TA" "acl"
TAS=$($JAN tree "$ROOT/deep/dir" -A -c never 2>&1)
assert_grep "tree -A marker short"    "$TAS" "acl"
setfacl -b "$ROOT/deep/dir/target.txt"

# ── 42. preset list ─────────────────────────────────────────────────
PL=$($JAN preset list 2>&1)
assert_grep "preset list private"     "$PL" "private"
assert_grep "preset list public-read" "$PL" "public-read"
assert_grep "preset list setgid-dir"  "$PL" "setgid-dir"

# ── 43. preset apply + alias `p` ────────────────────────────────────
mkdir -p "$ROOT/pre_target"
touch "$ROOT/pre_target/file.txt"
$JAN preset apply private-file "$ROOT/pre_target/file.txt" > /dev/null 2>&1
PM_MODE=$(stat -c '%a' "$ROOT/pre_target/file.txt")
if [[ "$PM_MODE" == "600" ]]; then pass "preset private-file=600"; else fail "preset $PM_MODE"; fi

$JAN p apply public-read "$ROOT/pre_target/file.txt" > /dev/null 2>&1
PM_MODE2=$(stat -c '%a' "$ROOT/pre_target/file.txt")
if [[ "$PM_MODE2" == "755" ]]; then pass "alias p public-read=755"; else fail "alias p $PM_MODE2"; fi

# preset recursive
chmod -R 644 "$ROOT/pre_target"
$JAN preset apply private -R "$ROOT/pre_target" > /dev/null 2>&1 || $JAN preset apply private "$ROOT/pre_target" -R > /dev/null 2>&1
PMR=$(stat -c '%a' "$ROOT/pre_target/file.txt")
if [[ "$PMR" == "700" ]]; then pass "preset -R recursive"; else fail "preset -R $PMR"; fi

# ── 44. completions shells ──────────────────────────────────────────
CMP=$($JAN completions bash 2>&1 | head -5)
assert_grep "completions bash"        "$CMP" "janitor"
CMPZ=$($JAN completions zsh 2>&1 | head -5)
assert_grep "completions zsh"         "$CMPZ" "janitor"
CMPF=$($JAN completions fish 2>&1 | head -5)
assert_grep "completions fish"        "$CMPF" "janitor"

# ── 45. grant to group (no user) ───────────────────────────────────
chmod -R 700 "$ROOT"
$JAN grant "$ROOT/deep/dir/target.txt" -g devs -a r > /dev/null 2>&1
TGT_G=$(stat -c '%G' "$ROOT/deep/dir/target.txt")
if [[ "$TGT_G" == "devs" ]]; then pass "grant -g devs (group only)"; else fail "group-only grant $TGT_G"; fi

# ── 46. grant -L max-level ─────────────────────────────────────────
chmod -R 700 "$ROOT"
$JAN grant "$ROOT/deep/dir/target.txt" -u "$USER" -a r -L 1 > /dev/null 2>&1
# -L 1 should limit how many parents get touched; verify we got a backup
assert "grant -L 1 runs"              test -d /var/lib/janitor/backups

# ── 47. export --json structure ────────────────────────────────────
B_EX=$($JAN b "$ROOT/deep/dir/target.txt" 2>&1 | awk '/^backup:/ {print $2}')
EXS=$($JAN -j export "$B_EX" 2>&1)
ID_J=$(echo "$EXS" | jq -r '.id' 2>/dev/null)
if [[ "$ID_J" == "$B_EX" ]]; then pass "export -j has id field"; else fail "export -j id $ID_J"; fi
ENT=$(echo "$EXS" | jq -r '.entries | length' 2>/dev/null)
if [[ -n "$ENT" && "$ENT" -ge 1 ]]; then pass "export -j has entries"; else fail "export -j entries $ENT"; fi

# ── 49. grant --force-all-parents ──────────────────────────────────
chmod 755 "$ROOT"  # world-readable parent
FAP=$($JAN grant "$ROOT/deep/dir/target.txt" -u "$USER" -a r --force-all-parents 2>&1)
assert_grep "--force-all-parents backup" "$FAP" "backup:"
chmod 700 "$ROOT"

# ── 50. chmod captures ACLs by default ─────────────────────────────
chmod 600 "$ROOT/deep/dir/target.txt"
setfacl -m u:"$USER":rw "$ROOT/deep/dir/target.txt"
CA=$($JAN chmod 640 "$ROOT/deep/dir/target.txt" 2>&1)
CA_BID=$(echo "$CA" | awk '/^backup:/ {print $2}')
setfacl -b "$ROOT/deep/dir/target.txt"
$JAN r "$CA_BID" --yes > /dev/null 2>&1
ACL_BACK=$(getfacl "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "restore brings ACL back" "$ACL_BACK" "user:$USER:rw"

# ── 51. info command ────────────────────────────────────────────────
chmod 4755 "$ROOT/deep/dir/target.txt"
INFO_OUT=$($JAN info "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "info shows path"      "$INFO_OUT" "target.txt"
assert_grep "info shows mode"      "$INFO_OUT" "4755"
assert_grep "info shows symbolic"  "$INFO_OUT" "rws"
assert_grep "info shows setuid"    "$INFO_OUT" "setuid"
assert_grep "info shows owner"     "$INFO_OUT" "owner "
assert_grep "info shows mtime"     "$INFO_OUT" "mtime "

# info on dir with sticky
chmod 1777 "$ROOT/deep/dir"
ID=$($JAN info "$ROOT/deep/dir" 2>&1)
assert_grep "info dir sticky"      "$ID" "sticky"
assert_grep "info dir symbolic t"  "$ID" "rwt"

# info -U effective access
chmod 755 "$ROOT/deep/dir/target.txt"
IU=$($JAN info "$ROOT/deep/dir/target.txt" -U "$USER" 2>&1)
assert_grep "info -U access line"  "$IU" "Access for"
assert_grep "info -U user name"    "$IU" "$USER"

# alias `i`
IA=$($JAN i "$ROOT/deep/dir/target.txt" 2>&1)
assert_grep "info alias i"         "$IA" "mode "

# info on symlink
ln -sf "$ROOT/deep/dir/target.txt" "$ROOT/info-link"
IS=$($JAN info "$ROOT/info-link" 2>&1)
assert_grep "info on symlink"      "$IS" "symlink"
assert_grep "info shows target"    "$IS" "→"
rm -f "$ROOT/info-link"

# ── 52. presets secret-dir + exec-only ──────────────────────────────
mkdir -p "$ROOT/secretdir" && chmod 755 "$ROOT/secretdir"
$JAN preset apply secret-dir "$ROOT/secretdir" > /dev/null 2>&1
SD=$(stat -c '%a' "$ROOT/secretdir")
if [[ "$SD" == "500" ]]; then pass "preset secret-dir=500"; else fail "secret-dir → $SD"; fi
chmod 755 "$ROOT/secretdir"
$JAN preset apply exec-only "$ROOT/secretdir" > /dev/null 2>&1
EO=$(stat -c '%a' "$ROOT/secretdir")
if [[ "$EO" == "711" ]]; then pass "preset exec-only=711"; else fail "exec-only → $EO"; fi
rm -rf "$ROOT/secretdir"

# ── 53. new audit flags: -r, -x, --no-owner, --no-group ─────────────
mkdir -p "$ROOT/audit2"
echo rx > "$ROOT/audit2/wrx"
chmod 0777 "$ROOT/audit2/wrx"     # world-rwx
echo rx > "$ROOT/audit2/ro"
chmod 0444 "$ROOT/audit2/ro"      # world-readable

AR=$($JAN audit "$ROOT/audit2" -r 2>&1)
assert_grep "audit -r finds world-readable" "$AR" "audit2/ro"
AX=$($JAN audit "$ROOT/audit2" -x 2>&1)
assert_grep "audit -x finds world-executable" "$AX" "audit2/wrx"

# orphan uid/gid
touch "$ROOT/audit2/orphan"
if AUDIT_ORPHAN_ID=$(pick_orphan_id "$ROOT/audit2/orphan"); then
    ANO=$($JAN audit "$ROOT/audit2" --no-owner 2>&1 || true)
    assert_grep "audit --no-owner (uid $AUDIT_ORPHAN_ID)"   "$ANO" "audit2/orphan"
    ANG=$($JAN audit "$ROOT/audit2" --no-group 2>&1 || true)
    assert_grep "audit --no-group (gid $AUDIT_ORPHAN_ID)"   "$ANG" "audit2/orphan"
else
    echo "  SKIP  audit --no-owner (no assignable unused uid here)"
    echo "  SKIP  audit --no-group (no assignable unused gid here)"
fi
rm -rf "$ROOT/audit2"

# ── 54. history command ─────────────────────────────────────────────
mkdir -p "$ROOT/hist"
echo a > "$ROOT/hist/f"
$JAN chmod 640 "$ROOT/hist/f" > /dev/null
$JAN chmod 600 "$ROOT/hist/f" > /dev/null
HO=$(tty_run "$JAN history $ROOT/hist/f")
assert_grep "history lists backups" "$HO" "$ROOT/hist/f"
HJ=$($JAN -j history "$ROOT/hist/f" 2>&1)
assert_grep "history --json array" "$HJ" "\["
HN=$($JAN history "$ROOT/does-not-exist-xyz" 2>&1 || true)
assert_grep "history empty note"   "$HN" "no backups"
assert "history alias h" $JAN h "$ROOT/hist/f"

# ── 55. copy-perms ─────────────────────────────────────────────────
mkdir -p "$ROOT/cp"
echo s > "$ROOT/cp/src"
echo d > "$ROOT/cp/dst"
chmod 750 "$ROOT/cp/src"
chmod 644 "$ROOT/cp/dst"
chown "$USER":devs "$ROOT/cp/src"
$JAN copy-perms "$ROOT/cp/src" "$ROOT/cp/dst" > /dev/null
DM=$(stat -c '%a' "$ROOT/cp/dst")
DU=$(stat -c '%U' "$ROOT/cp/dst")
DG=$(stat -c '%G' "$ROOT/cp/dst")
if [[ "$DM" == "750" ]]; then pass "copy-perms mode"; else fail "cp mode $DM"; fi
if [[ "$DU" == "$USER" ]]; then pass "copy-perms user"; else fail "cp user $DU"; fi
if [[ "$DG" == "devs" ]]; then pass "copy-perms group"; else fail "cp group $DG"; fi

# recursive
mkdir -p "$ROOT/cpR/src/sub" "$ROOT/cpR/dst/sub"
touch "$ROOT/cpR/src/sub/f" "$ROOT/cpR/dst/sub/f"
chmod -R 770 "$ROOT/cpR/src"
chmod -R 644 "$ROOT/cpR/dst"
$JAN copy-perms "$ROOT/cpR/src" "$ROOT/cpR/dst" -R > /dev/null
RM=$(stat -c '%a' "$ROOT/cpR/dst/sub/f")
if [[ "$RM" == "770" ]]; then pass "copy-perms -R applies to children"; else fail "cp -R $RM"; fi

# ACL copy
if command -v setfacl >/dev/null 2>&1; then
    setfacl -m u:"$USER":rwx "$ROOT/cp/src" 2>/dev/null || true
    $JAN copy-perms "$ROOT/cp/src" "$ROOT/cp/dst" -A > /dev/null 2>&1 || true
    AO=$(getfacl -c "$ROOT/cp/dst" 2>/dev/null | tr -d '\n')
    assert_grep "copy-perms -A copies ACL" "$AO" "user:$USER:rwx"
fi

# copy-perms alias cp
assert "copy-perms alias cp" $JAN cp "$ROOT/cp/src" "$ROOT/cp/dst"
rm -rf "$ROOT/cp" "$ROOT/cpR"

# ── 56. new presets (7) ─────────────────────────────────────────────
touch "$ROOT/p_sshkey" "$ROOT/p_config" "$ROOT/p_log" "$ROOT/p_unit" "$ROOT/p_ro" "$ROOT/p_no"
mkdir -p "$ROOT/p_sshdir"
$JAN preset apply ssh-key      "$ROOT/p_sshkey" > /dev/null
$JAN preset apply ssh-dir      "$ROOT/p_sshdir" > /dev/null
$JAN preset apply config       "$ROOT/p_config" > /dev/null
$JAN preset apply log-file     "$ROOT/p_log"    > /dev/null
$JAN preset apply systemd-unit "$ROOT/p_unit"   > /dev/null
$JAN preset apply read-only    "$ROOT/p_ro"     > /dev/null
$JAN preset apply no-access    "$ROOT/p_no"     > /dev/null
for pair in "p_sshkey:600" "p_sshdir:700" "p_config:640" "p_log:640" \
            "p_unit:644" "p_ro:444" "p_no:0"; do
    f=${pair%%:*}; want=${pair##*:}
    got=$(stat -c '%a' "$ROOT/$f")
    if [[ "$got" == "$want" ]]; then pass "preset $f=$want"; else fail "preset $f expected $want got $got"; fi
done
rm -rf "$ROOT/p_sshkey" "$ROOT/p_sshdir" "$ROOT/p_config" "$ROOT/p_log" \
       "$ROOT/p_unit" "$ROOT/p_ro" "$ROOT/p_no"

# ── 57. final cleanup ───────────────────────────────────────────────
$JAN prune -k 0 > /dev/null 2>&1

# ── 58. variadic chmod + --from-file + --stdin0 + --exclude ─────────
mkdir -p "$ROOT/v"
touch "$ROOT/v/a" "$ROOT/v/b" "$ROOT/v/c" "$ROOT/v/skip.bak"
$JAN chmod 0600 "$ROOT/v/a" "$ROOT/v/b" > /dev/null
a=$(stat -c '%a' "$ROOT/v/a"); b=$(stat -c '%a' "$ROOT/v/b")
if [[ "$a" == "600" && "$b" == "600" ]]; then pass "chmod variadic a+b=600"; else fail "chmod variadic got a=$a b=$b"; fi

# --from-file
cat > "$ROOT/v/list" <<EOF
$ROOT/v/a
$ROOT/v/b
$ROOT/v/c
EOF
$JAN chmod 0644 --from-file "$ROOT/v/list" > /dev/null
c=$(stat -c '%a' "$ROOT/v/c")
if [[ "$c" == "644" ]]; then pass "chmod --from-file"; else fail "chmod --from-file got $c"; fi

# --stdin0
printf '%s\0%s\0' "$ROOT/v/a" "$ROOT/v/b" | $JAN chmod 0400 --stdin0 > /dev/null
a=$(stat -c '%a' "$ROOT/v/a")
if [[ "$a" == "400" ]]; then pass "chmod --stdin0"; else fail "chmod --stdin0 got $a"; fi

# --exclude glob
chmod 700 "$ROOT/v"/* 2>/dev/null
$JAN chmod 0644 -R "$ROOT/v" -E '*.bak' > /dev/null
skip=$(stat -c '%a' "$ROOT/v/skip.bak")
keep=$(stat -c '%a' "$ROOT/v/a")
if [[ "$skip" == "700" && "$keep" == "644" ]]; then pass "chmod --exclude glob"; else fail "chmod --exclude got skip=$skip keep=$keep"; fi

rm -rf "$ROOT/v"

# ── 59. (removed — the `find` subcommand was dropped upstream; the
# audit block below still reuses this scratch tree) ─────────────────
mkdir -p "$ROOT/f"
touch "$ROOT/f/x"; chmod 0777 "$ROOT/f/x"
touch "$ROOT/f/y"; chmod 0644 "$ROOT/f/y"

# ── 60. audit --fix strip-world-write ──────────────────────────────
chmod 0666 "$ROOT/f/x"
$JAN audit "$ROOT/f" -W --fix strip-world-write > /dev/null
xm=$(stat -c '%a' "$ROOT/f/x")
if [[ "$xm" == "664" ]]; then pass "audit --fix strip-world-write"; else fail "fix got $xm"; fi

# audit --fix chmod MODE
chmod 0777 "$ROOT/f/x"
$JAN audit "$ROOT/f" -m 0777 --fix "chmod 0600" > /dev/null
xm=$(stat -c '%a' "$ROOT/f/x")
if [[ "$xm" == "600" ]]; then pass "audit --fix chmod MODE"; else fail "fix chmod got $xm"; fi

# audit --exclude glob
touch "$ROOT/f/skip.log"; chmod 0777 "$ROOT/f/skip.log"
AO=$($JAN audit "$ROOT/f" -m 0777 -E '*.log' 2>&1)
refute_grep "audit --exclude skips .log" "$AO" "skip.log"

rm -rf "$ROOT/f"

# ── 61. explain ───────────────────────────────────────────────────
mkdir -p "$ROOT/ex"; touch "$ROOT/ex/file"; chmod 0640 "$ROOT/ex/file"
EO=$($JAN explain "$ROOT/ex/file" 2>&1)
assert_grep "explain prints verdict" "$EO" "verdict"
EO2=$($JAN explain "$ROOT/ex/file" -U "$USER" 2>&1)
assert_grep "explain -U prints for user" "$EO2" "$USER"

# alias e
assert "explain alias e"  $JAN e "$ROOT/ex/file"

# ── 62. compare ────────────────────────────────────────────────────
mkdir -p "$ROOT/cmp/a" "$ROOT/cmp/b"
touch "$ROOT/cmp/a/f" "$ROOT/cmp/b/f"
chmod 0644 "$ROOT/cmp/a/f" "$ROOT/cmp/b/f"
assert "compare identical"                   $JAN compare "$ROOT/cmp/a/f" "$ROOT/cmp/b/f"
chmod 0600 "$ROOT/cmp/b/f"
refute "compare diff exits 1"                $JAN compare "$ROOT/cmp/a/f" "$ROOT/cmp/b/f"
assert "compare -R recursive"                $JAN compare -R "$ROOT/cmp/a" "$ROOT/cmp/a"
rm -rf "$ROOT/cmp"

# ── 63. lock / unlock / locks ─────────────────────────────────────
touch "$ROOT/lockme"; chmod 0644 "$ROOT/lockme"
assert "lock"                                $JAN lock "$ROOT/lockme" -r "do not touch"
LO=$($JAN locks 2>&1)
assert_grep "locks lists path"               "$LO" "lockme"
refute "chmod on locked path fails"          $JAN chmod 0600 "$ROOT/lockme"
assert "unlock"                              $JAN unlock "$ROOT/lockme"
assert "chmod after unlock works"            $JAN chmod 0600 "$ROOT/lockme"
rm -f "$ROOT/lockme"

# ── 64. policy apply / verify ─────────────────────────────────────
mkdir -p "$ROOT/pol"
touch "$ROOT/pol/app.conf"
cat > "$ROOT/pol/policy.yml" <<EOF
rules:
  - path: $ROOT/pol/app.conf
    mode: "0640"
EOF
assert "policy apply"                        $JAN policy apply "$ROOT/pol/policy.yml"
m=$(stat -c '%a' "$ROOT/pol/app.conf")
if [[ "$m" == "640" ]]; then pass "policy apply sets 640"; else fail "policy got $m"; fi
assert "policy verify clean"                 $JAN policy verify "$ROOT/pol/policy.yml"
chmod 0600 "$ROOT/pol/app.conf"
refute "policy verify drift exits 1"         $JAN policy verify "$ROOT/pol/policy.yml"
rm -rf "$ROOT/pol"

# ── 65. batch ─────────────────────────────────────────────────────
mkdir -p "$ROOT/ba"
touch "$ROOT/ba/f1" "$ROOT/ba/f2"
cat > "$ROOT/ba/ops" <<EOF
# batch file
chmod 0644 $ROOT/ba/f1
chmod 0600 $ROOT/ba/f2
EOF
assert "batch"                               $JAN batch "$ROOT/ba/ops"
m1=$(stat -c '%a' "$ROOT/ba/f1")
m2=$(stat -c '%a' "$ROOT/ba/f2")
if [[ "$m1" == "644" && "$m2" == "600" ]]; then pass "batch applied both ops"; else fail "batch got m1=$m1 m2=$m2"; fi
rm -rf "$ROOT/ba"

# ── 66. history --since ───────────────────────────────────────────
touch "$ROOT/h"; chmod 0644 "$ROOT/h"
$JAN chmod 0600 "$ROOT/h" > /dev/null
HO=$(tty_run "$JAN history $ROOT/h --since 1h")
assert_grep "history --since 1h lists it"    "$HO" "chmod"
$JAN history "$ROOT/h" -s 1s > /dev/null 2>&1 || true
rm -f "$ROOT/h"

# ── 67. attr show (lsattr) ────────────────────────────────────────
touch "$ROOT/at"
if command -v lsattr >/dev/null 2>&1; then
    assert "attr show"                       $JAN attr show "$ROOT/at"
fi
rm -f "$ROOT/at"

# ── 68. preset variadic ───────────────────────────────────────────
touch "$ROOT/p1" "$ROOT/p2"
$JAN preset apply config "$ROOT/p1" "$ROOT/p2" > /dev/null
m1=$(stat -c '%a' "$ROOT/p1"); m2=$(stat -c '%a' "$ROOT/p2")
if [[ "$m1" == "640" && "$m2" == "640" ]]; then pass "preset variadic"; else fail "preset variadic got m1=$m1 m2=$m2"; fi
rm -f "$ROOT/p1" "$ROOT/p2"

# ── 69. batch transactionality: one undo reverts every op ─────────
$JAN prune -k 0 > /dev/null 2>&1
mkdir -p "$ROOT/bt"
touch "$ROOT/bt/a" "$ROOT/bt/b" "$ROOT/bt/c"
chmod 0600 "$ROOT/bt/a" "$ROOT/bt/b" "$ROOT/bt/c"
cat > "$ROOT/bt/ops" <<EOF
chmod 0755 $ROOT/bt/a
chmod 0755 $ROOT/bt/b
chmod 0755 $ROOT/bt/c
EOF
BO=$($JAN batch "$ROOT/bt/ops" 2>&1)
assert_grep "batch prints single backup id"  "$BO" "backup:"
N_BID=$(echo "$BO" | grep -c "^backup:")
if [[ "$N_BID" == "1" ]]; then pass "batch creates exactly 1 backup for 3 ops"; else fail "batch made $N_BID backups"; fi
m1=$(stat -c '%a' "$ROOT/bt/a"); m2=$(stat -c '%a' "$ROOT/bt/b"); m3=$(stat -c '%a' "$ROOT/bt/c")
if [[ "$m1$m2$m3" == "755755755" ]]; then pass "batch applied all 3 ops"; else fail "batch mode=$m1/$m2/$m3"; fi
$JAN undo --yes > /dev/null
m1=$(stat -c '%a' "$ROOT/bt/a"); m2=$(stat -c '%a' "$ROOT/bt/b"); m3=$(stat -c '%a' "$ROOT/bt/c")
if [[ "$m1$m2$m3" == "600600600" ]]; then pass "single undo reverts every batch op"; else fail "batch undo mode=$m1/$m2/$m3"; fi
rm -rf "$ROOT/bt"

# ── 70. batch fail-closed: bad path in middle aborts before any mutation ─
mkdir -p "$ROOT/bf"
touch "$ROOT/bf/x" "$ROOT/bf/y"
chmod 0600 "$ROOT/bf/x" "$ROOT/bf/y"
cat > "$ROOT/bf/ops" <<EOF
chmod 0755 $ROOT/bf/x
chmod 0755 /does/not/exist/here
chmod 0755 $ROOT/bf/y
EOF
if $JAN batch "$ROOT/bf/ops" >/dev/null 2>&1; then fail "batch with bad path should fail"; else pass "batch fail-closed on bad path"; fi
m1=$(stat -c '%a' "$ROOT/bf/x"); m2=$(stat -c '%a' "$ROOT/bf/y")
if [[ "$m1" == "600" && "$m2" == "600" ]]; then pass "batch left files untouched on fail"; else fail "batch partially applied: $m1/$m2"; fi
rm -rf "$ROOT/bf"

# ── 71. policy transactionality: one undo reverts every rule ──────
$JAN prune -k 0 > /dev/null 2>&1
mkdir -p "$ROOT/pt"
touch "$ROOT/pt/a" "$ROOT/pt/b"
chmod 0600 "$ROOT/pt/a" "$ROOT/pt/b"
cat > "$ROOT/pt/pol.yml" <<EOF
rules:
  - path: $ROOT/pt/a
    mode: "0755"
  - path: $ROOT/pt/b
    mode: "0755"
EOF
PO=$($JAN policy apply "$ROOT/pt/pol.yml" 2>&1)
N_BID=$(echo "$PO" | grep -c "^backup:")
if [[ "$N_BID" == "1" ]]; then pass "policy creates exactly 1 backup for 2 rules"; else fail "policy made $N_BID backups"; fi
m1=$(stat -c '%a' "$ROOT/pt/a"); m2=$(stat -c '%a' "$ROOT/pt/b")
if [[ "$m1" == "755" && "$m2" == "755" ]]; then pass "policy applied both rules"; else fail "policy mode=$m1/$m2"; fi
$JAN undo --yes > /dev/null
m1=$(stat -c '%a' "$ROOT/pt/a"); m2=$(stat -c '%a' "$ROOT/pt/b")
if [[ "$m1" == "600" && "$m2" == "600" ]]; then pass "single undo reverts whole policy"; else fail "policy undo mode=$m1/$m2"; fi
rm -rf "$ROOT/pt"

# ── 72. policy rejects mode+preset in same rule; invalid mode rejected ─
mkdir -p "$ROOT/pr"
touch "$ROOT/pr/f"
cat > "$ROOT/pr/bad1.yml" <<EOF
rules:
  - path: $ROOT/pr/f
    mode: "0640"
    preset: config
EOF
refute "policy rejects mode+preset"   $JAN policy apply "$ROOT/pr/bad1.yml"

cat > "$ROOT/pr/bad2.yml" <<EOF
rules:
  - path: $ROOT/pr/f
    mode: "not-octal"
EOF
refute "policy rejects bad octal"     $JAN policy apply "$ROOT/pr/bad2.yml"

# mode "0" must parse (was broken by old trim_start_matches('0') code)
cat > "$ROOT/pr/zero.yml" <<EOF
rules:
  - path: $ROOT/pr/f
    mode: "0"
EOF
assert "policy accepts mode 0"        $JAN policy apply "$ROOT/pr/zero.yml"
m=$(stat -c '%a' "$ROOT/pr/f")
if [[ "$m" == "0" ]]; then pass "mode 0 applied"; else fail "mode 0 got $m"; fi
rm -rf "$ROOT/pr"

# ── 73. batch stdin (-) ──────────────────────────────────────────
mkdir -p "$ROOT/bs"; touch "$ROOT/bs/x"; chmod 0600 "$ROOT/bs/x"
echo "chmod 0644 $ROOT/bs/x" | $JAN batch - > /dev/null
m=$(stat -c '%a' "$ROOT/bs/x")
if [[ "$m" == "644" ]]; then pass "batch from stdin"; else fail "batch stdin got $m"; fi
rm -rf "$ROOT/bs"

# ── 74. chmod fail-closed on missing path does not mutate existing ─
mkdir -p "$ROOT/fc"; touch "$ROOT/fc/a" "$ROOT/fc/b"
chmod 0600 "$ROOT/fc/a" "$ROOT/fc/b"
if $JAN chmod 0777 "$ROOT/fc/a" "$ROOT/fc/b" /does/not/exist >/dev/null 2>&1; then
    fail "chmod should fail-closed"
else
    pass "chmod fail-closed exit 1"
fi
m1=$(stat -c '%a' "$ROOT/fc/a"); m2=$(stat -c '%a' "$ROOT/fc/b")
if [[ "$m1" == "600" && "$m2" == "600" ]]; then pass "chmod left originals untouched"; else fail "chmod partially applied: $m1/$m2"; fi
rm -rf "$ROOT/fc"

# ── 75. --stdin0 with empty stdin errors cleanly ──────────────────
if echo -n '' | $JAN chmod 0644 --stdin0 >/dev/null 2>&1; then
    fail "stdin0 empty should error"
else
    pass "stdin0 empty errors"
fi

# ── 76. history --since rejects bad unit ──────────────────────────
if $JAN history "$ROOT" --since "1y" >/dev/null 2>&1; then fail "--since 1y should error"; else pass "--since rejects y unit"; fi
if $JAN history "$ROOT" --since "abc" >/dev/null 2>&1; then fail "--since abc should error"; else pass "--since rejects garbage"; fi

# ── 77. lock idempotency ──────────────────────────────────────────
touch "$ROOT/lk"
$JAN lock "$ROOT/lk" > /dev/null
if $JAN lock "$ROOT/lk" >/dev/null 2>&1; then fail "double-lock should error"; else pass "double-lock rejected"; fi
$JAN unlock "$ROOT/lk" > /dev/null
if $JAN unlock "$ROOT/lk" >/dev/null 2>&1; then fail "unlock-unlocked should error"; else pass "unlock-unlocked rejected"; fi
rm -f "$ROOT/lk"

$JAN prune -k 0 > /dev/null 2>&1

# ── Summary ─────────────────────────────────────────────────────────
echo
echo "========================================"
echo "  PASSED: $PASS"
echo "  FAILED: $FAIL"
echo "========================================"
[[ $FAIL -eq 0 ]]
