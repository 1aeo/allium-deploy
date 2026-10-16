#!/usr/bin/env bash

set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

MOCK_BIN="$TMP_DIR/mock-bin"
STAT_COUNT="$TMP_DIR/stat-count"
FINGERPRINT='DB1629B59707F744A0C7933E56B6802786FFC317'
PREVIEW='https://12345678-allium-shadow-test.test.workers.dev'
REAL_STAT=$(command -v stat)
mkdir -p "$MOCK_BIN"

# The GNU branch needs a find with -printf: Linux CI has one, macOS may have gfind.
REAL_FIND=$(command -v find)
GNU_FIND=
if "$REAL_FIND" --version 2>/dev/null | grep -q GNU; then
    GNU_FIND="$REAL_FIND"
elif command -v gfind >/dev/null 2>&1; then
    GNU_FIND=$(command -v gfind)
fi

# find shim: optionally rejects -printf like BSD find, and can make the
# largest-file walk (the only call that mentions _headers) fail part-way or
# outright, to prove the verifier treats find errors exactly as before.
cat > "$MOCK_BIN/find" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
selection=0
for arg in "$@"; do
    if [[ "$arg" == -printf && "${MOCK_FIND_REJECT_PRINTF:-0}" == 1 ]]; then
        echo "find: -printf: unknown primary or operator" >&2
        exit 1
    fi
    [[ "$arg" == _headers ]] && selection=1
done
if (( selection )); then
    case "${MOCK_FIND_SELECTION:-ok}" in
        fail) echo "find: simulated walk failure" >&2; exit 1 ;;
        partial)
            # Drop one known small file, as a vanished entry would, then fail.
            "$MOCK_FIND_REAL" "$@" | grep -v 'nested/small\.bin'
            echo "find: simulated vanished entry" >&2
            exit 1
            ;;
    esac
fi
exec "$MOCK_FIND_REAL" "$@"
EOF

# stat shim: counts calls so each test can tell which selection branch ran.
cat > "$MOCK_BIN/stat" <<'EOF'
#!/usr/bin/env bash
printf 'x\n' >> "$MOCK_STAT_COUNT"
exec "$MOCK_STAT_REAL" "$@"
EOF

# curl fixture: a healthy immutable preview serving every file in the tree.
cat > "$MOCK_BIN/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=/dev/null
headers=
url=
while (( $# )); do
    case "$1" in
        --output) output="$2"; shift 2 ;;
        --dump-header) headers="$2"; shift 2 ;;
        --max-time|--write-out) shift 2 ;;
        --silent|--show-error) shift ;;
        http*) url="$1"; shift ;;
        *) shift ;;
    esac
done
path="/${url#*://*/}"
[[ "$url" =~ ^https://[^/]+/$ ]] && path=/
status=200
case "$path" in
    /__allium_cfassets_missing_probe__) status=404; : > "$output" ;;
    /search\?q=*) status=302 ;;
    /nested) status=307 ;;
    */) [[ "$output" == /dev/null ]] || cp "$MOCK_SOURCE_DIR${path}index.html" "$output" ;;
    *)
        [[ -f "$MOCK_SOURCE_DIR$path" ]] || { echo "unexpected fixture URL: $url" >&2; exit 90; }
        cp "$MOCK_SOURCE_DIR$path" "$output"
        ;;
esac
if [[ -n "$headers" ]]; then
    if [[ "$path" == / ]]; then
        printf 'HTTP/1.1 200 OK\r\ncache-control: public, max-age=0, must-revalidate\r\nx-robots-tag: noindex, nofollow\r\n\r\n' > "$headers"
    else
        printf 'HTTP/1.1 302 Found\r\nlocation: /relay/%s/\r\n\r\n' "$MOCK_FINGERPRINT" > "$headers"
    fi
fi
printf '%s' "$status"
EOF
chmod 0755 "$MOCK_BIN/find" "$MOCK_BIN/stat" "$MOCK_BIN/curl"

write_bytes() {
    head -c "$2" /dev/zero | tr '\0' "$3" > "$1"
}

# Minimal site plus a _headers file larger than everything else (it must
# never be chosen) and two files that tie for the largest size.
make_tree() {
    local dir="$1"
    mkdir -p "$dir/nested" "$dir/dir with space"
    printf '<html>root</html>\n' > "$dir/index.html"
    printf '<html>nested route</html>\n' > "$dir/nested/index.html"
    printf '{"meta":{"version":"1.6"},"relays":[{"f":"%s"}]}\n' "$FINGERPRINT" > "$dir/search-index.json"
    write_bytes "$dir/_headers" 9000 h
    write_bytes "$dir/nested/small.bin" 100 s
    write_bytes "$dir/dir with space/tie b.bin" 4096 b
    write_bytes "$dir/dir with space/tie a.bin" 4096 a
}

TREE="$TMP_DIR/tree"
make_tree "$TREE"

# A tree whose largest file has a tab and a space in its name: the record's
# TAB separator splits on the first tab only, so the full path survives.
TAB_TREE="$TMP_DIR/tab-tree"
make_tree "$TAB_TREE"
TAB_NAME=$'tab\there now.bin'
write_bytes "$TAB_TREE/$TAB_NAME" 5000 t

# A tree with a file whose name embeds a newline followed by a forged
# "size<TAB>name" record. The forged size must never be selected.
NL_TREE="$TMP_DIR/newline-tree"
make_tree "$NL_TREE"
NL_NAME=$'evil\n999999999\tREADME.md'
if printf 'x\n' > "$NL_TREE/$NL_NAME" 2>/dev/null; then
    NL_SUPPORTED=1
else
    NL_SUPPORTED=0
fi

# run_verifier <real-find> <reject-printf 0|1> <selection ok|partial|fail> <tree>
# Sets RUN_OUTPUT, RUN_STATUS and RUN_STATS (number of stat calls).
run_verifier() {
    : > "$STAT_COUNT"
    set +e
    RUN_OUTPUT=$(PATH="$MOCK_BIN:$PATH" \
        MOCK_FIND_REAL="$1" \
        MOCK_FIND_REJECT_PRINTF="$2" \
        MOCK_FIND_SELECTION="$3" \
        MOCK_STAT_REAL="$REAL_STAT" \
        MOCK_STAT_COUNT="$STAT_COUNT" \
        MOCK_SOURCE_DIR="$4" \
        MOCK_FINGERPRINT="$FINGERPRINT" \
        CF_ASSETS_VERIFY_ATTEMPTS=1 \
        CF_ASSETS_VERIFY_MAX_ATTEMPTS=1 \
        CF_ASSETS_VERIFY_RETRY_DELAY=0 \
        "$REPO_DIR/scripts/allium-deploy-verify-cfassets.sh" "$PREVIEW" "$4" 2>&1)
    RUN_STATUS=$?
    set -e
    RUN_STATS=$(wc -l < "$STAT_COUNT" | tr -d ' ')
}

# assert_largest <label> <expected url path>
assert_largest() {
    [[ "$RUN_STATUS" == 0 ]] || fail "$1: verifier exited $RUN_STATUS: $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" == *"largest ok: $2 sha256="* ]] || fail "$1: expected largest file $2, got: $RUN_OUTPUT"
}

# assert_branch <label> <gnu|fallback>
assert_branch() {
    if [[ "$2" == gnu ]]; then
        [[ "$RUN_STATS" == 0 ]] || fail "$1: GNU find branch still ran stat $RUN_STATS times"
    else
        (( RUN_STATS > 0 )) || fail "$1: fallback branch never ran stat"
    fi
}

check_branch() {
    local branch="$1" real_find="$2" reject_printf="$3"

    run_verifier "$real_find" "$reject_printf" ok "$TREE"
    assert_largest "$branch tie" '/dir with space/tie a.bin'
    assert_branch "$branch tie" "$branch"
    pass "$branch branch: equal sizes pick the first path in sort order, spaces kept, _headers skipped"

    run_verifier "$real_find" "$reject_printf" ok "$TREE//"
    assert_largest "$branch trailing slash" '/dir with space/tie a.bin'
    pass "$branch branch: a source directory given with trailing slashes still selects the largest file"

    run_verifier "$real_find" "$reject_printf" ok "$TAB_TREE"
    assert_largest "$branch tab" "/$TAB_NAME"
    assert_branch "$branch tab" "$branch"
    pass "$branch branch: a tab in the largest file's name survives the size<TAB>path record"

    if (( NL_SUPPORTED )); then
        run_verifier "$real_find" "$reject_printf" ok "$NL_TREE"
        assert_largest "$branch newline name" '/dir with space/tie a.bin'
        pass "$branch branch: a newline in a file name cannot forge the largest-file record"
    fi

    run_verifier "$real_find" "$reject_printf" partial "$TREE"
    assert_largest "$branch partial walk" '/dir with space/tie a.bin'
    pass "$branch branch: a find error after a partial listing still selects the largest file"

    run_verifier "$real_find" "$reject_printf" fail "$TREE"
    [[ "$RUN_STATUS" == 2 ]] || fail "$branch failed walk exited $RUN_STATUS instead of 2: $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" == *'Could not select largest file'* ]] || fail "$branch failed walk did not explain itself: $RUN_OUTPUT"
    pass "$branch branch: a walk that lists nothing fails closed with the same error"
}

if [[ -n "$GNU_FIND" ]]; then
    check_branch gnu "$GNU_FIND" 0
else
    echo "ok - # SKIP GNU find branch: no GNU find or gfind on this host"
fi
check_branch fallback "$REAL_FIND" 1
