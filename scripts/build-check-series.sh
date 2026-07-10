#!/bin/bash
# Build and optionally test every commit in a series to verify bisectability.
# Uses a temporary git worktree so the main repo stays usable while this runs.
#
# Usage: scripts/build-check-series.sh [--test] [BASE_COMMIT]
#   --test        Run tests/tests after each successful build
#   BASE_COMMIT   defaults to origin/master

RUN_TESTS=0
if [ "$1" = "--test" ]; then
    RUN_TESTS=1
    shift
fi

BASE=${1:-origin/master}
TOTAL=$(git rev-list --count ${BASE}..HEAD)
if [ "$TOTAL" -eq 0 ]; then
    echo "No commits in ${BASE}..HEAD"
    exit 0
fi

# Create a temporary worktree so checkouts don't disturb the main repo
WORKTREE=$(mktemp -d /tmp/pahole-build-check.XXXXXX)
git worktree add -q --detach "$WORKTREE" HEAD 2>/dev/null || {
    echo "error: failed to create worktree at $WORKTREE" >&2
    rmdir "$WORKTREE"
    exit 1
}

cleanup_worktree() {
    git worktree remove --force "$WORKTREE" 2>/dev/null
    rm -rf "$WORKTREE" 2>/dev/null
}

handle_int() {
    INTERRUPTED=1
}

trap cleanup_worktree EXIT
trap handle_int INT TERM

# Set up cmake build directory inside the worktree
BUILD_DIR="$WORKTREE/build"
mkdir -p "$BUILD_DIR"
if ! cmake -S "$WORKTREE" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release > "$BUILD_DIR/.build-check.log" 2>&1; then
    echo "error: cmake setup failed:" >&2
    tail -10 "$BUILD_DIR/.build-check.log" >&2
    exit 1
fi

WIDTH=74
INTERRUPTED=0
COMMIT_NUM=0
BUILD_FAIL_LIST=""
TEST_FAIL_LIST=""
NR_BUILD_FAIL=0
NR_TEST_FAIL=0
NR_TEST_SKIP=0

for sha in $(git rev-list --reverse ${BASE}..HEAD); do
    COMMIT_NUM=$((COMMIT_NUM + 1))
    [ "$INTERRUPTED" -eq 1 ] && break
    SHORT=$(git log --oneline -1 $sha)
    LABEL=$(printf "%3d/%-3d: %s" "$COMMIT_NUM" "$TOTAL" "$SHORT")

    printf "%-${WIDTH}.${WIDTH}s" "$LABEL"

    if ! git -C "$WORKTREE" checkout -q $sha 2>/dev/null; then
        echo ": FAILED! (checkout)"
        BUILD_FAIL_LIST="$BUILD_FAIL_LIST
  $LABEL (checkout)"
        NR_BUILD_FAIL=$((NR_BUILD_FAIL + 1))
        continue
    fi

    if ! make -C "$BUILD_DIR" -j32 > "$BUILD_DIR/.build-check.log" 2>&1; then
        if [ "$INTERRUPTED" -eq 1 ]; then
            echo ""
            break
        fi
        echo ": FAILED! (build)"
        tail -5 "$BUILD_DIR/.build-check.log" | sed 's/^/     /'
        BUILD_FAIL_LIST="$BUILD_FAIL_LIST
  $LABEL (build)"
        NR_BUILD_FAIL=$((NR_BUILD_FAIL + 1))
        continue
    fi

    if [ "$RUN_TESTS" -eq 1 ]; then
        if [ ! -x "$BUILD_DIR/pahole" ]; then
            echo ": FAILED! (pahole binary not built)"
            BUILD_FAIL_LIST="$BUILD_FAIL_LIST
  $LABEL (no pahole binary)"
            NR_BUILD_FAIL=$((NR_BUILD_FAIL + 1))
            continue
        fi
        if [ ! -x "$WORKTREE/tests/tests" ]; then
            echo ": Ok (no test runner)"
            NR_TEST_SKIP=$((NR_TEST_SKIP + 1))
            continue
        fi
        if ! PATH="$BUILD_DIR:$PATH" "$WORKTREE/tests/tests" > "$BUILD_DIR/.test-check.log" 2>&1; then
            if [ "$INTERRUPTED" -eq 1 ]; then
                echo ""
                break
            fi
            echo ": FAILED! (test)"
            grep 'FAILED!' "$BUILD_DIR/.test-check.log" | sed 's/^/     /'
            TEST_FAIL_LIST="$TEST_FAIL_LIST
  $LABEL (test)"
            NR_TEST_FAIL=$((NR_TEST_FAIL + 1))
            continue
        fi
    fi

    echo ": Ok"
done

echo ""
if [ $NR_BUILD_FAIL -gt 0 ] || [ $NR_TEST_FAIL -gt 0 ]; then
    if [ $NR_BUILD_FAIL -gt 0 ]; then
        echo "Build failures ($NR_BUILD_FAIL):"
        echo "$BUILD_FAIL_LIST"
        echo ""
    fi
    if [ $NR_TEST_FAIL -gt 0 ]; then
        echo "Test failures ($NR_TEST_FAIL):"
        echo "$TEST_FAIL_LIST"
        echo ""
    fi
    exit 1
fi

if [ "$RUN_TESTS" -eq 1 ]; then
    SKIP_MSG=""
    [ "$NR_TEST_SKIP" -gt 0 ] && SKIP_MSG=", $NR_TEST_SKIP skipped tests"
    echo "All $TOTAL commits build and test ok${SKIP_MSG}"
else
    echo "All $TOTAL commits build ok"
fi
