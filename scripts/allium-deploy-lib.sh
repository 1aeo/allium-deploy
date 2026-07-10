#!/usr/bin/env bash

run_with_timeout() {
    local seconds="$1"
    shift

    if command -v timeout &>/dev/null; then
        timeout "$seconds" "$@"
        return $?
    fi

    "$@" &
    local pid=$!
    local elapsed=0
    while kill -0 "$pid" 2>/dev/null; do
        if (( elapsed >= seconds )); then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    wait "$pid"
}
