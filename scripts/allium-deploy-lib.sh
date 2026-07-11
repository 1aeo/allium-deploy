#!/usr/bin/env bash

run_with_timeout() {
    local seconds="$1"
    shift

    if command -v timeout &>/dev/null; then
        local start status end
        start=$(date +%s)
        timeout --kill-after=5 "$seconds" "$@"
        status=$?
        if [[ "$status" -eq 137 ]]; then
            end=$(date +%s)
            if (( end - start >= seconds )); then
                return 124
            fi
        fi
        return "$status"
    fi

    "$@" &
    local pid=$!
    local elapsed=0
    while kill -0 "$pid" 2>/dev/null; do
        if (( elapsed >= seconds )); then
            kill "$pid" 2>/dev/null || true
            local grace_elapsed=0
            while kill -0 "$pid" 2>/dev/null; do
                if (( grace_elapsed >= 5 )); then
                    kill -KILL "$pid" 2>/dev/null || true
                    break
                fi
                sleep 1
                grace_elapsed=$((grace_elapsed + 1))
            done
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    wait "$pid"
}
