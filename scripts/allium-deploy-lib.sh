#!/usr/bin/env bash

capture_env_overrides() {
    local name set_var value_var
    for name in "$@"; do
        set_var="ENV_OVERRIDE_${name}_SET"
        value_var="ENV_OVERRIDE_${name}_VALUE"
        if [[ "${!name+x}" == "x" ]]; then
            printf -v "$set_var" '%s' "1"
            printf -v "$value_var" '%s' "${!name-}"
        else
            printf -v "$set_var" '%s' ""
            printf -v "$value_var" '%s' ""
        fi
    done
}

restore_env_overrides() {
    local name set_var value_var
    for name in "$@"; do
        set_var="ENV_OVERRIDE_${name}_SET"
        value_var="ENV_OVERRIDE_${name}_VALUE"
        if [[ -n "${!set_var:-}" ]]; then
            printf -v "$name" '%s' "${!value_var-}"
        fi
    done
}

# Wrangler always writes every debug-level message to WRANGLER_LOG_PATH,
# regardless of the WRANGLER_LOG console threshold. Point the default file at
# the null device while retaining error-level console output in update.log.
prepare_null_log_sink() {
    local sink_path="$1"
    local target=""

    mkdir -p "$(dirname "$sink_path")"
    if [[ -L "$sink_path" ]]; then
        target=$(readlink "$sink_path")
        [[ "$target" == /dev/null ]] || {
            printf 'Refusing Wrangler sink symlink %s -> %s; expected /dev/null\n' \
                "$sink_path" "$target" >&2
            return 1
        }
        return 0
    fi
    if [[ -e "$sink_path" ]]; then
        printf 'Refusing to replace existing Wrangler sink path: %s\n' "$sink_path" >&2
        return 1
    fi
    ln -s /dev/null "$sink_path"
}

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
