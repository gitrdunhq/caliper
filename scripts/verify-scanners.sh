#!/usr/bin/env bash
# verify-scanners.sh — Check whether all required scanner CLIs are installed.
# Returns exit code 0 if all tools present, 1 if any missing.

set -euo pipefail

# scancode removed — orphaned/disabled (no arm64 wheels). Re-add when re-enabled.
REQUIRED_TOOLS=(syft osv-scanner trivy opa)

missing=0
total=${#REQUIRED_TOOLS[@]}

# Collect results into parallel arrays
declare -a tool_names=()
declare -a tool_statuses=()
declare -a tool_versions=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    tool_names+=("$tool")

    if ! command -v "$tool" >/dev/null 2>&1; then
        tool_statuses+=("MISSING")
        tool_versions+=("-")
        missing=$((missing + 1))
        continue
    fi

    # Extract version string — tools use different flags
    version_output=""
    case "$tool" in
        syft)
            version_output=$(syft version 2>/dev/null | grep -i "^version" | awk '{print $NF}') || true
            if [ -z "$version_output" ]; then
                version_output=$(syft --version 2>/dev/null | awk '{print $NF}') || true
            fi
            ;;
        osv-scanner)
            version_output=$(osv-scanner --version 2>/dev/null | awk '{print $NF}') || true
            ;;
        trivy)
            version_output=$(trivy --version 2>/dev/null | grep -i "^version" | awk '{print $NF}') || true
            if [ -z "$version_output" ]; then
                version_output=$(trivy version 2>/dev/null | grep -i "^version" | awk '{print $NF}') || true
            fi
            ;;
        scancode)
            version_output=$(scancode --version 2>/dev/null | awk '{print $NF}') || true
            ;;
        opa)
            version_output=$(opa version 2>/dev/null | grep "^Version" | awk '{print $NF}') || true
            if [ -z "$version_output" ]; then
                version_output=$(opa --version 2>/dev/null | awk '{print $NF}') || true
            fi
            ;;
    esac

    if [ -z "$version_output" ]; then
        version_output="(unknown)"
    fi

    tool_statuses+=("OK")
    tool_versions+=("$version_output")
done

# Print formatted table
printf "\nScanner Verification\n"
printf "====================\n"
printf "%-14s %-12s %s\n" "Tool" "Status" "Version"
printf "%-14s %-12s %s\n" "----" "------" "-------"

for i in "${!tool_names[@]}"; do
    printf "%-14s %-12s %s\n" "${tool_names[$i]}" "${tool_statuses[$i]}" "${tool_versions[$i]}"
done

printf "\n"

if [ "$missing" -eq 0 ]; then
    printf "Result: All %d tools installed. Ready to run admission control.\n" "$total"
    exit 0
else
    printf "Result: %d tool(s) missing. Install missing tools before running admission control.\n" "$missing"
    exit 1
fi
