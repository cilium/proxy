#!/bin/bash

set -eu

# Script to automatically update the version compatibility matrix in README.md
# This script fetches the last N supported minor versions of Cilium,
# gets all patch releases for each, and extracts the Envoy version from
# each Cilium Docker image.
#
# Usage:
#   ./update_version_matrix.sh [OPTIONS]
#
# Options:
#   -n, --dry-run     Show what would be updated without making changes
#   -v, --verbose     Enable verbose output
#   -h, --help        Show this help message
#
# Environment variables:
#   SUPPORTED_MINOR_VERSIONS  Number of minor versions to include (default: 3)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
README_FILE="${REPO_ROOT}/README.md"

# Number of minor versions to support (Cilium supports last 3 minor versions)
SUPPORTED_MINOR_VERSIONS=${SUPPORTED_MINOR_VERSIONS:-3}

# Options
DRY_RUN=false
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Update the version compatibility matrix in README.md"
            echo ""
            echo "Usage: $(basename "$0") [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -n, --dry-run     Show what would be updated without making changes"
            echo "  -v, --verbose     Enable verbose output"
            echo "  -h, --help        Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  SUPPORTED_MINOR_VERSIONS  Number of minor versions to include (default: 3)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_verbose() {
    if [[ "${VERBOSE}" == "true" ]]; then
        echo "$@" >&2
    fi
}

# Temporary file for building the matrix
TEMP_MATRIX=$(mktemp)
trap "rm -f ${TEMP_MATRIX}" EXIT

echo "Fetching Cilium releases..."

# Get all Cilium release tags from GitHub API
# Filter to stable releases (vX.Y.Z format, no rc/beta/alpha)
get_cilium_releases() {
    local page=1
    local releases=""

    while true; do
        local response
        response=$(curl -s "https://api.github.com/repos/cilium/cilium/releases?per_page=100&page=${page}")

        # Check if we got any results
        if [[ $(echo "${response}" | jq 'length') -eq 0 ]]; then
            break
        fi

        # Extract tag names, filter stable releases only (vX.Y.Z)
        local page_releases
        page_releases=$(echo "${response}" | jq -r '.[].tag_name' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)

        if [[ -n "${page_releases}" ]]; then
            releases="${releases}${page_releases}"$'\n'
        fi

        # Check if there are more pages
        if [[ $(echo "${response}" | jq 'length') -lt 100 ]]; then
            break
        fi

        page=$((page + 1))
    done

    echo "${releases}" | grep -v '^$' | sort -V -r
}

# Extract minor version from a full version string (e.g., v1.18.1 -> 1.18)
get_minor_version() {
    echo "$1" | sed -E 's/^v([0-9]+\.[0-9]+)\.[0-9]+$/\1/'
}

# Get the main branch Envoy version from Cilium main branch Dockerfile
get_main_envoy_version() {
    local dockerfile_url="https://raw.githubusercontent.com/cilium/cilium/main/images/cilium/Dockerfile"
    local dockerfile_content
    dockerfile_content=$(curl -sf "${dockerfile_url}" 2>/dev/null || true)

    if [[ -n "${dockerfile_content}" ]]; then
        # Extract version from CILIUM_ENVOY_IMAGE line and convert to vX.Y.x format
        local version
        version=$(echo "${dockerfile_content}" | grep -E "CILIUM_ENVOY_IMAGE=" | grep -oE 'cilium-envoy:v[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)
        if [[ -n "${version}" ]]; then
            echo "v${version}.x"
            return
        fi
    fi

    echo "  Warning: Could not fetch main branch Envoy version" >&2
    echo "unknown"
}

# Get the Envoy version from Cilium GitHub source (Dockerfile)
get_envoy_version() {
    local cilium_version=$1
    local envoy_version

    log_verbose "  Fetching Envoy version for Cilium ${cilium_version} from GitHub..."

    # Fetch the Dockerfile from GitHub and extract CILIUM_ENVOY_IMAGE version
    # Format: ARG CILIUM_ENVOY_IMAGE=quay.io/cilium/cilium-envoy:v1.35.9-...
    local dockerfile_url="https://raw.githubusercontent.com/cilium/cilium/${cilium_version}/images/cilium/Dockerfile"
    local dockerfile_content
    dockerfile_content=$(curl -sf "${dockerfile_url}" 2>/dev/null || true)

    if [[ -z "${dockerfile_content}" ]]; then
        echo "  Warning: Failed to fetch Dockerfile for ${cilium_version}" >&2
        echo "unknown"
        return
    fi

    # Extract version from CILIUM_ENVOY_IMAGE line
    # Pattern: quay.io/cilium/cilium-envoy:vX.Y.Z-...
    envoy_version=$(echo "${dockerfile_content}" | grep -E "CILIUM_ENVOY_IMAGE=" | grep -oE 'cilium-envoy:v[0-9]+\.[0-9]+\.[0-9]+' | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)

    if [[ -n "${envoy_version}" ]]; then
        echo "${envoy_version}"
        return
    fi

    echo "  Warning: Could not extract Envoy version for ${cilium_version}" >&2
    echo "unknown"
}

# Get all releases
ALL_RELEASES=$(get_cilium_releases)

if [[ -z "${ALL_RELEASES}" ]]; then
    echo "Error: Failed to fetch Cilium releases"
    exit 1
fi

# Get unique minor versions and select the latest N
MINOR_VERSIONS=$(echo "${ALL_RELEASES}" | while read -r version; do
    get_minor_version "${version}"
done | sort -V -r | uniq | head -n "${SUPPORTED_MINOR_VERSIONS}")

echo "Supported minor versions: $(echo ${MINOR_VERSIONS} | tr '\n' ' ')"

# Build the matrix
echo "Building version matrix..."

# Collect all versions we need to process
VERSIONS_TO_PROCESS=""
for minor in ${MINOR_VERSIONS}; do
    # Get all patch releases for this minor version
    PATCH_RELEASES=$(echo "${ALL_RELEASES}" | grep "^v${minor}\." | sort -V -r)
    VERSIONS_TO_PROCESS="${VERSIONS_TO_PROCESS}${PATCH_RELEASES}"$'\n'
done

# Remove empty lines and process each version
echo "${VERSIONS_TO_PROCESS}" | grep -v '^$' | while read -r version; do
    envoy_ver=$(get_envoy_version "${version}")
    echo "${version}|${envoy_ver}"
done > "${TEMP_MATRIX}"

# Generate the new table content
generate_table() {
    local main_envoy_version
    main_envoy_version=$(get_main_envoy_version)

    echo "| Cilium Version | Envoy version |"
    echo "|----------------|---------------|"
    printf "| %-14s | %-13s |\n" "(main)" "${main_envoy_version}"

    while IFS='|' read -r cilium_ver envoy_ver; do
        printf "| %-14s | %-13s |\n" "${cilium_ver}" "${envoy_ver}"
    done < "${TEMP_MATRIX}"
    echo ""
}

# Find the line numbers for the table
TABLE_START=$(grep -n "| Cilium Version | Envoy version |" "${README_FILE}" | cut -d: -f1)

if [[ -z "${TABLE_START}" ]]; then
    echo "Error: Could not find version matrix table in README.md"
    exit 1
fi

# Find where the table ends (first non-table line after the header)
TABLE_END=$(tail -n +"${TABLE_START}" "${README_FILE}" | grep -n -m 1 "^[^|]" | cut -d: -f1)
TABLE_END=$((TABLE_START + TABLE_END - 2))

if [[ "${DRY_RUN}" == "true" ]]; then
    echo ""
    echo "=== DRY RUN - Would update README.md with: ==="
    echo ""
    generate_table
    echo ""
    echo "=== End of table ==="
    echo ""
    echo "Versions collected:"
    cat "${TEMP_MATRIX}"
else
    # Update the README.md
    echo "Updating README.md..."

    # Create new README content
    {
        head -n "$((TABLE_START - 1))" "${README_FILE}"
        generate_table
        tail -n "+$((TABLE_END + 1))" "${README_FILE}"
    } > "${README_FILE}.new"

    mv "${README_FILE}.new" "${README_FILE}"

    echo "Done! Version matrix updated in README.md"
    echo ""
    echo "Updated versions:"
    cat "${TEMP_MATRIX}"
fi
