#!/bin/bash

# check_hpe_oneview.sh
# Icinga plugin: gather Server/Hardware Status from HPE OneView REST API
# Dependencies: curl, jq
#
# Author:
#   Felix Longardt <monitoring@longardt.com>
#
# Version history:
# 2025-08-22 Felix Longardt <monitoring@longardt.com>
# Release: 0.0.1
#   Initial release
# Release: 0.0.2
#   add proxy support
# Release: 1.0.0
#   Fixed missing functions and improved error handling, add synergy support
#

set -o errexit
set -o nounset
set -o pipefail

OK=0; WARNING=1; CRITICAL=2; UNKNOWN=3

usage() {
cat <<EOF
Usage: $0 -H <oneview-host> -u <username> -p <password> [options]

Options:
  -H, --host            HPE OneView appliance hostname/IP
  -u, --username        Username for OneView authentication
  -p, --password        Password for OneView authentication
  -S, --server-name     Filter by specific server name pattern
  -E, --enclosure-mode  Enable comprehensive enclosure/frame mode (checks all components)
  -t, --resource-type   Resource type to check (default: server-hardware)
                        Valid types: server-hardware, enclosures, interconnects, logical-interconnects,
                        power-devices, storage-systems, storage-pools, networks
  -V, --verify-tls      Verify TLS certificates (default: false)
  -v, --verbose         Show individual resource status
  -D, --debug           Show detailed debug information
      --use-proxy       Enable proxy settings (default: proxy is disabled)
      --proxy           Use specific proxy (format: http://proxy:port)
  -d, --detail          Show resource details/description (requires --verbose)
  -P, --perfdata        Include extended performance data in output
  -O, --perfdata-only   Show only performance data (no status message)
  -e, --exclude         Exclude resources by name (comma-separated patterns)
  -E, --exclude-status  Exclude resources by status (comma-separated patterns) (requires --detail)
  -i, --include         Include ONLY resources matching name patterns (comma-separated)
  -I, --include-status  Include ONLY resources matching status patterns (comma-separated) (requires --detail)
  -j, --include-perfdata Include ONLY these resources in performance data (comma-separated)
  -g, --exclude-perfdata Exclude these resources from performance data (comma-separated)
      --timeout         Connection timeout in seconds (default: 30)
      --api-version     OneView API version (default: 2000)
      --port            OneView HTTPS port (default: auto-detect from 443,8443)
      --auto-discover   Automatically discover OneView connection settings

Patterns can be:
  - exact names:      "Server-001"
  - wildcards:        "Server-*"
  - regex (surrounded by slashes): "/^Server-[0-9]+$/"

Resource Types:
  server-hardware     - Physical servers (default)
  enclosures         - Synergy enclosures/frames
  interconnects      - Network interconnects
  logical-interconnects - Logical interconnects
  storage-systems    - Storage systems
  storage-pools      - Storage pools
  networks          - Networks

Comprehensive Check Modes:
  -S "ServerPattern"   - Filter servers by name pattern (supports wildcards)
  -E                   - Enable comprehensive enclosure mode (all frames + components)

Examples:
  $0 -H oneview.example.com -u administrator -p password
  $0 -H oneview.example.com -u admin -p secret -S "Server-001" -v -d
  $0 -H oneview.example.com -u admin -p secret -S "SY-480-*" -v
  $0 -H oneview.example.com -u admin -p secret -E -v -d
  $0 -H oneview.example.com -u admin -p secret -t enclosures -v
  $0 -H oneview.example.com -u admin -p secret -i "Server-*" -P
  $0 -H oneview.example.com -u admin -p secret -t server-hardware -j "Server-[12]*"
  $0 -H oneview.example.com -u admin -p secret --use-proxy
  $0 -H oneview.example.com -u admin -p secret --proxy http://proxy:8080

Note: Proxy is DISABLED by default to avoid enterprise proxy issues.
Use --use-proxy to enable proxy or --proxy to specify a custom proxy.

Note: Include filters are applied before exclude filters. Performance data filters
work independently of resource display filters.
EOF
exit $UNKNOWN
}

# Defaults
ONEVIEW_HOST=""
USERNAME=""
PASSWORD=""
SERVER_NAME=""
ENCLOSURE_MODE=false
RESOURCE_TYPE="server-hardware"
VERIFY_TLS=false
VERBOSE=false
DEBUG=false
DETAIL=false
PERFDATA=false
PERFDATA_ONLY=false
TIMEOUT=30
API_VERSION=2000
ONEVIEW_PORT=""
AUTO_DISCOVER=false
NO_PROXY=true  # Default to true to avoid proxy issues
CUSTOM_PROXY=""
EXCLUDES=()
STATUS_EXCLUDES=()
INCLUDES=()
STATUS_INCLUDES=()
PERFDATA_INCLUDES=()
PERFDATA_EXCLUDES=()

# Parse args
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -H|--host) ONEVIEW_HOST="$2"; shift ;;
    -u|--username) USERNAME="$2"; shift ;;
    -p|--password) PASSWORD="$2"; shift ;;
    -S|--server-name) SERVER_NAME="$2"; shift ;;
    -E|--enclosure-mode) ENCLOSURE_MODE=true ;;
    -t|--resource-type) RESOURCE_TYPE="$2"; shift ;;
    -V|--verify-tls) VERIFY_TLS=true ;;
    -v|--verbose) VERBOSE=true ;;
    -D|--debug) DEBUG=true ;;
    --use-proxy) NO_PROXY=false ;;
    --proxy) CUSTOM_PROXY="$2"; NO_PROXY=false; shift ;;
    -d|--detail) DETAIL=true ;;
    -P|--perfdata) PERFDATA=true ;;
    -O|--perfdata-only) PERFDATA_ONLY=true ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --api-version) API_VERSION="$2"; shift ;;
    --port) ONEVIEW_PORT="$2"; shift ;;
    --auto-discover) AUTO_DISCOVER=true ;;
    -i|--include)
      IFS=',' read -r -a raw_includes <<< "$2"
      for p in "${raw_includes[@]}"; do
        p="${p#"${p%%[![:space:]]*}"}"
        p="${p%"${p##*[![:space:]]}"}"
        [[ -n "$p" ]] && INCLUDES+=("$p")
      done
      shift ;;
    -I|--include-status)
      IFS=',' read -r -a raw_includes <<< "$2"
      for p in "${raw_includes[@]}"; do
        p="${p#"${p%%[![:space:]]*}"}"
        p="${p%"${p##*[![:space:]]}"}"
        [[ -n "$p" ]] && STATUS_INCLUDES+=("$p")
      done
      shift ;;
    -j|--include-perfdata)
      IFS=',' read -r -a raw_includes <<< "$2"
      for p in "${raw_includes[@]}"; do
        p="${p#"${p%%[![:space:]]*}"}"
        p="${p%"${p##*[![:space:]]}"}"
        [[ -n "$p" ]] && PERFDATA_INCLUDES+=("$p")
      done
      shift ;;
    -g|--exclude-perfdata)
      IFS=',' read -r -a raw_excludes <<< "$2"
      for p in "${raw_excludes[@]}"; do
        p="${p#"${p%%[![:space:]]*}"}"
        p="${p%"${p##*[![:space:]]}"}"
        [[ -n "$p" ]] && PERFDATA_EXCLUDES+=("$p")
      done
      shift ;;
    -e|--exclude)
      IFS=',' read -r -a raw_excludes <<< "$2"
      for p in "${raw_excludes[@]}"; do
        p="${p#"${p%%[![:space:]]*}"}"
        p="${p%"${p##*[![:space:]]}"}"
        [[ -n "$p" ]] && EXCLUDES+=("$p")
      done
      shift ;;
    --exclude-status)
      IFS=',' read -r -a raw_excludes <<< "$2"
      for p in "${raw_excludes[@]}"; do
        p="${p#"${p%%[![:space:]]*}"}"
        p="${p%"${p##*[![:space:]]}"}"
        [[ -n "$p" ]] && STATUS_EXCLUDES+=("$p")
      done
      shift ;;
    *) echo "Unknown parameter: $1"; usage ;;
  esac
  shift
done

[[ -z "${ONEVIEW_HOST:-}" ]] && usage
if [[ -z "${USERNAME:-}" || -z "${PASSWORD:-}" ]]; then
  echo "ERROR: Username and password are required"
  exit $UNKNOWN
fi

# Validate resource type
case "$RESOURCE_TYPE" in
  server-hardware|enclosures|interconnects|logical-interconnects|power-devices|storage-systems|storage-pools|networks) ;;
  *) echo "ERROR: Invalid resource type: $RESOURCE_TYPE"; usage ;;
esac

# Validate that enclosure mode doesn't conflict with server filtering
if [[ "$ENCLOSURE_MODE" = true && -n "$SERVER_NAME" ]]; then
  echo "ERROR: Cannot use --enclosure-mode with --server-name filter"
  exit $UNKNOWN
fi

# curl options
CURL_OPTS=(--silent --show-error --connect-timeout 10 --max-time "$TIMEOUT")
[[ "$VERIFY_TLS" = false ]] && CURL_OPTS+=(-k)

# Handle proxy settings (default: no proxy to avoid enterprise proxy issues)
if [[ "$NO_PROXY" = true ]]; then
  [[ "$DEBUG" = true ]] && echo "DEBUG: Disabling proxy settings (default behavior)" >&2
  unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy
  export NO_PROXY="*"
  CURL_OPTS+=(--noproxy "*")
elif [[ -n "$CUSTOM_PROXY" ]]; then
  [[ "$DEBUG" = true ]] && echo "DEBUG: Using custom proxy: $CUSTOM_PROXY" >&2
  CURL_OPTS+=(--proxy "$CUSTOM_PROXY")
else
  # User explicitly wants to use proxy
  if [[ -n "${HTTP_PROXY:-}${HTTPS_PROXY:-}${http_proxy:-}${https_proxy:-}" ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Using proxy environment variables:" >&2
    [[ "$DEBUG" = true ]] && [[ -n "${HTTP_PROXY:-}" ]] && echo "DEBUG:   HTTP_PROXY=$HTTP_PROXY" >&2
    [[ "$DEBUG" = true ]] && [[ -n "${HTTPS_PROXY:-}" ]] && echo "DEBUG:   HTTPS_PROXY=$HTTPS_PROXY" >&2
    [[ "$DEBUG" = true ]] && [[ -n "${http_proxy:-}" ]] && echo "DEBUG:   http_proxy=$http_proxy" >&2
    [[ "$DEBUG" = true ]] && [[ -n "${https_proxy:-}" ]] && echo "DEBUG:   https_proxy=$https_proxy" >&2
  else
    [[ "$DEBUG" = true ]] && echo "DEBUG: No proxy configured, using direct connection" >&2
  fi
fi

# Global variables for session management
SESSION_ID=""
AUTH_TOKEN=""

# Auto-discover OneView connection settings
auto_discover_oneview() {
  local host="$1"
  [[ "$DEBUG" = true ]] && echo "DEBUG: Auto-discovering OneView connection settings for $host" >&2

  # Test common OneView ports (removed c7000/c3000 support)
  local test_ports=(443 8443)
  local working_port=""
  local working_protocol=""

  for port in "${test_ports[@]}"; do
    [[ "$DEBUG" = true ]] && echo "DEBUG: Testing port $port..." >&2

    # Test HTTPS first, then HTTP
    for protocol in https http; do
      local test_url="${protocol}://${host}:${port}"

      if timeout 5 bash -c "</dev/tcp/$host/$port" &>/dev/null 2>&1; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: Port $port is open, testing $protocol..." >&2

        # Test if we get a response
        local response
        response=$(curl -k -s -I --connect-timeout 5 --max-time 10 "$test_url" 2>/dev/null | head -1)
        if [[ -n "$response" ]]; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: Got response from $test_url: $response" >&2

          # Test OneView REST API endpoint
          local api_test_url="${test_url}/rest/"
          local api_response
          api_response=$(curl -k -s -I --connect-timeout 5 --max-time 10 "$api_test_url" 2>/dev/null | head -1)
          if [[ -n "$api_response" ]]; then
            [[ "$DEBUG" = true ]] && echo "DEBUG: OneView REST API detected at $test_url" >&2
            working_port="$port"
            working_protocol="$protocol"
            break 2
          fi
        fi
      fi
    done
  done

  if [[ -n "$working_port" ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Auto-discovery successful: $working_protocol://$host:$working_port" >&2
    echo "$working_protocol:$working_port"
    return 0
  else
    [[ "$DEBUG" = true ]] && echo "DEBUG: Auto-discovery failed - no working OneView endpoint found" >&2
    return 1
  fi
}

# Authenticate with OneView and get session token
authenticate_oneview() {
  local base_url=""

  # Determine the base URL
  if [[ "$AUTO_DISCOVER" = true ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Auto-discovering OneView connection..." >&2
    local discovered
    if discovered=$(auto_discover_oneview "$ONEVIEW_HOST"); then
      local protocol port
      protocol=$(echo "$discovered" | cut -d':' -f1)
      port=$(echo "$discovered" | cut -d':' -f2)
      base_url="${protocol}://${ONEVIEW_HOST}:${port}"
      [[ "$DEBUG" = true ]] && echo "DEBUG: Auto-discovery found: $base_url" >&2
    else
      [[ "$DEBUG" = true ]] && echo "DEBUG: Auto-discovery failed, using defaults" >&2
      base_url="https://${ONEVIEW_HOST}"
    fi
  elif [[ -n "$ONEVIEW_PORT" ]]; then
    base_url="https://${ONEVIEW_HOST}:${ONEVIEW_PORT}"
  else
    base_url="https://${ONEVIEW_HOST}"
  fi

  local auth_url="${base_url}/rest/login-sessions"
  local auth_data="{\"userName\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}"

  [[ "$DEBUG" = true ]] && echo "DEBUG: Authenticating to OneView at $auth_url" >&2
  [[ "$DEBUG" = true ]] && echo "DEBUG: Using API version: ${API_VERSION}" >&2
  [[ "$DEBUG" = true ]] && echo "DEBUG: Username: ${USERNAME}" >&2

  # First, test basic connectivity
  [[ "$DEBUG" = true ]] && echo "DEBUG: Testing basic connectivity..." >&2
  if ! ping -c 1 -W 5 "$ONEVIEW_HOST" &>/dev/null; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Cannot ping OneView host: $ONEVIEW_HOST" >&2
    echo "UNKNOWN - Cannot reach OneView host: $ONEVIEW_HOST" >&2
    return 1
  fi
  [[ "$DEBUG" = true ]] && echo "DEBUG: Host is reachable" >&2

  # Test HTTPS connectivity to the determined URL
  [[ "$DEBUG" = true ]] && echo "DEBUG: Testing connectivity to $base_url..." >&2
  if ! curl "${CURL_OPTS[@]}" --head "$base_url" &>/dev/null; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Cannot connect to $base_url" >&2

    # If auto-discovery is not enabled, try alternative ports
    if [[ "$AUTO_DISCOVER" = false ]]; then
      [[ "$DEBUG" = true ]] && echo "DEBUG: Trying alternative ports..." >&2
      local alt_ports=(8443 80 8080)
      local found_alternative=false

      for alt_port in "${alt_ports[@]}"; do
        local alt_url="https://${ONEVIEW_HOST}:${alt_port}"
        [[ "$DEBUG" = true ]] && echo "DEBUG: Trying $alt_url..." >&2
        if curl "${CURL_OPTS[@]}" --head "$alt_url" &>/dev/null; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: Alternative port $alt_port works" >&2
          auth_url="${alt_url}/rest/login-sessions"
          base_url="$alt_url"
          found_alternative=true
          break
        fi
      done

      if [[ "$found_alternative" = false ]]; then
        echo "UNKNOWN - Cannot establish connection to OneView: $ONEVIEW_HOST" >&2
        echo "Try using --auto-discover or specify --port manually" >&2
        return 1
      fi
    else
      echo "UNKNOWN - Cannot establish connection to OneView: $ONEVIEW_HOST" >&2
      return 1
    fi
  fi
  [[ "$DEBUG" = true ]] && echo "DEBUG: Successfully connected to $base_url" >&2

  # Store base URL for later use
  ONEVIEW_BASE_URL="$base_url"

  # Attempt authentication with detailed error handling
  local auth_response http_code
  [[ "$DEBUG" = true ]] && echo "DEBUG: Attempting authentication..." >&2

  # Use a temporary file to capture both response and HTTP status
  local temp_response=$(mktemp)
  local temp_headers=$(mktemp)

  trap "rm -f '$temp_response' '$temp_headers'" RETURN

  http_code=$(curl "${CURL_OPTS[@]}" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-API-Version: ${API_VERSION}" \
    -d "$auth_data" \
    -w "%{http_code}" \
    -D "$temp_headers" \
    -o "$temp_response" \
    "$auth_url" 2>/dev/null || echo "000")

  auth_response=$(cat "$temp_response" 2>/dev/null || echo "")

  [[ "$DEBUG" = true ]] && echo "DEBUG: HTTP response code: $http_code" >&2
  [[ "$DEBUG" = true ]] && echo "DEBUG: Response body length: ${#auth_response}" >&2
  [[ "$DEBUG" = true ]] && echo "DEBUG: Response preview: ${auth_response:0:100}..." >&2

  # Handle different HTTP response codes
  case "$http_code" in
    000)
      [[ "$DEBUG" = true ]] && echo "DEBUG: Connection failed - no HTTP response" >&2
      echo "UNKNOWN - Connection failed to OneView: $ONEVIEW_HOST" >&2
      return 1
      ;;
    401)
      [[ "$DEBUG" = true ]] && echo "DEBUG: Authentication failed - invalid credentials" >&2
      echo "UNKNOWN - Authentication failed: Invalid username or password" >&2
      return 1
      ;;
    400)
      [[ "$DEBUG" = true ]] && echo "DEBUG: Bad request - possibly unsupported API version" >&2
      echo "UNKNOWN - Bad request: Check API version (current: $API_VERSION)" >&2
      return 1
      ;;
    403)
      [[ "$DEBUG" = true ]] && echo "DEBUG: Forbidden - user may not have required permissions" >&2
      echo "UNKNOWN - Access forbidden: User may lack required permissions" >&2
      return 1
      ;;
    404)
      [[ "$DEBUG" = true ]] && echo "DEBUG: Not found - login endpoint not available" >&2
      echo "UNKNOWN - Login endpoint not found: Check OneView version" >&2
      return 1
      ;;
    500|502|503)
      [[ "$DEBUG" = true ]] && echo "DEBUG: Server error ($http_code) - OneView may be unavailable" >&2
      echo "UNKNOWN - OneView server error ($http_code): Service may be unavailable" >&2
      return 1
      ;;
    200)
      [[ "$DEBUG" = true ]] && echo "DEBUG: Authentication request successful" >&2
      ;;
    *)
      [[ "$DEBUG" = true ]] && echo "DEBUG: Unexpected HTTP code: $http_code" >&2
      echo "UNKNOWN - Unexpected response from OneView (HTTP $http_code)" >&2
      return 1
      ;;
  esac

  # Parse response for session ID
  if ! command -v jq &>/dev/null; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: jq not available, cannot parse response" >&2
    echo "UNKNOWN - jq command not found: Required for JSON parsing" >&2
    return 1
  fi

  if ! SESSION_ID=$(echo "$auth_response" | jq -r '.sessionID // empty' 2>/dev/null); then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Failed to parse JSON response" >&2
    [[ "$DEBUG" = true ]] && echo "DEBUG: Raw response: $auth_response" >&2
    echo "UNKNOWN - Failed to parse authentication response" >&2
    return 1
  fi

  if [[ -z "$SESSION_ID" || "$SESSION_ID" == "null" ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: No sessionID in authentication response" >&2
    [[ "$DEBUG" = true ]] && echo "DEBUG: Available fields: $(echo "$auth_response" | jq -r 'keys[]' 2>/dev/null | tr '\n' ' ')" >&2
    echo "UNKNOWN - No session ID received from OneView" >&2
    return 1
  fi

  [[ "$DEBUG" = true ]] && echo "DEBUG: Successfully authenticated, sessionID: ${SESSION_ID:0:8}..." >&2
  return 0
}

# Logout from OneView
logout_oneview() {
  if [[ -n "$SESSION_ID" ]]; then
    local logout_url="${ONEVIEW_BASE_URL:-https://${ONEVIEW_HOST}}/rest/login-sessions"
    [[ "$DEBUG" = true ]] && echo "DEBUG: Logging out from OneView" >&2
    curl "${CURL_OPTS[@]}" \
      -X DELETE \
      -H "Auth: ${SESSION_ID}" \
      -H "X-API-Version: ${API_VERSION}" \
      "$logout_url" >/dev/null 2>&1 || true
  fi
}

# Trap to ensure cleanup on exit
trap logout_oneview EXIT

# Get resources from OneView API
get_oneview_resources() {
  local resource_type="$1"
  local filter="$2"

  local resource_url="${ONEVIEW_BASE_URL}/rest/${resource_type}"

  # Add filter if specified
  if [[ -n "$filter" ]]; then
    resource_url="${resource_url}?filter=${filter}"
  fi

  [[ "$DEBUG" = true ]] && echo "DEBUG: Fetching resources from: $resource_url" >&2

  # Use temporary files for clean separation of HTTP code and response
  local temp_response=$(mktemp)
  local temp_headers=$(mktemp)

  trap "rm -f '$temp_response' '$temp_headers'" RETURN

  local http_code
  http_code=$(curl "${CURL_OPTS[@]}" \
    -H "Auth: ${SESSION_ID}" \
    -H "X-API-Version: ${API_VERSION}" \
    -H "Accept: application/json" \
    -w "%{http_code}" \
    -D "$temp_headers" \
    -o "$temp_response" \
    "$resource_url" 2>/dev/null || echo "000")

  local response
  response=$(cat "$temp_response" 2>/dev/null || echo "")

  [[ "$DEBUG" = true ]] && echo "DEBUG: HTTP code: $http_code, Response length: ${#response}" >&2

  if [[ "$http_code" == "404" ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Resource type '$resource_type' not found (404), trying alternatives..." >&2

    # Try alternative resource type names
    case "$resource_type" in
      power-devices)
        for alt_type in "power-delivery-devices" "unmanaged-devices" "rack-managers" "appliances"; do
          [[ "$DEBUG" = true ]] && echo "DEBUG: Trying alternative: $alt_type" >&2
          local alt_url="${ONEVIEW_BASE_URL}/rest/${alt_type}"
          [[ -n "$filter" ]] && alt_url="${alt_url}?filter=${filter}"

          http_code=$(curl "${CURL_OPTS[@]}" \
            -H "Auth: ${SESSION_ID}" \
            -H "X-API-Version: ${API_VERSION}" \
            -H "Accept: application/json" \
            -w "%{http_code}" \
            -D "$temp_headers" \
            -o "$temp_response" \
            "$alt_url" 2>/dev/null || echo "000")

          response=$(cat "$temp_response" 2>/dev/null || echo "")

          if [[ "$http_code" == "200" ]]; then
            [[ "$DEBUG" = true ]] && echo "DEBUG: Found working alternative: $alt_type" >&2
            break
          fi
        done
        ;;
    esac
  fi

  if [[ "$http_code" != "200" ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: API call failed with HTTP code: $http_code" >&2
    echo '{"members":[]}'
    return 1
  fi

  # Check if response has the expected structure
  if ! jq -e '.members | type == "array"' >/dev/null 2>&1 <<< "$response"; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Response doesn't have expected members array structure" >&2
    echo '{"members":[]}'
    return 1
  fi

  echo "$response"
}

# Get all enclosure/frame components comprehensively - FIXED VERSION
# Replace the get_all_enclosure_components() function with this corrected version

get_all_enclosure_components() {
  [[ "$DEBUG" = true ]] && echo "DEBUG: Getting all enclosure/frame components comprehensively" >&2

  local combined_response='{"members":[]}'

  # Get all enclosures first
  [[ "$DEBUG" = true ]] && echo "DEBUG: Getting all enclosures..." >&2
  local enclosures_response
  enclosures_response=$(get_oneview_resources "enclosures" "")

  if jq -e '.members | length > 0' >/dev/null 2>&1 <<< "$enclosures_response"; then
    while IFS= read -r enclosure; do
      combined_response=$(echo "$combined_response" | jq --argjson enc "$enclosure" '.members += [$enc]')

      # Get enclosure URI for related components
      local enclosure_uri enclosure_name
      enclosure_uri=$(echo "$enclosure" | jq -r '.uri // empty')
      enclosure_name=$(echo "$enclosure" | jq -r '.name // empty')

      if [[ -n "$enclosure_uri" && "$enclosure_uri" != "null" ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: Getting components for enclosure: $enclosure_name" >&2

        # Get all servers/compute modules in this enclosure
        [[ "$DEBUG" = true ]] && echo "DEBUG: - Getting server-hardware..." >&2
        local servers_response
        servers_response=$(get_oneview_resources "server-hardware" "locationUri='${enclosure_uri}'")
        if jq -e '.members | length > 0' >/dev/null 2>&1 <<< "$servers_response"; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Found $(echo "$servers_response" | jq '.members | length') servers" >&2
          while IFS= read -r server; do
            combined_response=$(echo "$combined_response" | jq --argjson srv "$server" '.members += [$srv]')
          done < <(echo "$servers_response" | jq -c '.members[]')
        fi

        # Get enclosure sub-components via direct enclosure API
        [[ "$DEBUG" = true ]] && echo "DEBUG: - Getting enclosure sub-components via direct API..." >&2
        local enclosure_details_url="${ONEVIEW_BASE_URL}/rest/enclosures/${enclosure_uri##*/}"
        local enclosure_details
        enclosure_details=$(curl "${CURL_OPTS[@]}" \
          -H "Auth: ${SESSION_ID}" \
          -H "X-API-Version: ${API_VERSION}" \
          -H "Accept: application/json" \
          "$enclosure_details_url" 2>/dev/null || echo '{}')

        [[ "$DEBUG" = true ]] && echo "DEBUG: Available enclosure fields: $(echo "$enclosure_details" | jq -r 'keys[]' 2>/dev/null | tr '\n' ' ')" >&2

        # Extract appliance bays (Synergy Composers, etc.)
        if jq -e '.applianceBays | length > 0' >/dev/null 2>&1 <<< "$enclosure_details"; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Processing $(echo "$enclosure_details" | jq '.applianceBays | length') appliance bays..." >&2
          while IFS= read -r appliance_bay; do
            local bay_presence bay_status bay_name bay_model bay_serial
            bay_presence=$(echo "$appliance_bay" | jq -r '.devicePresence // "Unknown"')
            bay_status=$(echo "$appliance_bay" | jq -r '.status // "Unknown"')
            bay_name=$(echo "$appliance_bay" | jq -r '.bayNumber // empty')
            bay_model=$(echo "$appliance_bay" | jq -r '.model // empty')
            bay_serial=$(echo "$appliance_bay" | jq -r '.serialNumber // empty')

            if [[ "$bay_presence" == "Present" ]]; then
              local appliance_object
              appliance_object=$(jq -n \
                --arg name "${enclosure_name} Appliance Bay ${bay_name}" \
                --arg status "$bay_status" \
                --arg model "$bay_model" \
                --arg serial "$bay_serial" \
                --arg type "appliance-bays" \
                --arg enc_name "$enclosure_name" \
                '{
                  name: $name,
                  status: $status,
                  model: $model,
                  serialNumber: $serial,
                  category: $type,
                  type: $type,
                  enclosureName: $enc_name
                }')

              combined_response=$(echo "$combined_response" | jq --argjson comp "$appliance_object" '.members += [$comp]')
              [[ "$DEBUG" = true ]] && echo "DEBUG: - Added appliance bay: ${enclosure_name} Appliance Bay ${bay_name}" >&2
            fi
          done < <(echo "$enclosure_details" | jq -c '.applianceBays[]?')
        fi

        # Extract power supply bays
        if jq -e '.powerSupplyBays | length > 0' >/dev/null 2>&1 <<< "$enclosure_details"; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Processing $(echo "$enclosure_details" | jq '.powerSupplyBays | length') power supply bays..." >&2
          while IFS= read -r power_bay; do
            local bay_presence bay_status bay_name bay_model bay_serial bay_part_num
            bay_presence=$(echo "$power_bay" | jq -r '.devicePresence // "Unknown"')
            bay_status=$(echo "$power_bay" | jq -r '.status // "Unknown"')
            bay_name=$(echo "$power_bay" | jq -r '.bayNumber // empty')
            bay_model=$(echo "$power_bay" | jq -r '.model // empty')
            bay_serial=$(echo "$power_bay" | jq -r '.serialNumber // empty')
            bay_part_num=$(echo "$power_bay" | jq -r '.partNumber // empty')

            if [[ "$bay_presence" == "Present" ]]; then
              local power_object
              power_object=$(jq -n \
                --arg name "${enclosure_name} Power Supply ${bay_name}" \
                --arg status "$bay_status" \
                --arg model "$bay_model" \
                --arg serial "$bay_serial" \
                --arg part "$bay_part_num" \
                --arg type "power-supply-bays" \
                --arg enc_name "$enclosure_name" \
                '{
                  name: $name,
                  status: $status,
                  model: $model,
                  serialNumber: $serial,
                  partNumber: $part,
                  category: $type,
                  type: $type,
                  enclosureName: $enc_name
                }')

              combined_response=$(echo "$combined_response" | jq --argjson comp "$power_object" '.members += [$comp]')
              [[ "$DEBUG" = true ]] && echo "DEBUG: - Added power supply: ${enclosure_name} Power Supply ${bay_name}" >&2
            fi
          done < <(echo "$enclosure_details" | jq -c '.powerSupplyBays[]?')
        fi

        # Extract fan bays
        if jq -e '.fanBays | length > 0' >/dev/null 2>&1 <<< "$enclosure_details"; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Processing $(echo "$enclosure_details" | jq '.fanBays | length') fan bays..." >&2
          while IFS= read -r fan_bay; do
            local bay_presence bay_status bay_name bay_model bay_serial
            bay_presence=$(echo "$fan_bay" | jq -r '.devicePresence // "Unknown"')
            bay_status=$(echo "$fan_bay" | jq -r '.status // "Unknown"')
            bay_name=$(echo "$fan_bay" | jq -r '.bayNumber // empty')
            bay_model=$(echo "$fan_bay" | jq -r '.model // empty')
            bay_serial=$(echo "$fan_bay" | jq -r '.serialNumber // empty')

            if [[ "$bay_presence" == "Present" ]]; then
              local fan_object
              fan_object=$(jq -n \
                --arg name "${enclosure_name} Fan ${bay_name}" \
                --arg status "$bay_status" \
                --arg model "$bay_model" \
                --arg serial "$bay_serial" \
                --arg type "fan-bays" \
                --arg enc_name "$enclosure_name" \
                '{
                  name: $name,
                  status: $status,
                  model: $model,
                  serialNumber: $serial,
                  category: $type,
                  type: $type,
                  enclosureName: $enc_name
                }')

              combined_response=$(echo "$combined_response" | jq --argjson comp "$fan_object" '.members += [$comp]')
              [[ "$DEBUG" = true ]] && echo "DEBUG: - Added fan: ${enclosure_name} Fan ${bay_name}" >&2
            fi
          done < <(echo "$enclosure_details" | jq -c '.fanBays[]?')
        fi

        # Extract manager bays (management modules)
        if jq -e '.managerBays | length > 0' >/dev/null 2>&1 <<< "$enclosure_details"; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Processing $(echo "$enclosure_details" | jq '.managerBays | length') manager bays..." >&2
          while IFS= read -r manager_bay; do
            local bay_presence bay_status bay_name bay_model bay_serial
            bay_presence=$(echo "$manager_bay" | jq -r '.devicePresence // "Unknown"')
            bay_status=$(echo "$manager_bay" | jq -r '.status // "Unknown"')
            bay_name=$(echo "$manager_bay" | jq -r '.bayNumber // empty')
            bay_model=$(echo "$manager_bay" | jq -r '.model // empty')
            bay_serial=$(echo "$manager_bay" | jq -r '.serialNumber // empty')

            if [[ "$bay_presence" == "Present" ]]; then
              local manager_object
              manager_object=$(jq -n \
                --arg name "${enclosure_name} Manager ${bay_name}" \
                --arg status "$bay_status" \
                --arg model "$bay_model" \
                --arg serial "$bay_serial" \
                --arg type "manager-bays" \
                --arg enc_name "$enclosure_name" \
                '{
                  name: $name,
                  status: $status,
                  model: $model,
                  serialNumber: $serial,
                  category: $type,
                  type: $type,
                  enclosureName: $enc_name
                }')

              combined_response=$(echo "$combined_response" | jq --argjson comp "$manager_object" '.members += [$comp]')
              [[ "$DEBUG" = true ]] && echo "DEBUG: - Added manager: ${enclosure_name} Manager ${bay_name}" >&2
            fi
          done < <(echo "$enclosure_details" | jq -c '.managerBays[]?')
        fi

        # Extract device bays (other devices)
       # Extract device bays (other devices) - SKIP UNKNOWN STATUS
        if jq -e '.deviceBays | length > 0' >/dev/null 2>&1 <<< "$enclosure_details"; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Processing $(echo "$enclosure_details" | jq '.deviceBays | length') device bays..." >&2
         while IFS= read -r device_bay; do
          local bay_presence bay_status bay_name bay_model bay_serial
          bay_presence=$(echo "$device_bay" | jq -r '.devicePresence // "Unknown"')
          bay_status=$(echo "$device_bay" | jq -r '.status // "Unknown"')
          bay_name=$(echo "$device_bay" | jq -r '.bayNumber // empty')
          bay_model=$(echo "$device_bay" | jq -r '.model // empty')
         bay_serial=$(echo "$device_bay" | jq -r '.serialNumber // empty')

          # Only add if device is present AND has a non-Unknown status
         if [[ "$bay_presence" == "Present" && "$bay_status" != "Unknown" ]]; then
          local device_object
         device_object=$(jq -n \
          --arg name "${enclosure_name} Device Bay ${bay_name}" \
          --arg status "$bay_status" \
          --arg model "$bay_model" \
          --arg serial "$bay_serial" \
          --arg type "device-bays" \
          --arg enc_name "$enclosure_name" \
          --arg presence "$bay_presence" \
          '{
            name: $name,
            status: $status,
            model: $model,
            serialNumber: $serial,
            category: $type,
            type: $type,
            enclosureName: $enc_name,
            devicePresence: $presence
          }')

          combined_response=$(echo "$combined_response" | jq --argjson comp "$device_object" '.members += [$comp]')
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Added device bay: ${enclosure_name} Device Bay ${bay_name} ($bay_presence, $bay_status)" >&2
         else
           [[ "$DEBUG" = true ]] && echo "DEBUG: - Skipped device bay: ${enclosure_name} Device Bay ${bay_name} (presence: $bay_presence, status: $bay_status)" >&2
         fi
          done < <(echo "$enclosure_details" | jq -c '.deviceBays[]?')
        fi
        # Extract interconnect bays
        if jq -e '.interconnectBays | length > 0' >/dev/null 2>&1 <<< "$enclosure_details"; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Processing $(echo "$enclosure_details" | jq '.interconnectBays | length') interconnect bays..." >&2
          while IFS= read -r interconnect_bay; do
            local bay_presence bay_status bay_name bay_model bay_serial
            bay_presence=$(echo "$interconnect_bay" | jq -r '.devicePresence // "Unknown"')
            bay_status=$(echo "$interconnect_bay" | jq -r '.status // "Unknown"')
            bay_name=$(echo "$interconnect_bay" | jq -r '.bayNumber // empty')
            bay_model=$(echo "$interconnect_bay" | jq -r '.model // empty')
            bay_serial=$(echo "$interconnect_bay" | jq -r '.serialNumber // empty')

            if [[ "$bay_presence" == "Present" ]]; then
              local interconnect_object
              interconnect_object=$(jq -n \
                --arg name "${enclosure_name} Interconnect Bay ${bay_name}" \
                --arg status "$bay_status" \
                --arg model "$bay_model" \
                --arg serial "$bay_serial" \
                --arg type "interconnect-bays" \
                --arg enc_name "$enclosure_name" \
                '{
                  name: $name,
                  status: $status,
                  model: $model,
                  serialNumber: $serial,
                  category: $type,
                  type: $type,
                  enclosureName: $enc_name
                }')

              combined_response=$(echo "$combined_response" | jq --argjson comp "$interconnect_object" '.members += [$comp]')
              [[ "$DEBUG" = true ]] && echo "DEBUG: - Added interconnect bay: ${enclosure_name} Interconnect Bay ${bay_name}" >&2
            fi
          done < <(echo "$enclosure_details" | jq -c '.interconnectBays[]?')
        fi

        # Extract crossBars (Frame Link Modules)
        if jq -e '.crossBars | length > 0' >/dev/null 2>&1 <<< "$enclosure_details"; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Processing $(echo "$enclosure_details" | jq '.crossBars | length') frame link modules..." >&2
          while IFS= read -r crossbar; do
            local cb_status cb_name cb_model cb_serial
            cb_status=$(echo "$crossbar" | jq -r '.status // "Unknown"')
            cb_name=$(echo "$crossbar" | jq -r '.bayNumber // .name // empty')
            cb_model=$(echo "$crossbar" | jq -r '.model // empty')
            cb_serial=$(echo "$crossbar" | jq -r '.serialNumber // empty')

            local crossbar_object
            crossbar_object=$(jq -n \
              --arg name "${enclosure_name} Frame Link Module ${cb_name}" \
              --arg status "$cb_status" \
              --arg model "$cb_model" \
              --arg serial "$cb_serial" \
              --arg type "frame-link-modules" \
              --arg enc_name "$enclosure_name" \
              '{
                name: $name,
                status: $status,
                model: $model,
                serialNumber: $serial,
                category: $type,
                type: $type,
                enclosureName: $enc_name
              }')

            combined_response=$(echo "$combined_response" | jq --argjson comp "$crossbar_object" '.members += [$comp]')
            [[ "$DEBUG" = true ]] && echo "DEBUG: - Added frame link module: ${enclosure_name} Frame Link Module ${cb_name}" >&2
          done < <(echo "$enclosure_details" | jq -c '.crossBars[]?')
        fi

        # Get logical interconnects related to this enclosure
        local logical_ic_response
        logical_ic_response=$(get_oneview_resources "logical-interconnects" "")
        if jq -e '.members | length > 0' >/dev/null 2>&1 <<< "$logical_ic_response"; then
          [[ "$DEBUG" = true ]] && echo "DEBUG: - Processing logical interconnects..." >&2
          while IFS= read -r logical_ic; do
            # Check if this logical interconnect is related to our enclosure
            local ic_enclosures
            ic_enclosures=$(echo "$logical_ic" | jq -r '.enclosureUris[]? // empty' 2>/dev/null || echo "")

            if [[ "$ic_enclosures" == *"$enclosure_uri"* ]] || [[ -z "$ic_enclosures" ]]; then
              # Add this logical interconnect
              combined_response=$(echo "$combined_response" | jq --argjson ic "$logical_ic" '.members += [$ic]')
            fi
          done < <(echo "$logical_ic_response" | jq -c '.members[]')
        fi
      fi
    done < <(echo "$enclosures_response" | jq -c '.members[]')
  fi

  # Get remaining global resources that might not be enclosure-specific
  [[ "$DEBUG" = true ]] && echo "DEBUG: Getting global Synergy resources..." >&2
  local global_resources=("uplink-sets" "network-sets" "sas-interconnects")

  for resource_type in "${global_resources[@]}"; do
    [[ "$DEBUG" = true ]] && echo "DEBUG: Attempting to get $resource_type..." >&2
    local global_response
    if global_response=$(get_oneview_resources "$resource_type" "" 2>/dev/null); then
      if jq -e '.members | length > 0' >/dev/null 2>&1 <<< "$global_response"; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: Found $(echo "$global_response" | jq '.members | length') $resource_type components" >&2
        while IFS= read -r component; do
          combined_response=$(echo "$combined_response" | jq --argjson comp "$component" '.members += [$comp]')
        done < <(echo "$global_response" | jq -c '.members[]')
      fi
    else
      [[ "$DEBUG" = true ]] && echo "DEBUG: Resource type $resource_type not available" >&2
    fi
  done

  echo "$combined_response"
}
# Get standard resources with optional server name filtering
get_standard_resources() {
  local resource_type="$1"
  local filter=""

  # Add server name filter if specified and we're checking server-hardware
  if [[ -n "$SERVER_NAME" && "$resource_type" == "server-hardware" ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Applying server name filter: $SERVER_NAME" >&2

    # Support different filter patterns
    if [[ "$SERVER_NAME" == *"*"* ]]; then
      # For wildcard patterns, we'll filter client-side using serverName field
      [[ "$DEBUG" = true ]] && echo "DEBUG: Using wildcard pattern, will filter client-side on serverName field" >&2
    else
      # Try exact serverName match first, fallback to name if needed
      filter="serverName='${SERVER_NAME}'"
      [[ "$DEBUG" = true ]] && echo "DEBUG: Using exact serverName filter: $filter" >&2
    fi
  fi

  local response
  response=$(get_oneview_resources "$resource_type" "$filter")

  # If we have a wildcard pattern and got results, filter client-side
  if [[ -n "$SERVER_NAME" && "$resource_type" == "server-hardware" && "$SERVER_NAME" == *"*"* ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Applying client-side wildcard filtering for pattern: $SERVER_NAME" >&2

    # Convert shell wildcard to bash pattern
    local pattern="$SERVER_NAME"

    # Filter the JSON response
    local filtered_response='{"members":[]}'

    while IFS= read -r member; do
      local name server_name
      name=$(echo "$member" | jq -r '.name // empty')
      server_name=$(echo "$member" | jq -r '.serverName // empty')

      # Try matching against serverName field first, then name field
      local match_field="$server_name"
      [[ -z "$match_field" || "$match_field" == "null" ]] && match_field="$name"

      # Use bash pattern matching
      if [[ "$match_field" == $pattern ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: Server '$match_field' matches pattern '$pattern'" >&2
        filtered_response=$(echo "$filtered_response" | jq --argjson member "$member" '.members += [$member]')
      fi
    done < <(echo "$response" | jq -c '.members[]?')

    response="$filtered_response"
  fi

  echo "$response"
}

# Map OneView status to monitoring status
map_oneview_status() {
  local status="$1"
  case "${status,,}" in
    "ok"|"normal"|"connected"|"configured") echo "OK" ;;
    "warning"|"degraded"|"minor") echo "WARNING" ;;
    "critical"|"error"|"failed"|"disconnected"|"major") echo "CRITICAL" ;;
    *) echo "UNKNOWN" ;;
  esac
}

# returns 0 if resource should be included in performance data
is_perfdata_included() {
  local resname="$1"
  local pat regex

  # If no perfdata include patterns are specified, include everything
  if [[ ${#PERFDATA_INCLUDES[@]} -eq 0 ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: No perfdata include patterns specified, including '$resname' in perfdata" >&2
    return 0
  fi

  [[ "$DEBUG" = true ]] && echo "DEBUG: Checking if resource '$resname' should be included in perfdata" >&2

  # Check perfdata inclusions
  for pat in "${PERFDATA_INCLUDES[@]}"; do
    [[ -z "$pat" ]] && continue
    [[ "$DEBUG" = true ]] && echo "DEBUG: Processing perfdata include pattern: '$pat'" >&2

    if [[ "$pat" =~ ^/.*/$ ]]; then
      regex="${pat:1:${#pat}-2}"
      if [[ "$resname" =~ $regex ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** PERFDATA INCLUDE MATCH *** '$resname' matched regex '$regex'" >&2
        return 0
      fi
    else
      if [[ "$resname" == $pat ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** PERFDATA INCLUDE MATCH *** '$resname' matched wildcard '$pat'" >&2
        return 0
      fi
    fi
  done

  [[ "$DEBUG" = true ]] && echo "DEBUG: Resource '$resname' NOT included in perfdata (no include patterns matched)" >&2
  return 1
}

# returns 0 if resource should be excluded from performance data
is_perfdata_excluded() {
  local resname="$1"
  local pat regex

  [[ "$DEBUG" = true ]] && echo "DEBUG: Checking if resource '$resname' should be excluded from perfdata" >&2

  # Check perfdata exclusions
  for pat in "${PERFDATA_EXCLUDES[@]}"; do
    [[ -z "$pat" ]] && continue
    [[ "$DEBUG" = true ]] && echo "DEBUG: Processing perfdata exclude pattern: '$pat'" >&2

    if [[ "$pat" =~ ^/.*/$ ]]; then
      regex="${pat:1:${#pat}-2}"
      if [[ "$resname" =~ $regex ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** PERFDATA EXCLUDE MATCH *** '$resname' matched regex '$regex'" >&2
        return 0
      fi
    else
      if [[ "$resname" == $pat ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** PERFDATA EXCLUDE MATCH *** '$resname' matched wildcard '$pat'" >&2
        return 0
      fi
    fi
  done

  [[ "$DEBUG" = true ]] && echo "DEBUG: Resource '$resname' NOT excluded from perfdata" >&2
  return 1
}

# returns 0 if resource should be included (matches include patterns)
is_included() {
  local resname="$1"
  local status="$2"
  local pat regex

  # If no include patterns are specified, include everything
  if [[ ${#INCLUDES[@]} -eq 0 && ${#STATUS_INCLUDES[@]} -eq 0 ]]; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: No include patterns specified, including resource '$resname'" >&2
    return 0
  fi

  [[ "$DEBUG" = true ]] && echo "DEBUG: Checking if resource '$resname' should be included" >&2

  # Check resource name inclusions
  for pat in "${INCLUDES[@]}"; do
    [[ -z "$pat" ]] && continue
    [[ "$DEBUG" = true ]] && echo "DEBUG: Processing include name pattern: '$pat'" >&2

    if [[ "$pat" =~ ^/.*/$ ]]; then
      regex="${pat:1:${#pat}-2}"
      if [[ "$resname" =~ $regex ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** INCLUDE MATCH *** '$resname' matched name regex '$regex'" >&2
        return 0
      fi
    else
      if [[ "$resname" == $pat ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** INCLUDE MATCH *** '$resname' matched name wildcard '$pat'" >&2
        return 0
      fi
    fi
  done

  # Check status inclusions
  for pat in "${STATUS_INCLUDES[@]}"; do
    [[ -z "$pat" ]] && continue
    [[ "$DEBUG" = true ]] && echo "DEBUG: Processing include status pattern: '$pat'" >&2

    if [[ "$pat" =~ ^/.*/$ ]]; then
      regex="${pat:1:${#pat}-2}"
      if [[ "$status" =~ $regex ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** INCLUDE MATCH *** '$status' matched status regex '$regex'" >&2
        return 0
      fi
    else
      if [[ "$status" == $pat ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** INCLUDE MATCH *** '$status' matched status wildcard '$pat'" >&2
        return 0
      fi
    fi
  done

  [[ "$DEBUG" = true ]] && echo "DEBUG: Resource '$resname' NOT included (no include patterns matched)" >&2
  return 1
}

# returns 0 if resname matches any exclude pattern
is_excluded() {
  local resname="$1"
  local status="$2"
  local pat regex

  [[ "$DEBUG" = true ]] && echo "DEBUG: Checking if resource '$resname' should be excluded" >&2

  # Check resource name exclusions
  for pat in "${EXCLUDES[@]}"; do
    [[ -z "$pat" ]] && continue
    [[ "$DEBUG" = true ]] && echo "DEBUG: Processing exclude name pattern: '$pat'" >&2

    if [[ "$pat" =~ ^/.*/$ ]]; then
      regex="${pat:1:${#pat}-2}"
      if [[ "$resname" =~ $regex ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** EXCLUDE MATCH *** '$resname' matched name regex '$regex'" >&2
        return 0
      fi
    else
      if [[ "$resname" == $pat ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** EXCLUDE MATCH *** '$resname' matched name wildcard '$pat'" >&2
        return 0
      fi
    fi
  done

  # Check status exclusions
  for pat in "${STATUS_EXCLUDES[@]}"; do
    [[ -z "$pat" ]] && continue
    [[ "$DEBUG" = true ]] && echo "DEBUG: Processing exclude status pattern: '$pat'" >&2

    if [[ "$pat" =~ ^/.*/$ ]]; then
      regex="${pat:1:${#pat}-2}"
      if [[ "$status" =~ $regex ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** EXCLUDE MATCH *** '$status' matched status regex '$regex'" >&2
        return 0
      fi
    else
      if [[ "$status" == $pat ]]; then
        [[ "$DEBUG" = true ]] && echo "DEBUG: *** EXCLUDE MATCH *** '$status' matched status wildcard '$pat'" >&2
        return 0
      fi
    fi
  done

  [[ "$DEBUG" = true ]] && echo "DEBUG: Resource '$resname' NOT excluded" >&2
  return 1
}

process_oneview_resources() {
  local json="$1"

  TOTAL=0; OK_COUNT=0; WARN_COUNT=0; CRIT_COUNT=0; UNKNOWN_COUNT=0

  # Separate arrays for different severity levels
  CRITICAL_DETAILS=()
  WARNING_DETAILS=()
  UNKNOWN_DETAILS=()
  OK_DETAILS=()
  PERFDATA_DETAILS=()

  [[ "$DEBUG" = true ]] && echo "DEBUG: Processing OneView resources" >&2

  if ! jq -e '.members | type == "array"' >/dev/null 2>&1 <<< "$json"; then
    [[ "$DEBUG" = true ]] && echo "DEBUG: Invalid OneView API response format" >&2
    return 1
  fi

  # Process each resource
  while IFS= read -r resource; do
    [[ -z "$resource" || "$resource" == "null" ]] && continue

    local name status description model serial power_state health_status resource_type
    name=$(jq -r '.name // "unknown"' <<< "$resource" 2>/dev/null || echo "unknown")
    status=$(jq -r '.status // .state // "Unknown"' <<< "$resource" 2>/dev/null || echo "Unknown")
    description=$(jq -r '.description // ""' <<< "$resource" 2>/dev/null || echo "")
    model=$(jq -r '.model // .productName // ""' <<< "$resource" 2>/dev/null || echo "")
    serial=$(jq -r '.serialNumber // ""' <<< "$resource" 2>/dev/null || echo "")
    power_state=$(jq -r '.powerState // ""' <<< "$resource" 2>/dev/null || echo "")
    resource_type=$(jq -r '.category // .type // ""' <<< "$resource" 2>/dev/null || echo "")

    # For server hardware, get additional health info
    if [[ "$resource_type" == *"server-hardware"* ]] || [[ "$RESOURCE_TYPE" == "server-hardware" ]]; then
      health_status=$(jq -r '.mpHealthSummary.status // .healthStatus // ""' <<< "$resource" 2>/dev/null || echo "")
      [[ -n "$health_status" && "$health_status" != "null" ]] && status="$health_status"
    fi

    [[ "$DEBUG" = true ]] && echo "DEBUG: Processing resource: '$name' with status '$status' (type: $resource_type)" >&2

    # Skip if no resource name
    [[ "$name" == "unknown" || "$name" == "null" || -z "$name" ]] && continue

    # Build detail information
    local detail_info=""
    if [[ "$DETAIL" = true ]]; then
      detail_parts=()
      [[ -n "$description" && "$description" != "null" ]] && detail_parts+=("$description")
      [[ -n "$model" && "$model" != "null" ]] && detail_parts+=("Model: $model")
      [[ -n "$serial" && "$serial" != "null" ]] && detail_parts+=("S/N: $serial")
      [[ -n "$power_state" && "$power_state" != "null" ]] && detail_parts+=("Power: $power_state")
      [[ -n "$resource_type" && "$resource_type" != "null" ]] && detail_parts+=("Type: $resource_type")

      if [[ ${#detail_parts[@]} -gt 0 ]]; then
        detail_info=" - $(IFS=', '; echo "${detail_parts[*]}")"
      fi
    fi

    # Apply include filters first (if any are specified)
    if ! is_included "$name" "$status"; then
      [[ "$DEBUG" = true ]] && echo "DEBUG: Resource '$name' not included by include filters" >&2
      continue
    fi

    # Apply exclude filters
    if is_excluded "$name" "$status"; then
      [[ "$DEBUG" = true ]] && echo "DEBUG: Excluding resource '$name'" >&2
      continue
    fi

    ((TOTAL++))

    # Map OneView status to monitoring status
    local mapped_status
    mapped_status=$(map_oneview_status "$status")

    # Convert state names to numbers and build detail string
    case "$mapped_status" in
      "OK") state_num=0; ((OK_COUNT++)); LABEL="[OK]" ;;
      "WARNING") state_num=1; ((WARN_COUNT++)); LABEL="[WARNING]" ;;
      "CRITICAL") state_num=2; ((CRIT_COUNT++)); LABEL="[CRITICAL]" ;;
      *) state_num=3; ((UNKNOWN_COUNT++)); LABEL="[UNKNOWN]" ;;
    esac

    # Add to appropriate severity-based details array for verbose output
    if [[ "$VERBOSE" = true ]]; then
      detail_line="${LABEL}: ${name} (${status})${detail_info}"

      case "$mapped_status" in
        "CRITICAL") CRITICAL_DETAILS+=("$detail_line") ;;
        "WARNING") WARNING_DETAILS+=("$detail_line") ;;
        "OK") OK_DETAILS+=("$detail_line") ;;
        *) UNKNOWN_DETAILS+=("$detail_line") ;;
      esac
    fi

    # Collect performance data if requested
    if [[ "$PERFDATA" = true || "$PERFDATA_ONLY" = true ]]; then
      # Apply perfdata include/exclude filters
      if is_perfdata_included "$name" && ! is_perfdata_excluded "$name"; then
        local perfdata_line="${name}=${state_num};status=${status}"
        [[ -n "$power_state" && "$power_state" != "null" ]] && perfdata_line+=";power=${power_state}"
        PERFDATA_DETAILS+=("$perfdata_line")
        [[ "$DEBUG" = true ]] && echo "DEBUG: Added perfdata for '$name': $perfdata_line" >&2
      fi
    fi
  done < <(jq -c '.members[]' <<< "$json" 2>/dev/null)

  [[ "$DEBUG" = true ]] && echo "DEBUG: Processed $TOTAL resources: OK=$OK_COUNT, WARN=$WARN_COUNT, CRIT=$CRIT_COUNT, UNKNOWN=$UNKNOWN_COUNT" >&2

  # Return success if we processed at least one resource
  return $(( TOTAL == 0 ? 1 : 0 ))
}

# Function to print sorted verbose output
print_sorted_details() {
  # Print in order of severity: CRITICAL, WARNING, UNKNOWN, OK
  [[ ${#CRITICAL_DETAILS[@]} -gt 0 ]] && printf "%s\n" "${CRITICAL_DETAILS[@]}"
  [[ ${#WARNING_DETAILS[@]} -gt 0 ]] && printf "%s\n" "${WARNING_DETAILS[@]}"
  [[ ${#UNKNOWN_DETAILS[@]} -gt 0 ]] && printf "%s\n" "${UNKNOWN_DETAILS[@]}"
  [[ ${#OK_DETAILS[@]} -gt 0 ]] && printf "%s\n" "${OK_DETAILS[@]}"
}

# Main execution logic
[[ "$DEBUG" = true ]] && echo "DEBUG: Starting OneView monitoring check" >&2

# Authenticate with OneView
if ! authenticate_oneview; then
  echo "UNKNOWN - Failed to authenticate with OneView"
  exit $UNKNOWN
fi

# Determine what to check based on options
if [[ "$ENCLOSURE_MODE" = true ]]; then
  # Comprehensive enclosure/frame mode - check ALL enclosures and components
  [[ "$DEBUG" = true ]] && echo "DEBUG: Performing comprehensive enclosure/frame mode check" >&2
  RESPONSE=$(get_all_enclosure_components)
else
  # Standard resource check with optional server filtering
  [[ "$DEBUG" = true ]] && echo "DEBUG: Fetching OneView resources..." >&2
  set +o errexit
  RESPONSE=$(get_standard_resources "$RESOURCE_TYPE")
  API_EXIT=$?
  set -o errexit

  if [[ $API_EXIT -ne 0 ]]; then
    echo "UNKNOWN - OneView API request failed. Response: ${RESPONSE:0:200}..."
    exit $UNKNOWN
  fi
fi

[[ "$DEBUG" = true ]] && echo "DEBUG: Response length: ${#RESPONSE} characters" >&2
[[ "$DEBUG" = true ]] && echo "DEBUG: Response starts with: ${RESPONSE:0:50}..." >&2

# Check if response is valid JSON
if ! jq -e '.members | type == "array"' >/dev/null 2>&1 <<< "$RESPONSE"; then
  echo "UNKNOWN - Invalid OneView API response format. Response: ${RESPONSE:0:200}..."
  exit $UNKNOWN
fi

# Process the resources
if ! process_oneview_resources "$RESPONSE"; then
  # If processing failed, show some debug info
  if [[ "$DEBUG" = true ]]; then
    echo "DEBUG: Processing failed. Response structure:" >&2
    echo "$RESPONSE" | jq '.members | length' 2>&1 | head -1 >&2
    echo "DEBUG: Sample member (if any):" >&2
    echo "$RESPONSE" | jq '.members[0]' 2>&1 | head -5 >&2
  fi

  # Check if we actually have zero resources (which is OK) vs processing failure
  member_count=$(echo "$RESPONSE" | jq '.members | length' 2>/dev/null || echo "0")

  if [[ "$member_count" == "0" ]]; then
    echo "[OK] - No ${RESOURCE_DISPLAY_NAME}${CONTEXT_INFO} found (OneView) | total=0 ok=0 warning=0 critical=0 unknown=0"
    exit $OK
  else
    echo "UNKNOWN - Processing failed for $member_count resources"
    exit $UNKNOWN
  fi
fi

# Generate performance data and output results
BASIC_PERFDATA="total=${TOTAL} ok=${OK_COUNT} warning=${WARN_COUNT} critical=${CRIT_COUNT} unknown=${UNKNOWN_COUNT}"

# Build extended performance data if requested
EXTENDED_PERFDATA=""
if [[ "$PERFDATA" = true || "$PERFDATA_ONLY" = true ]] && [[ ${#PERFDATA_DETAILS[@]} -gt 0 ]]; then
  # Join all resource performance data
  EXTENDED_PERFDATA=" $(IFS=' '; echo "${PERFDATA_DETAILS[*]}")"
fi

# If --perfdata-only flag is used, only show performance data
if [[ "$PERFDATA_ONLY" = true ]]; then
  if [[ -n "$EXTENDED_PERFDATA" ]]; then
    echo "${BASIC_PERFDATA}${EXTENDED_PERFDATA}"
  else
    echo "${BASIC_PERFDATA}"
  fi
  exit $OK
fi

# Determine which perfdata to use in the output
FINAL_PERFDATA="$BASIC_PERFDATA"
if [[ "$PERFDATA" = true && -n "$EXTENDED_PERFDATA" ]]; then
  FINAL_PERFDATA="${BASIC_PERFDATA}${EXTENDED_PERFDATA}"
fi

# Determine resource type display name and context
RESOURCE_DISPLAY_NAME="$RESOURCE_TYPE"
CONTEXT_INFO=""

if [[ "$ENCLOSURE_MODE" = true ]]; then
  RESOURCE_DISPLAY_NAME="enclosure components"
  CONTEXT_INFO=" (comprehensive mode)"
elif [[ -n "$SERVER_NAME" ]]; then
  RESOURCE_DISPLAY_NAME="servers"
  CONTEXT_INFO=" matching '$SERVER_NAME'"
else
  case "$RESOURCE_TYPE" in
    server-hardware) RESOURCE_DISPLAY_NAME="servers" ;;
    logical-interconnects) RESOURCE_DISPLAY_NAME="logical interconnects" ;;
    power-devices) RESOURCE_DISPLAY_NAME="power devices" ;;
    storage-systems) RESOURCE_DISPLAY_NAME="storage systems" ;;
    storage-pools) RESOURCE_DISPLAY_NAME="storage pools" ;;
  esac
fi

if (( CRIT_COUNT > 0 )); then
  echo "[CRITICAL] - ${CRIT_COUNT} critical ${RESOURCE_DISPLAY_NAME}${CONTEXT_INFO} (OneView) | ${FINAL_PERFDATA}"
  [[ "$VERBOSE" = true ]] && print_sorted_details
  exit $CRITICAL
elif (( WARN_COUNT > 0 )); then
  echo "[WARNING] - ${WARN_COUNT} warning ${RESOURCE_DISPLAY_NAME}${CONTEXT_INFO} (OneView) | ${FINAL_PERFDATA}"
  [[ "$VERBOSE" = true ]] && print_sorted_details
  exit $WARNING
elif (( UNKNOWN_COUNT > 0 )); then
  echo "[UNKNOWN] - ${UNKNOWN_COUNT} unknown ${RESOURCE_DISPLAY_NAME}${CONTEXT_INFO} (OneView) | ${FINAL_PERFDATA}"
  [[ "$VERBOSE" = true ]] && print_sorted_details
  exit $UNKNOWN
else
  echo "[OK] - All ${TOTAL} ${RESOURCE_DISPLAY_NAME}${CONTEXT_INFO} OK (OneView) | ${FINAL_PERFDATA}"
  [[ "$VERBOSE" = true ]] && print_sorted_details
  exit $OK
fi

