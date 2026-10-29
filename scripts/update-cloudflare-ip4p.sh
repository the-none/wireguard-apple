#!/bin/sh
# Update one exclusively managed AAAA record using POSIX sh (BusyBox ash).
# Required: CF_API_TOKEN and DOMAIN. The caller runs updates serially.
# The IP4P address is supplied in $3 by the calling DDNS hook.

# User config
CF_API_TOKEN="${CF_API_TOKEN:-cf token with Zone.DNS and Zone.Zone}"
RECORD_TYPE="${RECORD_TYPE:-AAAA}"
TTL="${TTL:-60}"
PROXIED="${PROXIED:-false}"
DOMAIN="${DOMAIN:-vpn.example.com}"

set -u

: "${CF_API_TOKEN:?Set CF_API_TOKEN}"
: "${DOMAIN:?Set DOMAIN}"
IP_ADDR="${3:-}"
TTL="${TTL:-60}"
CF_API="https://api.cloudflare.com/client/v4"

[ -n "$IP_ADDR" ] || { echo 'missing IPv6 address in $3' >&2; exit 1; }
[ "${RECORD_TYPE:-AAAA}" = AAAA ] || { echo 'This hook only manages AAAA records' >&2; exit 1; }
[ "${PROXIED:-false}" = false ] || { echo 'IP4P records must use DNS only (PROXIED=false)' >&2; exit 1; }
# Limit characters before constructing JSON; Cloudflare validates IPv6 syntax.
case "$IP_ADDR" in *[!0-9a-fA-F:]*) echo 'Invalid IPv6 characters' >&2; exit 1 ;; esac
case "$IP_ADDR" in *:*) ;; *) echo 'Expected an IPv6 address' >&2; exit 1 ;; esac
case "$TTL" in ''|*[!0-9]*) echo 'TTL must be a number' >&2; exit 1 ;; esac
DOMAIN=$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')
DOMAIN="${DOMAIN%.}"
case "$DOMAIN" in ''|*[!a-z0-9.-]*) echo 'DOMAIN must be an ASCII DNS name' >&2; exit 1 ;; esac

for command in curl jsonfilter; do
    command -v "$command" >/dev/null 2>&1 || { echo "Missing command: $command" >&2; exit 1; }
done

# No automatic retry here: a POST may have succeeded even if its reply was lost.
api() (
    method=$1
    path=$2
    shift 2
    response=$(curl -fsS --connect-timeout 10 --max-time 30 \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -X "$method" "${CF_API}/${path}" "$@") || return 1
    success=$(printf '%s' "$response" | jsonfilter -e '@.success') || return 1
    if [ "$success" != true ]; then
        echo "Cloudflare API rejected $method $path" >&2
        printf '%s' "$response" | jsonfilter -e '@.errors[*].message' >&2
        return 1
    fi
    printf '%s\n' "$response"
)

ROOT_ZONE="$DOMAIN"
ZONE_ID=""
while :; do
    zone=$(api GET zones --get --data-urlencode "name=$ROOT_ZONE" --data-urlencode 'status=active') || exit 1
    ZONE_ID=$(printf '%s' "$zone" | jsonfilter -e '@.result[0].id') || true
    [ -z "$ZONE_ID" ] || break
    ROOT_ZONE="${ROOT_ZONE#*.}"
    case "$ROOT_ZONE" in
        *.*) ;;
        *) echo "No accessible active Cloudflare zone found for $DOMAIN" >&2; exit 1 ;;
    esac
done
case "$ZONE_ID" in ''|*[!0-9a-fA-F]*) echo 'Missing or invalid Cloudflare zone ID' >&2; exit 1 ;; esac

RECORDS_PATH="zones/${ZONE_ID}/dns_records"
BODY="{\"type\":\"AAAA\",\"name\":\"${DOMAIN}\",\"content\":\"${IP_ADDR}\",\"ttl\":${TTL},\"proxied\":false}"

list_ids() (
    page=1
    while :; do
        response=$(api GET "$RECORDS_PATH" --get \
            --data-urlencode 'type=AAAA' --data-urlencode "name.exact=$DOMAIN" --data-urlencode 'match=all' \
            --data-urlencode 'per_page=100' --data-urlencode "page=$page") || return 1
        pages=$(printf '%s' "$response" | jsonfilter -e '@.result_info.total_pages') || return 1
        case "$pages" in ''|*[!0-9]*) echo 'Missing DNS pagination metadata' >&2; return 1 ;; esac
        printf '%s' "$response" | jsonfilter -e '@.result[*].id'
        [ "$page" -ge "$pages" ] && break
        page=$((page + 1))
    done
)

sync_record() (
    ids=$(list_ids) || return 1
    keep=""
    for id in $ids; do
        keep="$id"
        break
    done
    if [ -n "$keep" ]; then
        response=$(api PUT "${RECORDS_PATH}/${keep}" --data "$BODY") || return 1
    else
        response=$(api POST "$RECORDS_PATH" --data "$BODY") || return 1
        keep=$(printf '%s' "$response" | jsonfilter -e '@.result.id') || return 1
        [ -n "$keep" ] || return 1
    fi

    # Keep a successfully updated record before removing any duplicates.
    ids=$(list_ids) || return 1
    found=false
    for id in $ids; do
        [ "$id" != "$keep" ] || found=true
    done
    [ "$found" = true ] || { echo 'Updated record disappeared; retrying from a fresh list' >&2; return 1; }
    for id in $ids; do
        if [ "$id" != "$keep" ]; then
            api DELETE "${RECORDS_PATH}/${id}" >/dev/null || return 1
            echo "Removed duplicate AAAA record $id for $DOMAIN"
        fi
    done

    ids=$(list_ids) || return 1
    [ "$ids" = "$keep" ] || { echo 'Record set changed during update; retrying' >&2; return 1; }
    echo "Updated $DOMAIN to $IP_ADDR; exactly one AAAA record remains"
)

attempt=1
while ! sync_record; do
    [ "$attempt" -lt 3 ] || { echo 'Cloudflare update failed after 3 attempts' >&2; exit 1; }
    echo "Attempt $attempt failed; re-reading Cloudflare records in 5 seconds" >&2
    attempt=$((attempt + 1))
    sleep 5
done
