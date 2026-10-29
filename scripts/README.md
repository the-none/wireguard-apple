# Cloudflare IP4P updater

`update-cloudflare-ip4p.sh` is a DDNS hook for a hostname whose AAAA records are
exclusively managed by one updater. It preserves one record, updates it to the
IPv6/IP4P value in `$3`, then deletes the other AAAA records for that exact name.
Other names and record types are not modified.

The host needs `sh`, `curl`, and `jsonfilter` (as used by OpenWrt).
The hook uses POSIX shell syntax suitable for BusyBox `ash`, with `tr` and
`sleep` supplied by BusyBox. It does not require Bash, `flock`, `jq`, GNU tools,
or Python on the router. Python is only used by the offline test suite.
Configure the calling DDNS service to export:

```sh
export DOMAIN="vpn.example.com"
export TTL=60
# Export CF_API_TOKEN from the existing private DDNS configuration.
```

Zone ID is discovered automatically by querying the hostname and then its parent
domains until an accessible active zone is found. This also handles zones such as
`example.co.uk`. No `CF_ZONE_ID` or `ROOT_ZONE` configuration is needed. The token
needs permission to list the zone as well as edit its DNS records. A failed zone
query stops the script without modifying records.

Forward the existing hook arguments, preserving the address in the third slot:

```sh
sh /path/to/update-cloudflare-ip4p.sh "$1" "$2" "$3"
```

`RECORD_TYPE`, if set, must be `AAAA`. `PROXIED`, if set, must be `false`.
Keep credentials in the device's private configuration, not in this repository.

The caller must run updates serially; the script does not use locks or `flock`.
A failed record update attempt starts again from a fresh record list, including
when a create request's response is lost.
The script stops with a nonzero exit status after three failed attempts, allowing
the calling service to retry with the current address.

Use one authoritative updater per hostname and supply the current address.
DNS caches can retain earlier answers until they refresh.

Run offline tests (no Cloudflare credentials or network access needed):

```sh
python3 -B -m unittest discover -s scripts/tests -v
```

The tests mock the Cloudflare HTTP API and the `jsonfilter` command
interfaces, while exercising the actual shell hook. Deployment on the target
router still needs its installed commands and real API credentials.
