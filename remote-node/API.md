# dnslg-api HTTP API

The remote node binary (`dnslg-api`) exposes a small HTTP API for DNS lookups. The web server proxies requests to it; you can also drive it directly with curl or your own tooling.

## Starting the server

```
dnslg-api [-port 53080] [-bind 127.0.0.1] [-debug]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `53080` | TCP port to listen on |
| `-bind` | `127.0.0.1` | Comma-separated bind addresses, e.g. `0.0.0.0,::` for dual-stack |
| `-debug` | off | Log every DNS query and DNSSEC validation decision to stderr |
| `-version` | — | Print version string and exit |
| `-revision` | — | Print full VCS build info and exit |

---

## Endpoints

### `GET /ping`

Health check. Returns version information.

**Response**

```json
{
  "status":  "ok",
  "version": "v1.2.3-4-gabcdef0",
  "built":   "2026-06-01T12:00:00Z"
}
```

```bash
curl http://127.0.0.1:53080/ping
```

---

### `POST /`

Execute a DNS query. The request and response are both JSON.

---

## Request object

```json
{
  "qname":             "example.com.",
  "qtype":             "A",
  "mode":              "localhost",
  "nameserver":        "",
  "port":              53,
  "use_tcp":           false,
  "flags": {
    "rd":       true,
    "ad":       false,
    "cd":       false,
    "do":       false,
    "validate": false
  },
  "edns": {
    "udp_size": 1232,
    "options":  []
  },
  "trust_anchor_mode":  "",
  "trust_anchors":      [],
  "zone_trust_anchors": []
}
```

### Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `qname` | string | — | **Required.** Query name. Trailing dot optional; normalised internally. |
| `qtype` | string | `"A"` | RR type name: `A`, `AAAA`, `MX`, `NS`, `SOA`, `TXT`, `DNSKEY`, `DS`, `NSEC`, `NSEC3`, `CAA`, `HTTPS`, `SVCB`, `ANY`, etc. Case-insensitive. |
| `mode` | string | `"localhost"` | Query mode: `"localhost"`, `"target"`, or `"recursive"`. |
| `nameserver` | string | — | Authoritative/resolver IP to query. Required when `mode == "target"`. Ignored in other modes. |
| `port` | int | `53` | DNS port. Applies in `localhost` and `target` modes. |
| `use_tcp` | bool | `false` | Send the query over TCP instead of UDP. Applies in `localhost` and `target` modes. `recursive` mode always starts with UDP and falls back to TCP automatically on truncation. |
| `flags` | object | see below | DNS header flags. |
| `edns` | object | see below | EDNS0 parameters. |
| `trust_anchor_mode` | string | `""` | How to establish the DNSSEC root trust anchor in `recursive` mode with `validate: true`. Either `"iana"` or `"local"`. |
| `trust_anchors` | array | `[]` | Root zone DS records supplied by the caller. Required when `trust_anchor_mode == "iana"`. |
| `zone_trust_anchors` | array | `[]` | Per-zone DS overrides for testing pre-publication scenarios. See [Zone trust anchors](#zone-trust-anchors). |

### `flags`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rd` | bool | `false` | Recursion Desired bit. |
| `ad` | bool | `false` | Authenticated Data bit. |
| `cd` | bool | `false` | Checking Disabled bit. When `true`, DNSSEC validation is skipped even if `validate: true` — result will be `"indeterminate"`. |
| `do` | bool | `false` | DNSSEC OK bit. Requests DNSSEC records (RRSIG, DS) from nameservers. Should be `true` whenever `validate: true`. |
| `validate` | bool | `false` | Perform full DNSSEC chain-of-trust validation. Only meaningful in `recursive` mode. Requires `do: true`. |

### `edns`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `udp_size` | int | `1232` (when EDNS active) | Advertised UDP payload size in the OPT RR. An OPT RR is added automatically when `do`, `udp_size`, or `options` is set. |
| `options` | array | `[]` | EDNS0 option objects. Each object must have a `"code"` field (integer). Additional fields depend on the option. |

#### EDNS option: NSID (code 3)

Requests the Name Server Identifier from the responding server. No additional fields needed.

```json
{"code": 3}
```

The response carries the NSID in the top-level `nsid` field, and also in each `ResolutionStep.nsid` in recursive mode (useful for tracing anycast nodes at each delegation level).

#### EDNS option: ECS / EDNS Client Subnet (code 8)

Sends a client subnet prefix to the nameserver for geolocation-aware responses.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `code` | int | — | Must be `8`. |
| `family` | int | `1` | Address family: `1` = IPv4, `2` = IPv6. |
| `address` | string | `"0.0.0.0"` | Client IP address (only the network prefix matters). |
| `source_prefix` | int | `24` (IPv4) / `48` (IPv6) | Prefix length to send. |
| `scope_prefix` | int | `0` | Scope prefix returned by the server (set this to `0` in requests). |

```json
{"code": 8, "family": 1, "address": "203.0.113.0", "source_prefix": 24}
```

### `trust_anchors`

Array of DS records representing the IANA root trust anchors. Used when `trust_anchor_mode == "iana"`. The web server fetches and caches these from IANA; supply them here when calling the node directly.

```json
[
  {
    "key_tag":     20326,
    "algorithm":   8,
    "digest_type": 2,
    "digest":      "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
  },
  {
    "key_tag":     38696,
    "algorithm":   8,
    "digest_type": 2,
    "digest":      "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
  }
]
```

### Zone trust anchors

`zone_trust_anchors` lets you supply DS records for a specific zone to simulate what validation would look like before (or instead of) publishing a DS in the parent. Each element:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `zone` | string | — | Zone name, e.g. `"example.com."`. |
| `ds` | array | — | Array of DS records in the same `TrustAnchorDS` format as `trust_anchors`. |
| `override` | bool | `false` | `false` = **add mode**: caller DS is accepted alongside any parent-published DS (test a new KSK before rollover). `true` = **replace mode**: caller DS replaces the parent DS entirely, and the DS RRSIG check is skipped (test a complete KSK swap before the change goes live). |

```json
"zone_trust_anchors": [
  {
    "zone": "example.com.",
    "ds": [
      {
        "key_tag":     12345,
        "algorithm":   13,
        "digest_type": 2,
        "digest":      "AABBCC..."
      }
    ],
    "override": false
  }
]
```

---

## Response object

```json
{
  "dns_query_ms":      12.3,
  "nameserver":        "8.8.8.8:53",
  "response_text":     ";; ... dig-style text ...",
  "query_bytes_hex":   "...",
  "response_bytes_hex":"...",
  "nsid":              "ns1.example.com",
  "dnssec_valid":      true,
  "resolution_chain":  [...],
  "error":             ""
}
```

| Field | Type | Description |
|-------|------|-------------|
| `dns_query_ms` | float | Round-trip time of the final DNS exchange in milliseconds. |
| `nameserver` | string | `ip:port` of the server that answered the final query. |
| `response_text` | string | dig-style text representation of the DNS response. |
| `query_bytes_hex` | string | Hex-encoded DNS wire format of the outbound query. |
| `response_bytes_hex` | string | Hex-encoded DNS wire format of the response. |
| `nsid` | string | NSID returned by the server, if requested and present. Omitted when empty. |
| `dnssec_valid` | null / bool / string | DNSSEC validation result. See below. |
| `resolution_chain` | array | One entry per iterative query step in `recursive` mode, plus extra DNSSEC validation steps when `validate: true`. Empty in `localhost` / `target` modes. |
| `error` | string | Non-empty when the query could not be completed. Omitted on success. |

### `dnssec_valid` values

| Value | Meaning |
|-------|---------|
| `null` | Validation was not requested (`validate: false`). |
| `true` | **Secure** — complete chain of trust from root to answer verified. |
| `false` | **Bogus** — a specific cryptographic check failed (bad RRSIG, DS mismatch, NSEC proof wrong, etc.). |
| `"insecure"` | Unsigned delegation (no DS in parent), or an algorithm the validator doesn't support (treated as unsigned per RFC 4033 §5). |
| `"indeterminate"` | A precondition could not be met: CD flag set, no trust anchor supplied, DNSKEY/DS fetch failed, or no RRSIGs in the answer. |

### `resolution_chain` entries

Each entry is a `ResolutionStep`:

| Field | Type | Description |
|-------|------|-------------|
| `nameserver` | string | `ip:port` queried. |
| `nameserver_name` | string | Hostname of the nameserver, if known. Omitted when empty. |
| `qname` | string | Name queried at this step. |
| `qtype` | string | Type queried at this step (e.g. `"A"`, `"DS"`, `"DNSKEY"`, `"VERIFY"`). |
| `step_note` | string | Human-readable annotation. For validation steps describes what was checked and the outcome. Omitted when empty. |
| `validation_step` | bool | `true` for DNSSEC DNSKEY/DS/VERIFY steps appended after the resolution chain. Lets you split the UI into "Resolution" and "DNSSEC validation" sections. Omitted (false) for resolution steps. |
| `nsid` | string | NSID returned by this nameserver, if requested. Omitted when empty. |
| `response_text` | string | dig-style text of the response at this step. |
| `query_bytes_hex` | string | Hex DNS wire of the query sent. |
| `response_bytes_hex` | string | Hex DNS wire of the response received. |
| `dns_query_ms` | float | Round-trip time in milliseconds. |

---

## Modes

### `localhost`

Sends a single query to `127.0.0.1:53` — the DNS resolver running on the same host as the node. The `rd` flag is typically set so the local resolver recurses. Useful for seeing how the local resolver answers, including its caches and any local zones it is authoritative for.

### `target`

Sends a single query to the IP and port you specify in `nameserver` and `port`. Useful for querying a specific authoritative nameserver directly.

### `recursive`

Performs full iterative resolution from the root servers, following NS referrals step by step. Does not rely on the local resolver at all. With `do: true` and `validate: true`, the node also fetches DNSKEYs at each delegation and verifies the full DNSSEC chain of trust.

---

## curl examples

All examples assume the node is listening on `127.0.0.1:53080`. Pipe through `jq` if available for readable output.

### 1. `localhost` mode — query the node's local resolver

```bash
curl -s -X POST http://127.0.0.1:53080/ \
  -H 'Content-Type: application/json' \
  -d '{
    "qname": "example.com.",
    "qtype": "A",
    "mode":  "localhost",
    "flags": {"rd": true}
  }' | jq .
```

### 2. `target` mode — query a specific nameserver directly

Query one of the root servers for the `.uk` delegation without recursion:

```bash
curl -s -X POST http://127.0.0.1:53080/ \
  -H 'Content-Type: application/json' \
  -d '{
    "qname":      "uk.",
    "qtype":      "NS",
    "mode":       "target",
    "nameserver": "198.41.0.4",
    "port":       53,
    "flags":      {"rd": false, "do": true},
    "edns":       {"udp_size": 1232}
  }' | jq .
```

Query a specific authoritative server over TCP with NSID:

```bash
curl -s -X POST http://127.0.0.1:53080/ \
  -H 'Content-Type: application/json' \
  -d '{
    "qname":      "nsec3.uk.",
    "qtype":      "SOA",
    "mode":       "target",
    "nameserver": "2a01:618:400::1",
    "port":       53,
    "use_tcp":    true,
    "flags":      {"do": true},
    "edns": {
      "udp_size": 1232,
      "options":  [{"code": 3}]
    }
  }' | jq '{nameserver, nsid, response_text}'
```

### 3. `recursive` mode — iterative resolution from root

Resolve an A record, following all NS referrals from root:

```bash
curl -s -X POST http://127.0.0.1:53080/ \
  -H 'Content-Type: application/json' \
  -d '{
    "qname": "www.example.com.",
    "qtype": "A",
    "mode":  "recursive"
  }' | jq '{dns_query_ms, nameserver, response_text, resolution_chain: [.resolution_chain[] | {qtype, qname, nameserver, dns_query_ms}]}'
```

Resolve with DNSSEC validation using the IANA root trust anchor. Replace the `trust_anchors` array with current values from `https://data.iana.org/root-anchors/root-anchors.xml` or copy from `dnslg-config.json`:

```bash
curl -s -X POST http://127.0.0.1:53080/ \
  -H 'Content-Type: application/json' \
  -d '{
    "qname": "nsec3.uk.",
    "qtype": "SOA",
    "mode":  "recursive",
    "flags": {"do": true, "validate": true},
    "trust_anchor_mode": "iana",
    "trust_anchors": [
      {
        "key_tag":     20326,
        "algorithm":   8,
        "digest_type": 2,
        "digest":      "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
      },
      {
        "key_tag":     38696,
        "algorithm":   8,
        "digest_type": 2,
        "digest":      "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
      }
    ]
  }' | jq '{dnssec_valid, nameserver, resolution_chain: [.resolution_chain[] | {qtype, qname, step_note, validation_step}]}'
```

Resolve with NSID at every hop to see which anycast node answers each delegation:

```bash
curl -s -X POST http://127.0.0.1:53080/ \
  -H 'Content-Type: application/json' \
  -d '{
    "qname": "nsec3.uk.",
    "qtype": "SOA",
    "mode":  "recursive",
    "flags": {"do": true},
    "edns": {
      "udp_size": 1232,
      "options":  [{"code": 3}]
    }
  }' | jq '[.resolution_chain[] | {qname, nameserver_name, nsid}]'
```

Resolve with ECS to influence geolocation-aware CDN responses:

```bash
curl -s -X POST http://127.0.0.1:53080/ \
  -H 'Content-Type: application/json' \
  -d '{
    "qname": "www.example.com.",
    "qtype": "A",
    "mode":  "recursive",
    "edns": {
      "udp_size": 1232,
      "options": [
        {"code": 8, "family": 1, "address": "203.0.113.0", "source_prefix": 24}
      ]
    }
  }' | jq .
```

---

## Testing a pre-publication DS (zone trust anchor)

Simulate what DNSSEC validation would look like if you added a specific DS to a zone's parent before actually doing so. Compute the DS from the zone's current KSK first (e.g. with `dig DNSKEY example.com. | dnssec-dsfromkey -f - example.com.`), then supply it in `zone_trust_anchors`.

**Add mode** — accept the new DS alongside any existing parent DS (safe pre-rollover test):

```bash
curl -s -X POST http://127.0.0.1:53080/ \
  -H 'Content-Type: application/json' \
  -d '{
    "qname": "example.com.",
    "qtype": "SOA",
    "mode":  "recursive",
    "flags": {"do": true, "validate": true},
    "trust_anchor_mode": "iana",
    "trust_anchors": [ ... ],
    "zone_trust_anchors": [
      {
        "zone": "example.com.",
        "override": false,
        "ds": [
          {
            "key_tag":     12345,
            "algorithm":   13,
            "digest_type": 2,
            "digest":      "AABBCCDD..."
          }
        ]
      }
    ]
  }' | jq '{dnssec_valid, resolution_chain: [.resolution_chain[] | select(.validation_step) | {step_note}]}'
```

**Replace mode** — replace the parent DS entirely (test a complete KSK rollover before publishing):

```bash
curl -s -X POST http://127.0.0.1:53080/ \
  -H 'Content-Type: application/json' \
  -d '{
    "qname": "example.com.",
    "qtype": "SOA",
    "mode":  "recursive",
    "flags": {"do": true, "validate": true},
    "trust_anchor_mode": "iana",
    "trust_anchors": [ ... ],
    "zone_trust_anchors": [
      {
        "zone": "example.com.",
        "override": true,
        "ds": [ { "key_tag": 12345, "algorithm": 13, "digest_type": 2, "digest": "AABBCCDD..." } ]
      }
    ]
  }' | jq '{dnssec_valid}'
```

---

## Error responses

HTTP errors from the server itself (not DNS errors) use status 400 or 405 with a JSON body:

```json
{"error": "qname is required"}
```

DNS-level failures (SERVFAIL, network timeout, unresolvable NS) are returned with HTTP 200. Check the `error` field in the response:

```json
{
  "dns_query_ms": 5001.2,
  "nameserver":   "198.41.0.4:53",
  "error":        "dial udp 198.41.0.4:53: i/o timeout"
}
```

In `recursive` mode a partial `resolution_chain` is returned when the hard step cap (30 steps) is hit or when all nameservers for a delegation fail.

---

## Adding a new EDNS option

Implement the `edns.Option` interface in `internal/dns/edns/myoption.go` and call `edns.Register(&MyOption{})` from an `init()` function. The new option code will then be accepted in the `options` array and any response data returned under that code will be parsed and discarded (or extended via `ParseResponse`). No other files need changing.
