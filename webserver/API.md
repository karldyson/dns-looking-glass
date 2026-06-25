# DNS Looking Glass — Web API

The web tier exposes two PHP endpoints under `/api/`. The browser (or any HTTP client) talks only to these; the internal Go node addresses are never revealed.

```
Client → Apache/nginx → /api/config.php   (nameserver list + trust anchors)
                      → /api/query.php    (DNS query, proxied to Go node)
                                ↓ (server-side only)
                          dnslg-api :53080
```

---

## `GET /api/config.php`

Returns the runtime configuration the UI needs to populate its controls. Nameserver groups are filtered by the client's IP address against each group's prefix list; groups with no `prefixes` key are always visible.

**No request body or query parameters.**

### Response

```json
{
  "nameservers": [
    {
      "name": "Global Nodes",
      "items": {
        "node-lon": {"name": "London"},
        "node-fra": {"name": "Frankfurt"},
        "node-nyc": {"name": "New York"}
      }
    }
  ],
  "defaults": {
    "nameserver": "node-lon",
    "qtype": "A"
  },
  "custom": {
    "enabled": false
  },
  "qtypes": ["SOA", "NS", "A", "AAAA", "DNSKEY", "DS", "TXT", "ANY"],
  "client_ip": "203.0.113.42",
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
}
```

| Field | Type | Description |
|-------|------|-------------|
| `nameservers` | array | Nameserver groups visible to this client. Each group has a `name` string and an `items` object keyed by node tag. Each item has at minimum a `name` string. |
| `defaults.nameserver` | string | Tag of the node pre-selected on page load. |
| `defaults.qtype` | string | Query type pre-selected on page load. |
| `custom.enabled` | bool | Whether the UI should show a free-text nameserver field for querying arbitrary IPs in `target` mode. |
| `qtypes` | array | Allowlisted query types accepted by `/api/query.php`. The UI should restrict its dropdown to this list. |
| `client_ip` | string | The client IP as seen by the web server. Useful for displaying to the user or for ECS pre-population. |
| `trust_anchors` | array | Current IANA root zone DS records, fetched from `https://data.iana.org/root-anchors/root-anchors.xml` and cached in `/tmp` for 24 hours. Empty array if the fetch fails. Pass these back verbatim in `POST /api/query.php` requests that use DNSSEC validation. |

### Error responses

| HTTP | Body | Cause |
|------|------|-------|
| `500` | `{"error": "Config file not found or not readable"}` | `dnslg-config.json` is missing or unreadable by the web process. |
| `500` | `{"error": "Config file is not valid JSON"}` | Config file exists but cannot be parsed. |

### curl example

```bash
curl -s https://your-looking-glass.example.com/api/config.php | jq .
```

---

## `POST /api/query.php`

Validates the request, resolves the node tag to an internal Go API URL, proxies the query, and returns the result. The Go node address is never included in the response.

Content-Type must be `application/json`.

### Request object

```json
{
  "tag":   "node-lon",
  "qname": "example.com.",
  "qtype": "A",
  "mode":  "localhost",
  "nameserver": "",
  "port":  53,
  "use_tcp": false,
  "flags": {
    "rd":       true,
    "ad":       true,
    "cd":       false,
    "do":       false,
    "validate": false
  },
  "edns": {
    "udp_size": 1232,
    "options":  []
  },
  "trust_anchor_mode":  "iana",
  "trust_anchors":      [],
  "zone_trust_anchors": []
}
```

#### Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tag` | string | — | **Required.** Node tag from the `nameservers.items` map in config. Determines which Go node receives the request. |
| `qname` | string | — | **Required.** Query name. Trailing dot optional. |
| `qtype` | string | `"A"` | Query type. Must be in the `qtypes` allowlist from config. Case-insensitive; normalised to uppercase. |
| `mode` | string | `"localhost"` | Query mode: `"localhost"`, `"target"`, or `"recursive"`. |
| `nameserver` | string | `""` | Target nameserver IP. Used only in `target` mode. |
| `port` | int | `53` | DNS port. Used in `localhost` and `target` modes. |
| `use_tcp` | bool | `false` | Force TCP instead of UDP. Used in `localhost` and `target` modes. `recursive` mode falls back to TCP automatically on truncation. |
| `flags` | object | see below | DNS header flag bits. |
| `edns` | object | see below | EDNS0 parameters. |
| `trust_anchor_mode` | string | `"iana"` | How to establish the DNSSEC root trust anchor. `"iana"` = use `trust_anchors` supplied in the request; `"local"` = ask the Go node to check its local resolver's AD bit. |
| `trust_anchors` | array | `[]` | IANA root DS records to validate against. Pass the array from `GET /api/config.php` back unchanged. Used when `trust_anchor_mode == "iana"` and `flags.validate == true`. |
| `zone_trust_anchors` | array | `[]` | Per-zone DS overrides. See [Zone trust anchors](#zone-trust-anchors). Entries with missing or malformed fields are silently dropped by the web tier. |

#### `flags`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rd` | bool | `true` | Recursion Desired. |
| `ad` | bool | `true` | Authenticated Data. |
| `cd` | bool | `false` | Checking Disabled. When `true`, DNSSEC validation is skipped regardless of `validate`. |
| `do` | bool | `false` | DNSSEC OK. Requests RRSIG and DS records. Should be `true` when `validate: true`. |
| `validate` | bool | `false` | Perform full DNSSEC chain-of-trust validation. Meaningful only in `recursive` mode; requires `do: true`. |

Note: the web tier defaults `rd` and `ad` to `true`, differing from the Go node's own defaults of `false`. If you omit these fields the web tier passes `true` for both.

#### `edns`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `udp_size` | int | `1232` | Advertised UDP payload size in the OPT record. |
| `options` | array | `[]` | EDNS0 option objects. Each must have a `"code"` field. |

**NSID (code 3)** — request the Name Server Identifier:

```json
{"code": 3}
```

**ZONEVERSION (code 19)** — request zone version information (RFC 9660). No additional fields:

```json
{"code": 19}
```

The server returns zone version data in the OPT record. It appears in `response_text` as `; ZONEVERSION: …` lines. Only type 0 (SOA-SERIAL) is currently defined; the implementation returns unknown future type codes as `"unassigned"` with the raw data as hex.

**ECS / EDNS Client Subnet (code 8)** — send a client subnet prefix:

```json
{"code": 8, "family": 1, "address": "203.0.113.0", "source_prefix": 24}
```

| ECS field | Type | Default | Description |
|-----------|------|---------|-------------|
| `family` | int | `1` | `1` = IPv4, `2` = IPv6. |
| `address` | string | `"0.0.0.0"` | Client IP (only the network prefix is sent). |
| `source_prefix` | int | `24` / `48` | Prefix length to send. |
| `scope_prefix` | int | `0` | Scope prefix (set to `0` in requests; servers may return a non-zero value). |

#### Zone trust anchors

Lets you test DNSSEC validation with a DS record that is not yet (or never will be) published in the parent zone — for example, to verify that a new KSK will validate before committing to a rollover.

Each element of `zone_trust_anchors`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `zone` | string | — | Zone name, e.g. `"example.com."`. |
| `ds` | array | — | DS records in the same `{key_tag, algorithm, digest_type, digest}` shape as `trust_anchors`. |
| `override` | bool | `false` | `false` = **add mode**: caller DS accepted alongside any parent-published DS (pre-rollover test). `true` = **replace mode**: caller DS replaces whatever the parent publishes; DS RRSIG check against the parent is skipped (full KSK swap test). |

The web tier sanitises this input: entries missing required fields are dropped, and non-hex characters are stripped from digests before forwarding to the Go node.

---

### Response object

The response passes through all fields from the Go node and adds one field (`api_ms`).

```json
{
  "dns_query_ms":       12.3,
  "api_ms":             18.7,
  "nameserver":         "127.0.0.1:53",
  "response_text":      ";; ... dig-style text ...",
  "query_bytes_hex":    "...",
  "response_bytes_hex": "...",
  "nsid":               "ns1.example.com",
  "dnssec_valid":       true,
  "resolution_chain":   [...],
  "error":              ""
}
```

| Field | Type | Description |
|-------|------|-------------|
| `dns_query_ms` | float | Round-trip time of the final DNS exchange as measured inside the Go node, in milliseconds. |
| `api_ms` | float | Round-trip time of the entire PHP→Go proxy call as measured by the web server, in milliseconds. Includes network latency to the node and its processing time. |
| `nameserver` | string | `ip:port` of the nameserver that answered the final DNS query. |
| `response_text` | string | dig-style text representation of the DNS response. |
| `query_bytes_hex` | string | Hex-encoded DNS wire format of the outbound query. |
| `response_bytes_hex` | string | Hex-encoded DNS wire format of the response. |
| `nsid` | string | NSID returned by the server, if requested and present. Omitted when empty. |
| `dnssec_valid` | null / bool / string | DNSSEC validation result. See table below. |
| `resolution_chain` | array | One entry per iterative query step in `recursive` mode, plus DNSSEC validation steps when `validate: true`. Empty in `localhost` / `target` modes. |
| `error` | string | Non-empty when the DNS query could not be completed. Omitted on success. |

#### `dnssec_valid` values

| Value | Meaning |
|-------|---------|
| `null` | Validation not requested (`validate: false`). |
| `true` | **Secure** — complete chain of trust from root to answer verified. |
| `false` | **Bogus** — a cryptographic check failed (bad RRSIG, DS mismatch, NSEC/NSEC3 proof wrong, etc.). |
| `"insecure"` | Unsigned delegation (no DS in parent), or an algorithm not supported by the validator (treated as unsigned per RFC 4033 §5). |
| `"indeterminate"` | A precondition could not be met: CD flag set, no trust anchor supplied, DNSKEY/DS fetch failed, or no RRSIGs in the answer. |

#### `resolution_chain` entries

| Field | Type | Description |
|-------|------|-------------|
| `nameserver` | string | `ip:port` queried at this step. |
| `nameserver_name` | string | Hostname of the nameserver, if known. Omitted when empty. |
| `qname` | string | Name queried at this step. |
| `qtype` | string | Type queried at this step (`A`, `DS`, `DNSKEY`, `VERIFY`, etc.). |
| `step_note` | string | Human-readable annotation. For validation steps describes what was checked and the outcome. Omitted when empty. |
| `validation_step` | bool | `true` for DNSSEC DNSKEY/DS/VERIFY steps appended after the resolution chain. Use this to split the display into "Resolution chain" and "DNSSEC validation" sections. Omitted (false) for resolution steps. |
| `nsid` | string | NSID returned by this nameserver, if requested. Omitted when empty. |
| `response_text` | string | dig-style text of this step's response. |
| `query_bytes_hex` | string | Hex DNS wire of the query sent. |
| `response_bytes_hex` | string | Hex DNS wire of the response received. |
| `dns_query_ms` | float | Round-trip time in milliseconds for this step. |

### Error responses

| HTTP | Body | Cause |
|------|------|-------|
| `400` | `{"error": "Invalid JSON body"}` | Request body is not valid JSON. |
| `400` | `{"error": "qname is required"}` | `qname` field is missing or empty. |
| `400` | `{"error": "qtype 'XYZ' is not permitted"}` | `qtype` is not in the configured allowlist. |
| `400` | `{"error": "Unknown nameserver tag: 'foo'"}` | `tag` does not match any node in the config. |
| `405` | `{"error": "Method not allowed"}` | Request was not a POST. |
| `500` | `{"error": "Config file not found"}` | Server-side config problem. |
| `502` | `{"error": "Failed to reach remote node at http://..."}` | The Go node did not respond within 15 seconds (connect timeout 5 s). |

DNS-level failures (SERVFAIL, timeout, unresolvable NS) are returned with **HTTP 200**. Check the `error` field in the response body.

---

## curl examples

Replace `https://your-looking-glass.example.com` with your deployment URL. The `tag` value must match a key in the `nameservers.items` map returned by `/api/config.php`.

### 1. `localhost` mode — query the node's local resolver

The node queries its own `127.0.0.1:53`. This is the simplest mode: one DNS exchange, no `resolution_chain`.

```bash
curl -s -X POST https://your-looking-glass.example.com/api/query.php \
  -H 'Content-Type: application/json' \
  -d '{
    "tag":   "node-lon",
    "qname": "example.com.",
    "qtype": "A",
    "mode":  "localhost",
    "flags": {"rd": true}
  }' | jq '{dns_query_ms, nameserver, response_text}'
```

### 2. `target` mode — query a specific nameserver directly

Send a non-recursive query to a root server for the `.com` NS delegation:

```bash
curl -s -X POST https://your-looking-glass.example.com/api/query.php \
  -H 'Content-Type: application/json' \
  -d '{
    "tag":        "node-lon",
    "qname":      "com.",
    "qtype":      "NS",
    "mode":       "target",
    "nameserver": "198.41.0.4",
    "port":       53,
    "flags":      {"rd": false, "do": true},
    "edns":       {"udp_size": 1232, "options": []}
  }' | jq '{nameserver, response_text}'
```

Query over TCP with NSID:

```bash
curl -s -X POST https://your-looking-glass.example.com/api/query.php \
  -H 'Content-Type: application/json' \
  -d '{
    "tag":        "node-lon",
    "qname":      "nsec3.uk.",
    "qtype":      "SOA",
    "mode":       "target",
    "nameserver": "213.248.216.1",
    "port":       53,
    "use_tcp":    true,
    "flags":      {"do": true},
    "edns": {
      "udp_size": 1232,
      "options":  [{"code": 3}]
    }
  }' | jq '{nameserver, nsid, response_text}'
```

### 3. `recursive` mode — full iterative resolution from root

Resolve with the full delegation chain visible. First fetch the config to get trust anchors, then query:

```bash
# Step 1: get current trust anchors
ANCHORS=$(curl -s https://your-looking-glass.example.com/api/config.php \
  | jq '.trust_anchors')

# Step 2: resolve with DNSSEC validation
curl -s -X POST https://your-looking-glass.example.com/api/query.php \
  -H 'Content-Type: application/json' \
  -d "{
    \"tag\":               \"node-lon\",
    \"qname\":             \"nsec3.uk.\",
    \"qtype\":             \"SOA\",
    \"mode\":              \"recursive\",
    \"flags\":             {\"do\": true, \"validate\": true},
    \"trust_anchor_mode\": \"iana\",
    \"trust_anchors\":     $ANCHORS
  }" | jq '{dnssec_valid, api_ms, resolution_chain: [.resolution_chain[] | {qtype, qname, nameserver_name, step_note, validation_step}]}'
```

Resolve without validation to just see the iterative path:

```bash
curl -s -X POST https://your-looking-glass.example.com/api/query.php \
  -H 'Content-Type: application/json' \
  -d '{
    "tag":   "node-nyc",
    "qname": "www.example.com.",
    "qtype": "A",
    "mode":  "recursive"
  }' | jq '[.resolution_chain[] | {qname, qtype, nameserver, dns_query_ms}]'
```

Resolve with NSID to see which anycast node answers at each hop:

```bash
curl -s -X POST https://your-looking-glass.example.com/api/query.php \
  -H 'Content-Type: application/json' \
  -d '{
    "tag":   "node-lon",
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

Resolve with ECS to influence geolocation-aware answers:

```bash
curl -s -X POST https://your-looking-glass.example.com/api/query.php \
  -H 'Content-Type: application/json' \
  -d '{
    "tag":   "node-sin",
    "qname": "www.example.com.",
    "qtype": "A",
    "mode":  "recursive",
    "edns": {
      "udp_size": 1232,
      "options": [
        {"code": 8, "family": 1, "address": "203.0.113.0", "source_prefix": 24}
      ]
    }
  }' | jq '{nameserver, response_text}'
```

---

## Testing a pre-publication DS

Simulate validation with a DS record before it is published in the parent zone. Compute the DS from the zone's current DNSKEY first (e.g. with `dnssec-dsfromkey`), then supply it in `zone_trust_anchors`.

**Add mode** — accept the new DS alongside any existing parent DS:

```bash
ANCHORS=$(curl -s https://your-looking-glass.example.com/api/config.php | jq '.trust_anchors')

curl -s -X POST https://your-looking-glass.example.com/api/query.php \
  -H 'Content-Type: application/json' \
  -d "{
    \"tag\":               \"node-lon\",
    \"qname\":             \"example.com.\",
    \"qtype\":             \"SOA\",
    \"mode\":              \"recursive\",
    \"flags\":             {\"do\": true, \"validate\": true},
    \"trust_anchor_mode\": \"iana\",
    \"trust_anchors\":     $ANCHORS,
    \"zone_trust_anchors\": [
      {
        \"zone\":     \"example.com.\",
        \"override\": false,
        \"ds\": [
          {
            \"key_tag\":     12345,
            \"algorithm\":   13,
            \"digest_type\": 2,
            \"digest\":      \"AABBCCDD...\"
          }
        ]
      }
    ]
  }" | jq '{dnssec_valid, resolution_chain: [.resolution_chain[] | select(.validation_step) | .step_note]}'
```

**Replace mode** — replace the parent DS entirely (full KSK swap test):

Set `"override": true` in the `zone_trust_anchors` entry above.

---

## Configuration reference (`dnslg-config.json`)

The web server reads `dnslg-config.json` from the webserver root directory (one level above `api/`). The file is gitignored; copy from `dnslg-config.example.json`.

```json
{
  "api": {
    "port": 53080
  },
  "nameservers": [
    {
      "name": "Global Nodes",
      "prefixes": ["0.0.0.0/0", "::/0"],
      "items": {
        "node-lon": {"name": "London", "host": "lon.example.com"},
        "node-fra": {"name": "Frankfurt", "host": "fra.example.com", "port": 53081}
      }
    },
    {
      "name": "Internal Nodes",
      "prefixes": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"],
      "items": {
        "node-int": {"name": "Internal", "host": "resolver.internal.example.com"}
      }
    }
  ],
  "defaults": {
    "nameserver": "node-lon",
    "qtype": "A"
  },
  "custom": {
    "enabled": false
  },
  "qtypes": ["SOA", "NS", "A", "AAAA", "DNSKEY", "DS", "TXT", "ANY"]
}
```

| Field | Description |
|-------|-------------|
| `api.port` | Default TCP port used to reach all Go API nodes. Overridden per node by adding `"port"` to the item. |
| `nameservers[].name` | Display name for the group. |
| `nameservers[].prefixes` | CIDR list (IPv4 or IPv6). Groups are only shown to clients matching at least one prefix. Omit `prefixes` entirely to show the group to all clients. |
| `nameservers[].items` | Map of tag → node. Each node requires `host`; `port` is optional. Tags are the values used in the `tag` field of `POST /api/query.php`. |
| `defaults.nameserver` | Tag pre-selected on page load. |
| `defaults.qtype` | Query type pre-selected on page load. |
| `custom.enabled` | Whether the UI shows a free-text IP input for `target` mode. |
| `qtypes` | Allowlist of query types accepted by `/api/query.php`. Requests with any other type receive HTTP 400. |
