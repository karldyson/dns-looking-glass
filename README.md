# DNS Looking Glass

A distributed DNS looking glass that executes queries from multiple geographic vantage points. Useful for comparing DNS responses across CDN/anycast infrastructure, troubleshooting DNSSEC, and observing how recursive resolvers respond from different network locations.

---

## Architecture

```
Browser (HTML / CSS / JS — static files)
  │
  │  GET  /api/config.php   — filtered nameserver list
  │  POST /api/query.php    — proxied query result + raw packet bytes
  ▼
Web server (Apache or nginx + PHP 7.4+)
  ├── Serves static files directly (index.html, app.js, style.css, dns-parser.js)
  ├── config.php  reads dnslg-config.json, filters groups by client IP, returns JSON
  └── query.php   validates request, resolves node API URL, proxies to Go node
            │
            │  HTTP POST to http://<node>:<port>/   (server-side only)
            ▼
         dnslg-api (Go binary, one per remote DNS node)
           ├── Executes DNS query via github.com/miekg/dns
           ├── Returns: response text, raw wire bytes, timing, NSID, DNSSEC status
           └── Managed by systemd
```

**Key design point:** The browser never contacts remote nodes directly. Only the web server makes outbound connections to them, keeping firewall exposure to a minimum.

---

## Features

- **Multi-node parallel queries** — select any number of nodes; results appear in a collapsible accordion as each node responds
- **Three query modes:**
  - *Localhost* — query DNS software running on the remote node (default)
  - *Specify IP* — send a query to an arbitrary nameserver from the node's vantage point
  - *Full Recursive* — iterative resolution from root servers; each delegation step is shown with the nameserver hostname and IP
- **DNSSEC support:**
  - Set DO to request DNSSEC records (RRSIG, DS) throughout the resolution chain
  - Enable *Validate DNSSEC chain* to additionally verify DS→DNSKEY links, DNSKEY self-signatures, and the final answer RRSIG; reports Secure / Bogus / Insecure / Indeterminate per RFC 4034/4035/5155/6840
  - Trust anchor source is selectable: IANA root anchors (fetched by the web server from `root-anchors.xml`) or the remote node's local validating resolver (AD bit check)
  - **DS override/add** — supply DS records for any zone in the chain to test signing changes before publishing them in the parent:
    - *Add mode*: your DS is accepted alongside the existing parent DS (pre-rollover check — tests that a new KSK won't break resolution)
    - *Replace mode*: your DS replaces the parent DS entirely (cut-over check — tests that removing the old DS and publishing a new one will work)
  - Signed zones with no parent DS are reported as *insecure* (RFC 4035 §5.2); a self-verification step shows whether the zone's own DNSSEC is self-consistent, and distinguishes expired RRSIGs from cryptographic failures
- **Full DNS flag control** — RD, AD, CD, DO; EDNS UDP size; NSID; EDNS Client Subnet
- **Packet visualiser** — Wireshark-style field/bit breakdown and tcpdump-style hex dump, with cross-highlighting between the two views
- **Timing breakdown** — round-trip time, DNS query time, and overhead (network + PHP + Go handling) shown per node

---

## Prerequisites

**Web server**
- Apache 2.4 (with `mod_php` or PHP-FPM) **or** nginx with PHP-FPM
- PHP 7.4+ with the `curl` extension enabled
- `allow_url_fopen = On` in `php.ini` (required to fetch IANA trust anchors; only called when DNSSEC validation with IANA anchor mode is used)

**Remote nodes**
- The `dnslg-api` Go binary (one per node)
- Linux or macOS (amd64 or arm64)
- systemd (for service management)

**Build** (only needed to compile the Go binary)
- Go 1.24+

---

## Installation

### 1. Web server

Copy the contents of `webserver/` to your document root (or a subdirectory):

```bash
cp -r webserver/ /var/www/html/dnslg/
```

Create the config file from the example:

```bash
cp dnslg-config.example.json /var/www/html/dnslg/dnslg-config.json
$EDITOR /var/www/html/dnslg/dnslg-config.json
```

The config file must be in the same directory as `api/config.php` and `api/query.php` (one level up from `api/`).

**Apache** — the supplied `.htaccess` blocks direct HTTP access to `dnslg-config.json`. Ensure `AllowOverride` is enabled for the directory.

**nginx** — add a location block to deny access to the config file:
```nginx
location = /dnslg/dnslg-config.json { deny all; }
```

### 2. Remote nodes

#### Build

```bash
cd remote-node
make linux-amd64       # or linux-arm64 / darwin-intel / darwin-apple
make all               # all platforms
```

Binaries are output to `remote-node/build/<platform>/dnslg-api`.

#### Deploy

```bash
scp remote-node/build/linux-amd64/dnslg-api user@node.example.com:/usr/local/bin/
```

#### Configure and start

```bash
# On each remote node:
cp systemd/dnslg-api.default.example /etc/default/dnslg-api
$EDITOR /etc/default/dnslg-api          # set -bind and -port as needed

cp systemd/dnslg-api.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dnslg-api
```

Create the service user if it doesn't exist:

```bash
useradd -r -s /usr/sbin/nologin dnslg
```

Verify the node is reachable from the web server:

```bash
curl http://node.example.com:53080/ping
# {"status":"ok","version":"v1.0.0","built":"2026-06-18T12:00:00Z"}
```

---

## Configuration reference

All configuration lives in `dnslg-config.json` (web server only). See `dnslg-config.example.json` for a fully annotated example.

### Top-level keys

| Key | Type | Description |
|-----|------|-------------|
| `api.port` | integer | Default TCP port for reaching remote Go nodes (default: `53080`) |
| `nameservers` | array | Groups of nodes |
| `defaults.nameserver` | string | Tag of the node pre-selected on load |
| `defaults.qtype` | string | Default query type |
| `custom.enabled` | boolean | (Reserved) Show free-text nameserver input |
| `qtypes` | array | Ordered list of query types shown in the QTYPE dropdown |

### Nameserver group

```json
{
  "name": "Display name shown in the UI",
  "prefixes": ["0.0.0.0/0", "::/0"],
  "items": {
    "tag-key": { "name": "London", "host": "lon.example.com" },
    "tag-key2": { "name": "Frankfurt", "host": "fra.example.com", "port": 53081 }
  }
}
```

- `prefixes` — optional list of CIDRs (IPv4 or IPv6). If present, only clients whose IP matches are shown this group. Omit to show to all clients.
- `host` — hostname or IP address of the remote node.
- `port` — per-node API port override. Falls back to `api.port` if absent, zero, or out of range (1–65535).

---

## Go binary configuration

The `dnslg-api` binary is configured entirely via command-line flags.

```
dnslg-api [flags]

  -port int      TCP port to listen on (default 53080)
  -bind string   Comma-separated bind addresses (default "127.0.0.1")
  -version       Print version string and exit
  -revision      Print full build/VCS revision info and exit
```

### Bind address examples

| `-bind` value | Effect |
|---------------|--------|
| `127.0.0.1` | IPv4 localhost only (default) |
| `0.0.0.0` | All IPv4 interfaces |
| `::` | IPv6 only (may accept IPv4-mapped on some OSes) |
| `0.0.0.0,::` | Explicit dual-stack: separate listeners for IPv4 and IPv6 |

Pass flags via the `/etc/default/dnslg-api` environment file:

```ini
DNSLG_ARGS=-port 53080 -bind 0.0.0.0,::
```

---

## Extending with new DNS / EDNS features

The remote API uses a registry pattern for EDNS options. Adding a new option requires only a new Go file — no changes to core query logic.

1. Create `remote-node/internal/dns/edns/myoption.go`
2. Implement the `edns.Option` interface:

```go
package edns

import "github.com/miekg/dns"

func init() { Register(&myOption{}) }

type myOption struct{}

func (m *myOption) Code() uint16 { return 12345 }   // your EDNS option code

func (m *myOption) FromRequest(params map[string]interface{}) (dns.EDNS0, error) {
    // Build a dns.EDNS0 value from the JSON params.
    return &dns.EDNS0_LOCAL{Code: m.Code(), Data: []byte{...}}, nil
}

func (m *myOption) ParseResponse(opt dns.EDNS0) map[string]interface{} {
    // Extract structured data from the response EDNS0 value.
    return map[string]interface{}{"my_field": "..."}
}
```

3. The frontend sends `{ "code": 12345, ... }` in the `edns.options` array to activate the option.

---

## Security notes

- `dnslg-config.json` is protected from direct HTTP access by `.htaccess` (Apache) or a `deny all` nginx location block.
- The PHP `config.php` endpoint filters nameserver groups by client IP before returning — restricted groups never reach the browser.
- All DNS response text is HTML-entity-encoded before insertion into the DOM.
- The Go binary defaults to binding `127.0.0.1` only. Widen the bind address explicitly to accept remote connections from the web server.
- The `dnslg-api.service` systemd unit runs under a dedicated unprivileged user (`dnslg`) with `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, and related hardening options.
- `query.php` validates `qtype` against the configured whitelist before proxying.

---

## Author & licence

Copyright © 2024–2026 **Karl Dyson**. All rights reserved.

Licensed under the **Apache License, Version 2.0** (the "Licence"); you may not use this software except in compliance with the Licence. You may obtain a copy of the Licence at:

> https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and limitations under the Licence.

A copy of the full licence text is included in this repository as [`LICENSE`](LICENSE).
