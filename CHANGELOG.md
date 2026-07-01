# Changelog

All notable changes to DNS Looking Glass are documented here. Version numbers correspond to git tags; dates are the tag commit date (Europe/London).

---

## [v0.5.2] — 2026-06-30

### Added

- **Packet payload sizes** — timing bar now shows `sent N B / rcvd N B` alongside query timing in all three modes. Recursive mode also shows per-step sizes in each resolution chain step header. The `packetSizeStr()` helper handles partial data gracefully (e.g. when only a sent size is available due to an error before the response arrived).
- **UDP/TCP protocol toggle in Localhost mode** — the Protocol (UDP/TCP) radio buttons were previously only visible in Specify IP mode. They are now shown for Localhost mode as well, and hidden only for Full Recursive mode (which manages its own transport). The node label appends `· TCP` when TCP is explicitly selected in Localhost mode.
- **DNSKEY Key Tag in packet detail** — the packet visualiser now shows the DNSKEY key tag as a computed field at the end of the DNSKEY RDATA tree. Computed per RFC 4034 Appendix B from the full RDATA bytes. The field is informational only (no hex cross-highlight, since the key tag is derived from all RDATA bytes rather than residing at a fixed wire offset).

### Fixed

- **Inaccurate wire byte sizes** — packet sizes were previously derived by calling `resp.Pack()` on the parsed response. `miekg/dns` sets `Compress=false` on received messages by default, so `Pack()` emits full owner names rather than compression pointers, inflating the reported size by roughly 10 bytes per compressed name reference (a 1317 B packet appeared as 1367 B). All query paths (main iterative loop, DNSKEY/DS fetch helpers, direct query modes, local root trust check) now use a new `exchangeRaw` helper that dials with `dns.DialTimeout`, writes with `conn.WriteMsg`, and reads with `conn.ReadMsgHeader` to capture exact wire bytes without re-serialisation.
- **"Overflowing header size" on large UDP responses** — `dns.DialTimeout` creates a `*dns.Conn` with `UDPSize = 0`, which caused `ReadMsgHeader` to allocate only a 512 B receive buffer. Responses larger than 512 B (DNSKEY records, large referral packets) were silently truncated by the OS read, producing `unpack: dns: overflowing header size` errors. Fixed by setting `co.UDPSize` from the EDNS OPT record in the outgoing query before calling `ReadMsgHeader` (falling back to `dns.DefaultMsgSize` = 4096 for non-EDNS queries). `dns.Client.Exchange` does this automatically; the new `exchangeRaw` path now matches that behaviour.
- **Step note causing timing to wrap** — validation step notes (italic annotation text in resolution chain step headers) were inline in the left `<span>`, pushing the right-aligned timing and size info off the end of the row on long notes. The note is now a full-width flex item rendered on its own line beneath the step label and timing.

---

## [v0.5.1] — 2026-06-25

### Added

- **Improved OPT / EDNS packet detail** — the packet visualiser (`dns-parser.js`) now special-cases the OPT RR (type 41). The `Class` field carries the UDP payload size (not a DNS class) and the `TTL` field carries EDNS version + extended flags (not seconds); both are now labelled and decoded correctly. The `Class` field is shown as `UDP Payload Size` with the numeric value; the `TTL` field expands to `Extended RCODE`, `EDNS Version`, and a DO bit in Wireshark bitfield style (`1... .... .... ....`). The RR label changes from `". OPT"` to `"OPT (EDNS)"`.
- **EDNS option inline decoding** — EDNS RDATA options are decoded by a new `decodeEdnsOpt` function rather than shown as raw hex: NSID (code 3) as `<hex> (<ASCII>)` or `(request)` when empty; ECS (code 8) as address family / source prefix / scope / address; ZONEVERSION (code 19) as type name and serial or value. `optCodeStr` updated to include ZONEVERSION.
- **All EDNS options in recursive mode** — options requested by the browser are now threaded through the full recursive resolver and DNSSEC validation stack via a pre-built `reqEdnsOpts []dns.EDNS0` slice. Functions that send DNS queries (`fetchDNSKEYResponse`, `fetchDSResponse`, `validateIntermediateZones`, `attemptSelfVerification`) all gained a `reqEdnsOpts` parameter, so user-requested options appear in the OPT record on every iterative query and every DNSKEY/DS fetch — not just the main loop queries.

### Fixed

- **EDNS UDP size override ignored in recursive mode** — the main iterative loop hardcoded a UDP payload size of 1232. It now reads `req.EDNS.UDPSize` (defaulting to 1232 when zero), matching the behaviour of the direct query modes.
- **EDNS UDP size checkbox UX** — per RFC 6891 §6.1.2 the OPT RR is always required when sending EDNS options (the UDP payload size is a field in the OPT RR itself, not a separate option). A new `syncEdnsUDPSize()` function enforces this: whenever DO, NSID, ZONEVERSION, or ECS is active, the EDNS UDP size checkbox is automatically checked and locked. The size value field remains editable. TCP mode bypasses the lock entirely.

---

## [v0.5.0] — 2026-06-25

### Added

- **EDNS ZONEVERSION (RFC 9660, option code 19)** — a checkbox in the EDNS options panel sends a ZONEVERSION request option on every query. The Go node (`edns/zoneversion.go`) decodes the response: type 0 (SOA-SERIAL) is exposed as a `serial` uint32; private-use types (246–255) with a 4-byte `Version` field are also decoded as a decimal `value` (matching `kdig` output). The structured result appears as a `zoneversion` field on both the top-level `QueryResponse` and each `ResolutionStep`. The raw miekg `; ZONEVERSION: …` line in `response_text` is replaced by a human-readable string (`cleanZoneVersionText`). In recursive mode, ZONEVERSION is included in the OPT record on every iterative query and every DNSKEY/DS fetch.
- **Webserver API documentation** — `webserver/api/` endpoint schemas (request, response, trust anchor modes, zone trust anchor semantics) documented.

---

## [v0.4.2] — 2026-06-24

### Fixed

- **Unsigned-zone DS add: indeterminate → bogus** — when a caller supplied a DS record (`zone_trust_anchors`) for a zone whose parent has no DS at all, and the supplied DS did not match the zone's DNSKEY, the result was incorrectly `"indeterminate"`. It is now correctly `"bogus"`. A test case was added to `dnssec_test.go` to cover this path.

---

## [v0.4.1] — 2026-06-22

### Added

- **RFC 4033 §5 compliance — unsupported algorithm → insecure** — DNSKEY or RRSIG algorithms not supported by `miekg/dns` (e.g. ED448, alg 16) are now treated as `"insecure"` rather than `"bogus"` or `"indeterminate"`. `validateIntermediateZones` propagates `isInsecure=true` upward when an intermediate zone uses an unsupported algorithm. Step note: `"DNSKEY self-signature uses unsupported algorithm X — insecure (RFC 4033 §5)"`.
- **RFC 4033 §5 constraint on zone trust anchors** — a caller-supplied DS cannot make a subtree of an insecure parent appear secure. When the parent chain has a DS but no RRSIG (the parent is unsigned), the result remains `"insecure"` regardless of any `zone_trust_anchors` override. Validation still proceeds with the supplied DS for diagnostic output; step note: `"zone validates with supplied DS, but parent chain is insecure (RFC 4033 §5)"`.
- **Version string in UI footer** — `webserver/version.json` (generated by `make version-json`, gitignored) is fetched on page load and displayed in the site footer. Graceful degradation: footer remains empty if the file is absent or the fetch fails.

### Changed

- **Integration test suite reorganised** — all tests in `dnssec_test.go` that query outside `nsec3.uk.` replaced with equivalent `nsec3.uk.` zones; synthetic `example.` TLD (RFC 2606) used throughout unit tests. Transport / non-DNSSEC tests moved to `dns_test.go`. Validation fixes following extensive testing against live `nsec3.uk.` zones.

---

## [v0.4.0] — 2026-06-21

### Added

- **Separate resolution and DNSSEC validation chain display** — the frontend splits `resolution_chain` into two labelled sub-sections: "Resolution chain (N steps)" and "DNSSEC validation (N steps)", based on the `validation_step` flag. Step numbers restart at 1 within each sub-section. The last step in each sub-section is expanded by default.

### Fixed

- **NSID not returned in recursive and validation chains** — the OPT record in iterative queries was not including the NSID option. NSID is now sent on every iterative query and every DNSKEY/DS validation query. Each `ResolutionStep` has an `nsid` field; `buildRecursiveResponse` copies the last non-validation step's NSID to the top-level response.

---

## [v0.3.0] — 2026-06-20

### Fixed

- Validation path corrections following testing against live `nsec3.uk.` zones, covering edge cases in NSEC/NSEC3 proof paths, insecure delegation handling, and intermediate zone traversal.

---

## [v0.2.0] — 2026-06-20

### Added

- **Zone trust anchors — pre-publication DS testing** — callers can supply DS records for specific zones via `zone_trust_anchors` to test DNSSEC signing changes before publishing in the parent:
  - *Add mode* (`override: false`) — caller DS accepted alongside any parent-published DS; parent DS RRSIG still verified. Tests that a new KSK won't break resolution before its DS is added.
  - *Replace mode* (`override: true`) — caller DS replaces the parent DS entirely; parent DS RRSIG check skipped. Tests a full KSK rollover before the old DS is removed.
- **DS override UI** — "Add DS override" button in the DNSSEC validation section. Each row has a zone name input, a DS record textarea (accepts full zone-file lines or bare RDATA; one per line — `parseDSRecord()` strips the optional `zone TTL IN DS` prefix), and an Add/Replace mode selector.
- **Key tag display in validation step notes** — step notes now include the key tag(s) at each check: `anyKeyMatchesDS` returns all matching tags; `verifyDNSKEYRRSig` and `verifyDSRRSig`/`verifyDSRRSigInAnswer` return the signing key tag. Formatted as `keytag=N` or `keytags=N, M`.

---

## [v0.1.0] — 2026-06-20

Initial release.

### Added

- **Iterative recursive resolver** with full DNSSEC chain-of-trust validation:
  - Four definitive validation states: **Secure** (`true`), **Bogus** (`false`), **Insecure** (`"insecure"` — unsigned delegation, RFC 4035 §5.2), **Indeterminate** (`"indeterminate"` — precondition unmet)
  - NSEC and NSEC3 denial-of-existence proofs (RFC 4035 §5.4, RFC 5155 §8.3–8.8)
  - NSEC3 opt-out (RFC 5155 §6)
  - Ancestor-delegation guard (RFC 6840 §4.1)
  - RRSIG temporal validity checked separately from cryptographic validity (RFC 4034 §3.1.5)
  - RRSIG SignerName ancestry check (RFC 4035 §5.3.1)
  - TC=1 UDP→TCP fallback on all DNS exchanges (`exchangeWithTCPFallback`)
  - IANA trust anchor mode (root-anchors.xml fetched and cached by `config.php`) and local resolver AD-bit mode
  - Insecure delegation self-verification (`attemptSelfVerification`) — when a zone has no parent DS, checks whether the zone is self-consistently signed as a diagnostic; distinguishes expired RRSIGs from cryptographic failures
  - DS RRSIG absent on explicit DS fetch path — signed child under unsigned parent correctly classified as insecure rather than bogus
- **Three query modes**: Localhost (node's local resolver), Specify IP (arbitrary nameserver), Full Recursive (iterative from root)
- **EDNS options** via registry pattern (`edns.Option` interface): NSID (code 3), ECS (code 8)
- **Packet visualiser** — Wireshark-style field tree with bit-level flag breakdown + tcpdump hex dump with cross-highlighting; covers DNS header, all common RR types, OPT/EDNS
- **IP-based nameserver group filtering** — `config.php` filters groups by client IP against CIDR prefix lists (pure PHP, no Composer)
- **Multi-node parallel queries** — `Promise.all` in the browser; collapsible accordion when more than one node is selected
- **systemd service unit** with hardening options (`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`); flag injection via `$DNSLG_ARGS` environment file
- **Dual-stack bind** — `-bind 0.0.0.0,::` opens separate listeners per address on the same port
- **Multi-arch Makefile** — `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`; version injected at build time via ldflags from `git describe`
