package dns

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Debug enables verbose logging of DNS queries and DNSSEC validation steps to stderr.
// Set via the -debug flag in main.
var Debug bool

func dbg(format string, args ...interface{}) {
	if Debug {
		log.Printf("[debug] "+format, args...)
	}
}

// namedAddr pairs a diallable address (ip:port) with its hostname.
type namedAddr struct {
	addr string // "ip:port"
	name string // hostname, may be empty
}

// rootServerList seeds iterative resolution with known root server hostnames.
var rootServerList = []namedAddr{
	{"198.41.0.4:53", "a.root-servers.net"},
	{"170.247.170.2:53", "b.root-servers.net"},
	{"192.33.4.12:53", "c.root-servers.net"},
	{"199.7.91.13:53", "d.root-servers.net"},
	{"192.203.230.10:53", "e.root-servers.net"},
	{"192.5.5.241:53", "f.root-servers.net"},
	{"192.112.36.4:53", "g.root-servers.net"},
	{"198.97.190.53:53", "h.root-servers.net"},
	{"192.36.148.17:53", "i.root-servers.net"},
	{"192.58.128.30:53", "j.root-servers.net"},
	{"193.0.14.129:53", "k.root-servers.net"},
	{"199.7.83.42:53", "l.root-servers.net"},
	{"202.12.27.33:53", "m.root-servers.net"},
}

// execRecursive performs iterative resolution from root servers.
func execRecursive(req *QueryRequest) *QueryResponse {
	qtype, ok := dns.StringToType[strings.ToUpper(req.QType)]
	if !ok {
		return &QueryResponse{Error: fmt.Sprintf("unknown qtype: %q", req.QType)}
	}

	var chain []ResolutionStep
	var dnssecValid interface{} = nil

	// Start with a random root server for load distribution.
	nameservers := shuffledNamed(rootServerList)

	qname := dns.Fqdn(req.QName)
	target := qname
	currentType := qtype
	const maxSteps = 30

	for step := 0; step < maxSteps; step++ {
		if len(nameservers) == 0 {
			break
		}
		cur := nameservers[0]

		msg := new(dns.Msg)
		msg.SetQuestion(target, currentType)
		msg.RecursionDesired = false // we do the iteration ourselves
		msg.AuthenticatedData = req.Flags.AD
		msg.CheckingDisabled = req.Flags.CD

		if req.Flags.DO {
			o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			o.SetUDPSize(1232)
			o.SetDo()
			msg.Extra = append(msg.Extra, o)
		}

		queryBytes, _ := msg.Pack()

		start := time.Now()
		resp, tcNote, err := exchangeWithTCPFallback(msg, cur.addr)
		elapsed := time.Since(start).Seconds() * 1000

		stepEntry := ResolutionStep{
			Nameserver:     cur.addr,
			NameserverName: cur.name,
			QName:          target,
			QType:          dns.TypeToString[currentType],
		}

		dbg("step %d: query %s %s → %s (%s)", step, target, dns.TypeToString[currentType], cur.addr, cur.name)

		if err != nil {
			dbg("step %d: error from %s: %v", step, cur.addr, err)
			nameservers = nameservers[1:]
			stepEntry.ResponseText = fmt.Sprintf("error: %v", err)
			stepEntry.QueryBytesHex = hex.EncodeToString(queryBytes)
			stepEntry.DNSQueryMS = elapsed
			chain = append(chain, stepEntry)
			continue
		}

		responseBytes, _ := resp.Pack()
		stepEntry.ResponseText = resp.String()
		if tcNote != "" {
			stepEntry.ResponseText = "; " + tcNote + "\n" + stepEntry.ResponseText
		}
		stepEntry.QueryBytesHex = hex.EncodeToString(queryBytes)
		stepEntry.ResponseBytesHex = hex.EncodeToString(responseBytes)
		stepEntry.DNSQueryMS = elapsed
		chain = append(chain, stepEntry)

		dbg("step %d: rcode=%s aa=%v answer=%d ns=%d additional=%d (%.1fms)",
			step, dns.RcodeToString[resp.Rcode], resp.Authoritative,
			len(resp.Answer), len(resp.Ns), len(resp.Extra), elapsed)

		switch resp.Rcode {
		case dns.RcodeSuccess:
			if len(resp.Answer) > 0 {
				// Check for CNAME chain.
				if isCNAME(resp.Answer, target, currentType) {
					cname := extractCNAME(resp.Answer, target)
					if cname != "" {
						dbg("step %d: following CNAME → %s", step, cname)
						target = dns.Fqdn(cname)
						nameservers = shuffledNamed(rootServerList)
						continue
					}
				}
				dbg("step %d: final answer (%d RRs)", step, len(resp.Answer))
				// We have a final answer.
				if req.Flags.DO && req.Flags.Validate {
					var validationSteps []ResolutionStep
					dnssecValid, validationSteps = validateChainOfTrust(chain, req)
					chain = append(chain, validationSteps...)
				}
				return buildRecursiveResponse(chain, dnssecValid)
			}
			// No answer but authority section — follow referral.
			if len(resp.Ns) > 0 {
				glue := extractGlue(resp.Extra)
				next := extractNSAddresses(resp.Ns, glue)
				if len(next) > 0 {
					dbg("step %d: referral via glue to %d server(s)", step, len(next))
					nameservers = next
					continue
				}
				// Need to resolve NS names — use first NS name.
				nsName := extractFirstNSName(resp.Ns)
				if nsName != "" {
					dbg("step %d: resolving NS name %s", step, nsName)
					nsAddrs := resolveNSAddr(nsName, req.Flags.DO)
					if len(nsAddrs) > 0 {
						nameservers = nsAddrs
						continue
					}
				}
			}
			dbg("step %d: NODATA or unresolvable", step)
			// NODATA or unresolvable.
			if req.Flags.DO && req.Flags.Validate {
				var validationSteps []ResolutionStep
				dnssecValid, validationSteps = validateChainOfTrust(chain, req)
				chain = append(chain, validationSteps...)
			}
			return buildRecursiveResponse(chain, dnssecValid)

		case dns.RcodeNameError: // NXDOMAIN
			dbg("step %d: NXDOMAIN", step)
			if req.Flags.DO && req.Flags.Validate {
				var validationSteps []ResolutionStep
				dnssecValid, validationSteps = validateChainOfTrust(chain, req)
				chain = append(chain, validationSteps...)
			}
			return buildRecursiveResponse(chain, dnssecValid)

		default:
			dbg("step %d: rcode %s — trying next server", step, dns.RcodeToString[resp.Rcode])
			// Server error — try next.
			nameservers = nameservers[1:]
		}
	}

	return buildRecursiveResponse(chain, dnssecValid)
}

func buildRecursiveResponse(chain []ResolutionStep, dnssecValid interface{}) *QueryResponse {
	var lastResponse, lastNS string
	var totalMS float64
	if len(chain) > 0 {
		last := chain[len(chain)-1]
		lastResponse = last.ResponseText
		lastNS = last.Nameserver
	}
	for _, step := range chain {
		totalMS += step.DNSQueryMS
	}
	return &QueryResponse{
		Nameserver:      lastNS,
		ResponseText:    lastResponse,
		DNSQueryMS:      totalMS,
		DNSSECValid:     dnssecValid,
		ResolutionChain: chain,
	}
}

// ── DNSSEC chain-of-trust validation ─────────────────────────────────────────

// zoneLevel represents one zone in the delegation hierarchy.
type zoneLevel struct {
	zone string    // e.g. ".", "com.", "example.com."
	ns   namedAddr // authoritative server for this zone
	ds   []*dns.DS // DS records from parent; nil means root (use trust anchor)
	resp *dns.Msg  // response received at this level
}

// parseDelegationChain converts the resolution step list into a sequence of zone
// levels. Each level carries the zone name, its authoritative NS, the DS records
// the parent provided, and the parsed response. DO must have been set during
// resolution so that DS records appear in authority sections.
func parseDelegationChain(chain []ResolutionStep) []zoneLevel {
	var levels []zoneLevel
	var pendingDS []*dns.DS
	currentZone := "."

	for _, step := range chain {
		if step.ResponseBytesHex == "" {
			continue
		}
		b, err := hex.DecodeString(step.ResponseBytesHex)
		if err != nil || len(b) == 0 {
			continue
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(b); err != nil {
			continue
		}

		// Skip server errors (SERVFAIL etc.) — the iterator retries another server;
		// only NOERROR referrals and NXDOMAIN carry useful delegation info.
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			continue
		}

		ns := namedAddr{addr: step.Nameserver, name: step.NameserverName}
		levels = append(levels, zoneLevel{zone: currentZone, ns: ns, ds: pendingDS, resp: resp})

		// NXDOMAIN and answers are terminal.
		if resp.Rcode == dns.RcodeNameError || len(resp.Answer) > 0 {
			break
		}

		// Extract DS records and the next zone's name from the authority section.
		pendingDS = nil
		nextZone := ""
		for _, rr := range resp.Ns {
			switch v := rr.(type) {
			case *dns.NS:
				if nextZone == "" {
					nextZone = strings.ToLower(v.Hdr.Name)
				}
			case *dns.DS:
				pendingDS = append(pendingDS, v)
			}
		}
		if nextZone == "" {
			break
		}
		currentZone = nextZone
	}

	return levels
}

// validateChainOfTrust performs full DNSSEC chain-of-trust validation. It parses
// the resolution chain to extract delegation zones and DS records, fetches DNSKEYs
// at each level, verifies DS→DNSKEY links and DNSKEY self-signatures, then verifies
// the answer RRSIG against the final zone's validated keys.
//
// Returns the result (true / false / "indeterminate") and all extra steps (DNSKEY
// queries) to append to the chain for display.
func validateChainOfTrust(chain []ResolutionStep, req *QueryRequest) (interface{}, []ResolutionStep) {
	if req.Flags.CD {
		return "indeterminate", nil
	}

	levels := parseDelegationChain(chain)
	if len(levels) == 0 {
		dbg("validate: no delegation levels parsed")
		return "indeterminate", nil
	}
	dbg("validate: parsed %d delegation level(s)", len(levels))

	var extraSteps []ResolutionStep
	validatedKeys := make(map[string][]*dns.DNSKEY) // zone → trusted key set

	// Inject caller-supplied DS records into delegation levels that have no parent DS.
	// This allows validation of zones whose DS hasn't been published yet.
	for i, level := range levels {
		if level.zone != "." && len(level.ds) == 0 {
			if zta := findZoneTrustAnchor(req, level.zone); len(zta) > 0 {
				levels[i].ds = convertZoneDS(level.zone, zta)
				dbg("validate: injected %d caller-supplied DS record(s) for %s at level %d", len(zta), level.zone, i)
			}
		}
	}

	for i, level := range levels {
		dbg("validate: level %d zone=%s ns=%s ds=%d", i, level.zone, level.ns.addr, len(level.ds))

		// A non-root zone with no DS in the parent is unsigned. If we've already
		// validated the parent zone (i > 0), the signed parent explicitly has no DS
		// for this child → insecure delegation (RFC 4035 §5.2). The root zone is
		// always the first level and always has ds=nil.
		if level.zone != "." && len(level.ds) == 0 {
			dbg("validate: zone %s has no DS in parent — unsigned, chain stops", level.zone)
			extraSteps = append(extraSteps, ResolutionStep{
				Nameserver:     level.ns.addr,
				NameserverName: level.ns.name,
				QName:          dns.Fqdn(level.zone),
				QType:          "DNSKEY",
				StepNote:       fmt.Sprintf("no DS record for %s in parent zone — unsigned delegation (insecure)", level.zone),
			})
			return "insecure", extraSteps
		}

		keyResp, step := fetchDNSKEYResponse(level.zone, level.ns)
		step.StepNote = fmt.Sprintf("Validating %s DNSKEY", level.zone)

		if keyResp == nil {
			dbg("validate: DNSKEY fetch failed for %s", level.zone)
			step.StepNote += " — fetch failed (indeterminate)"
			extraSteps = append(extraSteps, step)
			return "indeterminate", extraSteps
		}

		keys := extractDNSKEYs(keyResp)
		dbg("validate: fetched %d DNSKEY(s) for %s", len(keys), level.zone)
		if len(keys) == 0 {
			if len(level.ds) > 0 {
				// Parent signed a DS for this zone but the zone has no DNSKEY — BOGUS.
				step.StepNote += " — no DNSKEY records but parent DS exists (BOGUS)"
				extraSteps = append(extraSteps, step)
				return false, extraSteps
			}
			step.StepNote += " — no DNSKEY records returned (indeterminate)"
			extraSteps = append(extraSteps, step)
			return "indeterminate", extraSteps
		}
		if Debug {
			for _, k := range keys {
				dbg("validate:   DNSKEY tag=%d alg=%d flags=%d", k.KeyTag(), k.Algorithm, k.Flags)
			}
		}

		if level.zone == "." {
			// Root zone: establish trust via the mode selected in the request.
			switch req.TrustAnchorMode {
			case "iana":
				if len(req.TrustAnchors) == 0 {
					dbg("validate: no IANA trust anchors supplied")
					step.StepNote += " — no IANA trust anchors supplied by web server (indeterminate)"
					extraSteps = append(extraSteps, step)
					return "indeterminate", extraSteps
				}
				anchorDS := convertTrustAnchors(req.TrustAnchors)
				dbg("validate: checking root against %d IANA DS record(s)", len(anchorDS))
				if !anyKeyMatchesDS(keys, anchorDS) {
					dbg("validate: no root DNSKEY matches IANA trust anchor")
					step.StepNote += " — no root DNSKEY matches IANA DS trust anchor (indeterminate)"
					extraSteps = append(extraSteps, step)
					return "indeterminate", extraSteps
				}
				dbg("validate: IANA trust anchor matched")
				step.StepNote += " — IANA trust anchor matched"
			case "local":
				trusted, localStep := fetchLocalRootTrust()
				dbg("validate: local resolver AD bit: %v", trusted)
				if !trusted {
					localStep.StepNote += " — local resolver did not return AD=1 for root DNSKEY (indeterminate)"
					step.StepNote += " — root trust check failed"
					extraSteps = append(extraSteps, step)
					extraSteps = append(extraSteps, localStep)
					return "indeterminate", extraSteps
				}
				localStep.StepNote += " — local resolver returned AD=1, root DNSKEY trusted"
				extraSteps = append(extraSteps, localStep)
				step.StepNote += " — root trust established via local resolver"
			default:
				dbg("validate: no trust anchor mode set")
				step.StepNote += " — no trust anchor mode specified (indeterminate)"
				extraSteps = append(extraSteps, step)
				return "indeterminate", extraSteps
			}
		} else {
			dbg("validate: checking %d DNSKEY(s) against %d DS record(s) for %s", len(keys), len(level.ds), level.zone)
			if Debug {
				for _, ds := range level.ds {
					dbg("validate:   DS tag=%d alg=%d dtype=%d digest=%.16s…", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
				}
			}
			if !anyKeyMatchesDS(keys, level.ds) {
				dbg("validate: no DNSKEY matches DS for %s → BOGUS", level.zone)
				step.StepNote += " — DNSKEY does not match parent DS records (BOGUS)"
				extraSteps = append(extraSteps, step)
				return false, extraSteps
			}
			dbg("validate: DS match OK for %s", level.zone)
			step.StepNote += " — DS match OK"
		}

		if !verifyDNSKEYRRSig(keys, keyResp) {
			dbg("validate: DNSKEY self-sig failed for %s → BOGUS", level.zone)
			step.StepNote += ", DNSKEY self-signature failed (BOGUS)"
			extraSteps = append(extraSteps, step)
			return false, extraSteps
		}
		dbg("validate: DNSKEY self-sig OK for %s", level.zone)
		step.StepNote += ", self-sig OK"

		if i < len(levels)-1 && len(levels[i+1].ds) > 0 {
			dbg("validate: verifying DS RRSIG for child zone %s", levels[i+1].zone)
			keysForDS := keys
			if signer := dsRRSigSigner(level.resp); signer != "" && signer != level.zone {
				// The DS was signed by an intermediate zone not present in the referral
				// chain (e.g. uk. and co.uk. share nameservers so the uk. server returns
				// the junesta.co.uk. DS signed by co.uk.'s ZSK directly).
				dbg("validate: DS signer %q ≠ current zone %q — interpolating intermediate zone(s)", signer, level.zone)
				intKeys, intSteps, intOK := validateIntermediateZones(level.zone, signer, level.ns, keys)
				extraSteps = append(extraSteps, intSteps...)
				if !intOK {
					step.StepNote += fmt.Sprintf(", intermediate zone %s validation failed (BOGUS)", signer)
					extraSteps = append(extraSteps, step)
					return false, extraSteps
				}
				keysForDS = intKeys
				validatedKeys[signer] = intKeys
			}
			if !verifyDSRRSig(levels[i+1].ds, level.resp, keysForDS) {
				dbg("validate: DS RRSIG failed for child %s → BOGUS", levels[i+1].zone)
				step.StepNote += ", DS signature for child zone failed (BOGUS)"
				extraSteps = append(extraSteps, step)
				return false, extraSteps
			}
			dbg("validate: DS RRSIG OK for child %s", levels[i+1].zone)
			step.StepNote += ", child DS sig OK"
		}

		extraSteps = append(extraSteps, step)
		validatedKeys[level.zone] = keys
	}

	// Verify the answer RRSIGs against the final zone's validated key set.
	last := levels[len(levels)-1]
	keys := validatedKeys[last.zone]
	if len(keys) == 0 {
		dbg("validate: no validated keys for final zone %s", last.zone)
		return "indeterminate", extraSteps
	}

	// Some servers are authoritative for both a parent zone and a child zone and answer
	// child-zone queries directly (AA=1) without giving a referral first. In that case
	// parseDelegationChain never sees the zone boundary, the RRSIG SignerName will differ
	// from last.zone, and we must explicitly fetch the child zone's DS and DNSKEY.
	// For NODATA responses the answer section is empty; check the authority section too
	// (the SOA RRSIG there is signed by the child zone's ZSK).
	signerZone := last.zone
	for _, rr := range append(last.resp.Answer, last.resp.Ns...) {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if z := strings.ToLower(dns.Fqdn(sig.SignerName)); z != last.zone {
				signerZone = z
			}
			break
		}
	}
	dbg("validate: final answer zone=%s signer=%s", last.zone, signerZone)

	// RFC 4035 §5.3.1: RRSIG SignerName must be an ancestor (or equal) of the RRset
	// owner name. Verify this before spending network round-trips fetching DS/DNSKEY.
	if signerZone != last.zone {
		for _, rr := range last.resp.Answer {
			owner := strings.ToLower(dns.Fqdn(rr.Header().Name))
			if owner != signerZone && !strings.HasSuffix(owner, "."+signerZone) {
				dbg("validate: RRSIG SignerName %q is not ancestor of owner %q → BOGUS", signerZone, owner)
				verifyStep := ResolutionStep{
					Nameserver:     last.ns.addr,
					NameserverName: last.ns.name,
					QName:          dns.Fqdn(req.QName),
					QType:          "VERIFY",
					StepNote: fmt.Sprintf("RRSIG SignerName %q is not an ancestor of RRset owner %q (RFC 4035 §5.3.1) — BOGUS",
						signerZone, owner),
				}
				return false, append(extraSteps, verifyStep)
			}
		}
	}

	if signerZone != last.zone {
		dbg("validate: signer zone differs — fetching DS for %s from parent server %s", signerZone, last.ns.addr)
		dsResp, dsStep := fetchDSResponse(signerZone, last.ns)
		dsStep.StepNote = fmt.Sprintf("Fetching DS for %s (zone boundary not seen in referrals)", signerZone)
		extraSteps = append(extraSteps, dsStep)

		if dsResp == nil {
			dbg("validate: DS fetch failed for %s", signerZone)
			return "indeterminate", extraSteps
		}

		var childDS []*dns.DS
		for _, rr := range dsResp.Answer {
			if ds, ok := rr.(*dns.DS); ok {
				childDS = append(childDS, ds)
			}
		}
		dbg("validate: got %d DS record(s) for %s", len(childDS), signerZone)

		callerSuppliedDS := false
		if len(childDS) == 0 {
			if zta := findZoneTrustAnchor(req, signerZone); len(zta) > 0 {
				// Caller supplied DS records for this zone — use them as trust anchor.
				childDS = convertZoneDS(signerZone, zta)
				callerSuppliedDS = true
				dbg("validate: using %d caller-supplied DS record(s) for %s", len(childDS), signerZone)
				extraSteps[len(extraSteps)-1].StepNote += fmt.Sprintf(
					" — no DS in parent; using caller-supplied trust anchor (%d DS record(s))", len(childDS))
			} else if dsResp.Rcode == dns.RcodeSuccess {
				// NOERROR with no DS means the parent explicitly has no DS for this
				// zone — unsigned delegation (RFC 4035 §5.2).
				dbg("validate: NOERROR but no DS for %s → insecure", signerZone)
				extraSteps[len(extraSteps)-1].StepNote += " — no DS records in parent, unsigned delegation (insecure)"
				selfSteps, _ := attemptSelfVerification(signerZone, last)
				return "insecure", append(extraSteps, selfSteps...)
			} else {
				return "indeterminate", extraSteps
			}
		}

		if !callerSuppliedDS && !verifyDSRRSigInAnswer(dsResp.Answer, keys) {
			dbg("validate: DS RRSIG in answer failed for %s → BOGUS", signerZone)
			dsStep.StepNote += " — DS RRSIG failed (BOGUS)"
			return false, extraSteps
		}
		dbg("validate: DS RRSIG OK for %s", signerZone)
		dsStep.StepNote += " — DS sig OK"

		childKeyResp, childKeyStep := fetchDNSKEYResponse(signerZone, last.ns)
		childKeyStep.StepNote = fmt.Sprintf("Validating %s DNSKEY", signerZone)
		if childKeyResp == nil {
			dbg("validate: DNSKEY fetch failed for child zone %s", signerZone)
			childKeyStep.StepNote += " — fetch failed (indeterminate)"
			extraSteps = append(extraSteps, childKeyStep)
			return "indeterminate", extraSteps
		}
		childKeys := extractDNSKEYs(childKeyResp)
		dbg("validate: got %d DNSKEY(s) for child zone %s", len(childKeys), signerZone)
		if len(childKeys) == 0 {
			childKeyStep.StepNote += " — no DNSKEY returned (indeterminate)"
			extraSteps = append(extraSteps, childKeyStep)
			return "indeterminate", extraSteps
		}
		if !anyKeyMatchesDS(childKeys, childDS) {
			dbg("validate: child DNSKEY does not match DS for %s → BOGUS", signerZone)
			childKeyStep.StepNote += " — DNSKEY does not match DS (BOGUS)"
			extraSteps = append(extraSteps, childKeyStep)
			return false, extraSteps
		}
		childKeyStep.StepNote += " — DS match OK"
		if !verifyDNSKEYRRSig(childKeys, childKeyResp) {
			dbg("validate: child DNSKEY self-sig failed for %s → BOGUS", signerZone)
			childKeyStep.StepNote += ", DNSKEY self-signature failed (BOGUS)"
			extraSteps = append(extraSteps, childKeyStep)
			return false, extraSteps
		}
		dbg("validate: child DNSKEY self-sig OK for %s", signerZone)
		childKeyStep.StepNote += ", self-sig OK"
		extraSteps = append(extraSteps, childKeyStep)
		keys = childKeys
	}

	// NXDOMAIN proofs are in the authority section; answers are in the answer section.
	allRRs := append(last.resp.Answer, last.resp.Ns...)
	var rrsigs []*dns.RRSIG
	var rrsets []dns.RR
	for _, rr := range allRRs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, sig)
		} else {
			rrsets = append(rrsets, rr)
		}
	}
	dbg("validate: final answer has %d RRSIG(s) and %d non-RRSIG RR(s)", len(rrsigs), len(rrsets))

	verifyStepBase := ResolutionStep{
		Nameserver:     last.ns.addr,
		NameserverName: last.ns.name,
		QName:          dns.Fqdn(req.QName),
		QType:          "VERIFY",
	}

	if len(rrsigs) == 0 {
		dbg("validate: no RRSIGs in final answer → indeterminate")
		// RFC 8482: servers may refuse to answer ANY with a full signed response
		// (HINFO, NODATA with SOA, etc. — none include RRSIGs). The chain of trust
		// is intact but the response itself cannot be cryptographically verified.
		if dns.StringToType[strings.ToUpper(req.QType)] == dns.TypeANY &&
			last.resp.Rcode == dns.RcodeSuccess {
			verifyStep := verifyStepBase
			verifyStep.StepNote = "RFC 8482 minimal response to ANY — chain of trust verified, response not cryptographically provable (indeterminate)"
			verifyStep.ResponseText = fmt.Sprintf("; RFC 8482 minimal response to ANY query — indeterminate\n\n%s", last.resp.String())
			if b, packErr := last.resp.Pack(); packErr == nil {
				verifyStep.ResponseBytesHex = hex.EncodeToString(b)
			}
			return "indeterminate", append(extraSteps, verifyStep)
		}
		return "indeterminate", extraSteps
	}

	// Verify ALL RRSIGs — for NXDOMAIN/NODATA the authority section carries both a
	// SOA RRSIG and NSEC/NSEC3 RRSIG(s); the NSEC/NSEC3 record is what proves
	// non-existence or type-absence, so its signature must be checked independently.
	// Returning on the first success would skip those proofs entirely.
	type sigResult struct{ label string }
	var verified []sigResult
	for _, sig := range rrsigs {
		rrset := rrsetForSig(rrsets, sig)
		if len(rrset) == 0 {
			dbg("validate: RRSIG covers %s at %s but no matching RRs found", dns.TypeToString[sig.TypeCovered], sig.Hdr.Name)
			continue
		}
		sigOK := false
		for _, key := range keys {
			if key.KeyTag() == sig.KeyTag {
				err := verifySig(sig, key, rrset)
				dbg("validate: verify RRSIG type=%s name=%s keytag=%d → %v", dns.TypeToString[sig.TypeCovered], sig.Hdr.Name, sig.KeyTag, err)
				if err == nil {
					sigOK = true
					break
				}
			}
		}
		if !sigOK {
			dbg("validate: RRSIG(%s) at %s could not be verified → BOGUS", dns.TypeToString[sig.TypeCovered], sig.Hdr.Name)
			verifyStep := verifyStepBase
			verifyStep.StepNote = fmt.Sprintf("RRSIG(%s) at %s could not be verified — BOGUS", dns.TypeToString[sig.TypeCovered], sig.Hdr.Name)
			verifyStep.ResponseText = fmt.Sprintf("; RRSIG(%s) at %s could not be verified.\n; Result: BOGUS\n\n%s",
				dns.TypeToString[sig.TypeCovered], sig.Hdr.Name, last.resp.String())
			if b, packErr := last.resp.Pack(); packErr == nil {
				verifyStep.ResponseBytesHex = hex.EncodeToString(b)
			}
			return false, append(extraSteps, verifyStep)
		}
		verified = append(verified, sigResult{label: fmt.Sprintf("RRSIG(%s)", dns.TypeToString[sig.TypeCovered])})
	}

	if len(verified) == 0 {
		dbg("validate: no RRSIGs had matching records → indeterminate")
		return "indeterminate", extraSteps
	}

	// Build a compact summary: deduplicate repeated type names with a count prefix.
	countOf := map[string]int{}
	var typeOrder []string
	for _, v := range verified {
		if countOf[v.label] == 0 {
			typeOrder = append(typeOrder, v.label)
		}
		countOf[v.label]++
	}
	var summaryParts []string
	for _, label := range typeOrder {
		if countOf[label] == 1 {
			summaryParts = append(summaryParts, label)
		} else {
			summaryParts = append(summaryParts, fmt.Sprintf("%d×%s", countOf[label], label))
		}
	}

	// Semantic denial-of-existence proof (RFC 4035 §5.4, RFC 5155 §8, RFC 6840).
	// Cryptographic RRSIG verification above proves the records are authentic;
	// this step proves their contents actually demonstrate non-existence.
	// ANY NODATA (NOERROR) is excluded: servers may put records in the authority
	// section or use RFC 8482 minimal responses — NSEC/NSEC3 proof is not required.
	qtype := dns.StringToType[strings.ToUpper(req.QType)]
	isDenial := last.resp.Rcode == dns.RcodeNameError ||
		(last.resp.Rcode == dns.RcodeSuccess && len(last.resp.Answer) == 0 &&
			qtype != dns.TypeANY)
	isWildcard := !isDenial && isWildcardAnswer(last.resp)

	var denialNote string
	if isDenial || isWildcard {
		nsecs, nsec3s := extractDenialRRs(last.resp.Ns)
		var denialOK bool

		switch {
		case isWildcard:
			denialOK, denialNote = verifyWildcardNextCloser(dns.Fqdn(req.QName), last.resp)
		case len(nsec3s) > 0:
			denialOK, denialNote = verifyNSEC3Denial(dns.Fqdn(req.QName), qtype, last.resp.Rcode, nsec3s)
		case len(nsecs) > 0:
			denialOK, denialNote = verifyNSECDenial(dns.Fqdn(req.QName), qtype, last.resp.Rcode, nsecs)
		default:
			denialOK = false
			denialNote = "no NSEC or NSEC3 records in authority section"
		}
		dbg("validate: denial proof: ok=%v note=%s", denialOK, denialNote)

		if strings.HasPrefix(denialNote, "indeterminate:") {
			verifyStep := verifyStepBase
			msg := strings.TrimPrefix(denialNote, "indeterminate:")
			verifyStep.StepNote = msg
			verifyStep.ResponseText = fmt.Sprintf("; %s\n\n%s", msg, last.resp.String())
			if b, packErr := last.resp.Pack(); packErr == nil {
				verifyStep.ResponseBytesHex = hex.EncodeToString(b)
			}
			return "indeterminate", append(extraSteps, verifyStep)
		}
		if !denialOK {
			verifyStep := verifyStepBase
			verifyStep.StepNote = denialNote + " — BOGUS"
			verifyStep.ResponseText = fmt.Sprintf("; %s\n; Result: BOGUS\n\n%s", denialNote, last.resp.String())
			if b, packErr := last.resp.Pack(); packErr == nil {
				verifyStep.ResponseBytesHex = hex.EncodeToString(b)
			}
			return false, append(extraSteps, verifyStep)
		}
	}

	context := "final answer"
	if last.resp.Rcode == dns.RcodeNameError {
		context = "NXDOMAIN proof"
	} else if len(last.resp.Answer) == 0 && qtype == dns.TypeANY {
		context = "ANY response (signed records in authority section)"
	} else if len(last.resp.Answer) == 0 {
		context = "NODATA proof"
	}
	note := fmt.Sprintf("%s verified for %s", strings.Join(summaryParts, ", "), context)
	if denialNote != "" {
		note += "; " + denialNote
	}
	note += " — SECURE"
	dbg("validate: %s", note)
	verifyStep := verifyStepBase
	verifyStep.StepNote = note
	verifyStep.ResponseText = fmt.Sprintf("; %s\n\n%s", note, last.resp.String())
	if b, packErr := last.resp.Pack(); packErr == nil {
		verifyStep.ResponseBytesHex = hex.EncodeToString(b)
	}
	return true, append(extraSteps, verifyStep)
}

// convertTrustAnchors converts the request's TrustAnchorDS list to dns.DS records
// so they can be compared against fetched DNSKEY sets via key.ToDS().
func convertTrustAnchors(anchors []TrustAnchorDS) []*dns.DS {
	var out []*dns.DS
	for _, a := range anchors {
		out = append(out, &dns.DS{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     a.KeyTag,
			Algorithm:  a.Algorithm,
			DigestType: a.DigestType,
			Digest:     strings.ToUpper(a.Digest),
		})
	}
	return out
}

// findZoneTrustAnchor returns the caller-supplied DS records for zone, if any.
// Zone comparison is case-insensitive and FQDN-normalised.
func findZoneTrustAnchor(req *QueryRequest, zone string) []TrustAnchorDS {
	target := strings.ToLower(dns.Fqdn(zone))
	for _, zta := range req.ZoneTrustAnchors {
		if strings.ToLower(dns.Fqdn(zta.Zone)) == target {
			return zta.DS
		}
	}
	return nil
}

// convertZoneDS converts a slice of TrustAnchorDS to *dns.DS for zone (not ".").
func convertZoneDS(zone string, anchors []TrustAnchorDS) []*dns.DS {
	var out []*dns.DS
	for _, a := range anchors {
		out = append(out, &dns.DS{
			Hdr:        dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     a.KeyTag,
			Algorithm:  a.Algorithm,
			DigestType: a.DigestType,
			Digest:     strings.ToUpper(a.Digest),
		})
	}
	return out
}

// attemptSelfVerification fetches the DNSKEY for zone and verifies RRSIGs in
// last.resp against those keys, without requiring a DS in the parent. Used to
// show whether a zone is self-consistently signed before DS is published.
// Returns extra steps and a human-readable note.
func attemptSelfVerification(zone string, last zoneLevel) ([]ResolutionStep, string) {
	keyResp, keyStep := fetchDNSKEYResponse(zone, last.ns)
	keyStep.StepNote = fmt.Sprintf("Self-verification: fetching %s DNSKEY (no parent DS — not a chain-of-trust check)", zone)
	if keyResp == nil {
		keyStep.StepNote += " — fetch failed"
		return []ResolutionStep{keyStep}, "DNSKEY fetch failed — cannot self-verify"
	}
	keys := extractDNSKEYs(keyResp)
	if len(keys) == 0 {
		keyStep.StepNote += " — no DNSKEY records returned"
		return []ResolutionStep{keyStep}, "no DNSKEY records — cannot self-verify"
	}
	// DNSKEY self-sig check — check crypto and temporal validity separately so
	// we can distinguish "expired signature" from "wrong key / bad signature".
	var keyRRs []dns.RR
	var dnskeySigs []*dns.RRSIG
	for _, rr := range keyResp.Answer {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDNSKEY {
				dnskeySigs = append(dnskeySigs, v)
			}
		case *dns.DNSKEY:
			keyRRs = append(keyRRs, v)
		}
	}
	if len(dnskeySigs) > 0 {
		selfSigOK := false
		selfSigExpiredOnly := false
		for _, sig := range dnskeySigs {
			for _, key := range keys {
				if key.KeyTag() == sig.KeyTag {
					cryptoOK := sig.Verify(key, keyRRs) == nil
					timeOK := sig.ValidityPeriod(time.Now())
					if cryptoOK && timeOK {
						selfSigOK = true
					} else if cryptoOK && !timeOK {
						selfSigExpiredOnly = true
					}
				}
			}
		}
		if !selfSigOK {
			if selfSigExpiredOnly {
				keyStep.StepNote += " — DNSKEY self-sig cryptographically OK but RRSIG expired (zone needs re-signing)"
				return []ResolutionStep{keyStep}, "DNSKEY self-sig expired (crypto OK — zone needs re-signing)"
			}
			keyStep.StepNote += " — DNSKEY self-sig FAILED (signing error)"
			return []ResolutionStep{keyStep}, "DNSKEY self-sig failed (zone signing error?)"
		}
	}

	allRRs := append(last.resp.Answer, last.resp.Ns...)
	var rrsets []dns.RR
	var rrsigs []*dns.RRSIG
	for _, rr := range allRRs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, sig)
		} else {
			rrsets = append(rrsets, rr)
		}
	}

	var verified, expired, failed []string
	for _, sig := range rrsigs {
		rrset := rrsetForSig(rrsets, sig)
		if len(rrset) == 0 {
			continue
		}
		label := fmt.Sprintf("RRSIG(%s)", dns.TypeToString[sig.TypeCovered])
		sigOK := false
		sigExpiredOnly := false
		for _, key := range keys {
			if key.KeyTag() == sig.KeyTag {
				cryptoOK := sig.Verify(key, rrset) == nil
				timeOK := sig.ValidityPeriod(time.Now())
				if cryptoOK && timeOK {
					sigOK = true
				} else if cryptoOK && !timeOK {
					sigExpiredOnly = true
				}
			}
		}
		if sigOK {
			verified = append(verified, label)
		} else if sigExpiredOnly {
			expired = append(expired, label)
		} else {
			failed = append(failed, label)
		}
	}

	if len(verified) == 0 && len(expired) == 0 && len(failed) == 0 {
		keyStep.StepNote += " — no RRSIGs in final response to verify"
		return []ResolutionStep{keyStep}, "no RRSIGs to verify (zone may not be signing)"
	}
	if len(failed) > 0 {
		parts := failed
		if len(expired) > 0 {
			parts = append(parts, expired...)
		}
		keyStep.StepNote += fmt.Sprintf(" — self-verification FAILED: %s", strings.Join(parts, ", "))
		return []ResolutionStep{keyStep}, fmt.Sprintf("self-verification failed for %s (zone signing error?)", strings.Join(failed, ", "))
	}
	if len(expired) > 0 && len(verified) == 0 {
		keyStep.StepNote += fmt.Sprintf(" — RRSIG(s) expired (crypto OK): %s (zone needs re-signing)", strings.Join(expired, ", "))
		return []ResolutionStep{keyStep}, fmt.Sprintf("self-verified crypto OK but RRSIG(s) expired: %s — zone needs re-signing", strings.Join(expired, ", "))
	}
	note := strings.Join(verified, ", ")
	if len(expired) > 0 {
		note += fmt.Sprintf("; expired (crypto OK): %s", strings.Join(expired, ", "))
	}
	keyStep.StepNote += fmt.Sprintf(" — self-verified: %s (signatures correct, but no parent DS — insecure)", note)
	return []ResolutionStep{keyStep}, fmt.Sprintf("self-verified %s OK (signatures correct, no parent DS)", note)
}

// fetchLocalRootTrust queries the local resolver (127.0.0.1:53) for the root DNSKEY
// set with RD=1/DO=1 and returns whether the response carries the AD (Authenticated
// Data) bit, indicating the local resolver has validated the root against its own
// trust anchor. Also returns a ResolutionStep for chain display.
func fetchLocalRootTrust() (bool, ResolutionStep) {
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeDNSKEY)
	m.RecursionDesired = true
	m.AuthenticatedData = true
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(1232)
	o.SetDo()
	m.Extra = append(m.Extra, o)

	queryBytes, _ := m.Pack()
	step := ResolutionStep{
		Nameserver:     "127.0.0.1:53",
		NameserverName: "localhost (trust anchor check)",
		QName:          ".",
		QType:          "DNSKEY",
		QueryBytesHex:  hex.EncodeToString(queryBytes),
	}

	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	start := time.Now()
	resp, _, err := c.Exchange(m, "127.0.0.1:53")
	step.DNSQueryMS = time.Since(start).Seconds() * 1000

	if err != nil {
		step.ResponseText = fmt.Sprintf("error: %v", err)
		return false, step
	}

	responseBytes, _ := resp.Pack()
	step.ResponseText = resp.String()
	step.ResponseBytesHex = hex.EncodeToString(responseBytes)
	return resp.AuthenticatedData, step
}

// anyKeyMatchesDS returns true if any key hashes to one of the DS records.
func anyKeyMatchesDS(keys []*dns.DNSKEY, dsRecs []*dns.DS) bool {
	for _, key := range keys {
		for _, ds := range dsRecs {
			computed := key.ToDS(ds.DigestType)
			if computed != nil && strings.EqualFold(computed.Digest, ds.Digest) {
				return true
			}
		}
	}
	return false
}

// verifySig checks both the cryptographic signature and the temporal validity
// window (RFC 4034 §3.1.5). miekg/dns Verify() is documented as "only the
// cryptographic test"; ValidityPeriod() must be called separately.
func verifySig(sig *dns.RRSIG, key *dns.DNSKEY, rrset []dns.RR) error {
	if !sig.ValidityPeriod(time.Now()) {
		return fmt.Errorf("RRSIG for %s expired or not yet valid (inception=%d expiration=%d)",
			dns.TypeToString[sig.TypeCovered], sig.Inception, sig.Expiration)
	}
	return sig.Verify(key, rrset)
}

// verifyDNSKEYRRSig returns true if the DNSKEY RRset in keyResp has a valid
// self-signature from the zone's KSK. Returns true when no RRSIG is present
// (the DS check already proved the key is trusted).
func verifyDNSKEYRRSig(keys []*dns.DNSKEY, keyResp *dns.Msg) bool {
	var rrsigs []*dns.RRSIG
	var keyRRs []dns.RR
	for _, rr := range keyResp.Answer {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDNSKEY {
				rrsigs = append(rrsigs, v)
			}
		case *dns.DNSKEY:
			keyRRs = append(keyRRs, v)
		}
	}
	if len(rrsigs) == 0 {
		return true
	}
	for _, sig := range rrsigs {
		for _, key := range keys {
			if key.KeyTag() == sig.KeyTag {
				if err := verifySig(sig, key, keyRRs); err == nil {
					return true
				}
			}
		}
	}
	return false
}

// verifyDSRRSig returns true if the DS records in the parent's authority section
// have a valid RRSIG from one of the parent's validated keys.
func verifyDSRRSig(dsRecs []*dns.DS, parentResp *dns.Msg, parentKeys []*dns.DNSKEY) bool {
	var rrsigs []*dns.RRSIG
	var dsRRs []dns.RR
	for _, rr := range parentResp.Ns {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDS {
				rrsigs = append(rrsigs, v)
			}
		case *dns.DS:
			dsRRs = append(dsRRs, v)
		}
	}
	if len(rrsigs) == 0 {
		return true
	}
	for _, sig := range rrsigs {
		for _, key := range parentKeys {
			if key.KeyTag() == sig.KeyTag {
				if err := verifySig(sig, key, dsRRs); err == nil {
					return true
				}
			}
		}
	}
	return false
}

// dsRRSigSigner returns the lowercased FQDN SignerName of the first RRSIG(DS) found
// in the authority section of resp, or "" if none is present.
func dsRRSigSigner(resp *dns.Msg) string {
	for _, rr := range resp.Ns {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDS {
			return strings.ToLower(dns.Fqdn(sig.SignerName))
		}
	}
	return ""
}

// validateIntermediateZones validates all zone levels strictly between parentZone
// (exclusive) and signerZone (inclusive) by querying ns, which serves all of them
// (the shared-nameserver case, e.g. uk. and co.uk. on the same servers).
// It returns the validated DNSKEY set for signerZone, any extra steps, and success.
func validateIntermediateZones(parentZone, signerZone string, ns namedAddr, parentKeys []*dns.DNSKEY) ([]*dns.DNSKEY, []ResolutionStep, bool) {
	// Build the ordered list of zones to traverse from just below parentZone to signerZone.
	var zones []string
	for z := signerZone; z != parentZone; {
		zones = append([]string{z}, zones...)
		labels := dns.SplitDomainName(z)
		if len(labels) <= 1 {
			break
		}
		z = dns.Fqdn(strings.Join(labels[1:], "."))
	}

	var extraSteps []ResolutionStep
	currentKeys := parentKeys

	for _, zone := range zones {
		dsResp, dsStep := fetchDSResponse(zone, ns)
		dsStep.StepNote = fmt.Sprintf("Fetching DS for intermediate zone %s (zone boundary inferred from RRSIG signer)", zone)
		extraSteps = append(extraSteps, dsStep)

		if dsResp == nil {
			dsStep.StepNote += " — fetch failed"
			return nil, extraSteps, false
		}

		var ds []*dns.DS
		for _, rr := range dsResp.Answer {
			if d, ok := rr.(*dns.DS); ok {
				ds = append(ds, d)
			}
		}
		if len(ds) == 0 {
			dsStep.StepNote += " — no DS records found"
			return nil, extraSteps, false
		}
		if !verifyDSRRSigInAnswer(dsResp.Answer, currentKeys) {
			dsStep.StepNote += " — DS RRSIG failed (BOGUS)"
			return nil, extraSteps, false
		}
		dsStep.StepNote += " — DS sig OK"

		keyResp, keyStep := fetchDNSKEYResponse(zone, ns)
		keyStep.StepNote = fmt.Sprintf("Validating intermediate zone %s DNSKEY", zone)
		extraSteps = append(extraSteps, keyStep)

		if keyResp == nil {
			keyStep.StepNote += " — fetch failed"
			return nil, extraSteps, false
		}
		keys := extractDNSKEYs(keyResp)
		if len(keys) == 0 {
			keyStep.StepNote += " — no DNSKEY records"
			return nil, extraSteps, false
		}
		if !anyKeyMatchesDS(keys, ds) {
			keyStep.StepNote += " — DNSKEY does not match DS (BOGUS)"
			return nil, extraSteps, false
		}
		if !verifyDNSKEYRRSig(keys, keyResp) {
			keyStep.StepNote += " — DNSKEY self-signature failed (BOGUS)"
			return nil, extraSteps, false
		}
		keyStep.StepNote += " — DS match OK, self-sig OK"
		currentKeys = keys
	}

	return currentKeys, extraSteps, true
}

// exchangeWithTCPFallback sends msg to addr over UDP. If the response has TC=1,
// it retries over TCP and returns the complete response plus a note for the UI.
func exchangeWithTCPFallback(msg *dns.Msg, addr string) (*dns.Msg, string, error) {
	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		return nil, "", err
	}
	if !resp.Truncated {
		return resp, "", nil
	}
	tcp := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
	r, _, tcpErr := tcp.Exchange(msg, addr)
	if tcpErr != nil {
		// TCP failed too — return the truncated UDP response and note the attempt.
		return resp, fmt.Sprintf("UDP response truncated (TC=1); TCP retry failed: %v", tcpErr), nil
	}
	return r, "UDP response truncated (TC=1) — retried over TCP", nil
}

// fetchDSResponse queries ns for the DS RRset at zone (used when an authoritative
// server answers child-zone queries directly without a referral, so we never saw
// the DS records in a referral authority section).
func fetchDSResponse(zone string, ns namedAddr) (*dns.Msg, ResolutionStep) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeDS)
	m.RecursionDesired = false
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(1232)
	o.SetDo()
	m.Extra = append(m.Extra, o)

	queryBytes, _ := m.Pack()
	step := ResolutionStep{
		Nameserver:     ns.addr,
		NameserverName: ns.name,
		QName:          dns.Fqdn(zone),
		QType:          "DS",
		QueryBytesHex:  hex.EncodeToString(queryBytes),
	}

	start := time.Now()
	resp, tcNote, err := exchangeWithTCPFallback(m, ns.addr)
	step.DNSQueryMS = time.Since(start).Seconds() * 1000

	if err != nil {
		step.ResponseText = fmt.Sprintf("error: %v", err)
		return nil, step
	}

	responseBytes, _ := resp.Pack()
	step.ResponseText = resp.String()
	if tcNote != "" {
		step.ResponseText = "; " + tcNote + "\n" + step.ResponseText
	}
	step.ResponseBytesHex = hex.EncodeToString(responseBytes)
	return resp, step
}

// verifyDSRRSigInAnswer verifies that the DS RRset in an answer section (from an
// explicit DS query) is signed by one of the parent zone's validated keys. This
// differs from verifyDSRRSig which looks in the authority section of a referral.
func verifyDSRRSigInAnswer(answer []dns.RR, parentKeys []*dns.DNSKEY) bool {
	var rrsigs []*dns.RRSIG
	var dsRRs []dns.RR
	for _, rr := range answer {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDS {
				rrsigs = append(rrsigs, v)
			}
		case *dns.DS:
			dsRRs = append(dsRRs, v)
		}
	}
	if len(rrsigs) == 0 {
		return true
	}
	for _, sig := range rrsigs {
		for _, key := range parentKeys {
			if key.KeyTag() == sig.KeyTag {
				dbg("verifyDSRRSigInAnswer: trying key tag=%d for DS RRSIG", sig.KeyTag)
				if err := verifySig(sig, key, dsRRs); err == nil {
					return true
				}
			}
		}
	}
	return false
}

// fetchDNSKEYResponse queries ns for the DNSKEY RRset at zone, returning the full
// DNS response and a ResolutionStep for the chain.
func fetchDNSKEYResponse(zone string, ns namedAddr) (*dns.Msg, ResolutionStep) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeDNSKEY)
	m.RecursionDesired = false
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(1232)
	o.SetDo()
	m.Extra = append(m.Extra, o)

	queryBytes, _ := m.Pack()
	step := ResolutionStep{
		Nameserver:     ns.addr,
		NameserverName: ns.name,
		QName:          dns.Fqdn(zone),
		QType:          "DNSKEY",
		QueryBytesHex:  hex.EncodeToString(queryBytes),
	}

	start := time.Now()
	resp, tcNote, err := exchangeWithTCPFallback(m, ns.addr)
	step.DNSQueryMS = time.Since(start).Seconds() * 1000

	if err != nil {
		step.ResponseText = fmt.Sprintf("error: %v", err)
		return nil, step
	}

	responseBytes, _ := resp.Pack()
	step.ResponseText = resp.String()
	if tcNote != "" {
		step.ResponseText = "; " + tcNote + "\n" + step.ResponseText
	}
	step.ResponseBytesHex = hex.EncodeToString(responseBytes)
	return resp, step
}

func extractDNSKEYs(resp *dns.Msg) []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	for _, rr := range append(resp.Answer, resp.Extra...) {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys
}

func rrsetForType(rrs []dns.RR, t uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			out = append(out, rr)
		}
	}
	return out
}

// rrsetForSig returns the RRs that a given RRSIG covers: same type AND same owner
// name. This matters for NSEC3 (and NSEC) in NXDOMAIN authority sections where
// multiple records of the same type appear at different hashed owner names — each
// is a distinct RRset and must be verified with only its own records.
func rrsetForSig(rrs []dns.RR, sig *dns.RRSIG) []dns.RR {
	want := strings.ToLower(dns.Fqdn(sig.Hdr.Name))
	var out []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == sig.TypeCovered &&
			strings.ToLower(rr.Header().Name) == want {
			out = append(out, rr)
		}
	}
	return out
}

// ── Denial of existence verification ─────────────────────────────────────────
// RFC 4035 §5.4 (NSEC), RFC 5155 §8 (NSEC3), RFC 6840 (clarifications).

func extractDenialRRs(ns []dns.RR) ([]*dns.NSEC, []*dns.NSEC3) {
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, rr := range ns {
		switch v := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, v)
		case *dns.NSEC3:
			nsec3s = append(nsec3s, v)
		}
	}
	return nsecs, nsec3s
}

func typeInNSECBitmap(n *dns.NSEC, t uint16) bool {
	for _, ty := range n.TypeBitMap {
		if ty == t {
			return true
		}
	}
	return false
}

func typeInNSEC3Bitmap(n *dns.NSEC3, t uint16) bool {
	for _, ty := range n.TypeBitMap {
		if ty == t {
			return true
		}
	}
	return false
}

// nsecIsAncestorDelegation detects parent-zone NSEC records that must not be used
// for non-existence proofs in child zones (RFC 6840 §4.1).
func nsecIsAncestorDelegation(n *dns.NSEC) bool {
	return typeInNSECBitmap(n, dns.TypeNS) && !typeInNSECBitmap(n, dns.TypeSOA)
}

func nsec3IsAncestorDelegation(n *dns.NSEC3) bool {
	return typeInNSEC3Bitmap(n, dns.TypeNS) && !typeInNSEC3Bitmap(n, dns.TypeSOA)
}

// canonicalNameLess implements RFC 4034 §6.1 canonical DNS name ordering.
// Labels are compared right-to-left (root side first).
func canonicalNameLess(a, b string) bool {
	aLabels := dns.SplitDomainName(strings.ToLower(a))
	bLabels := dns.SplitDomainName(strings.ToLower(b))
	aLen, bLen := len(aLabels), len(bLabels)
	for i := 1; i <= aLen && i <= bLen; i++ {
		al, bl := aLabels[aLen-i], bLabels[bLen-i]
		if al < bl {
			return true
		}
		if al > bl {
			return false
		}
	}
	return aLen < bLen // shorter name sorts first (root < com < example.com)
}

// nsecCoversName returns true if name falls strictly between the NSEC owner name
// and its NextDomain in canonical DNS name order, handling zone wrap-around.
func nsecCoversName(n *dns.NSEC, name string) bool {
	owner := strings.ToLower(dns.Fqdn(n.Hdr.Name))
	next := strings.ToLower(dns.Fqdn(n.NextDomain))
	name = strings.ToLower(dns.Fqdn(name))
	if canonicalNameLess(owner, next) {
		// Normal case: owner < name < next
		return canonicalNameLess(owner, name) && canonicalNameLess(name, next)
	}
	// Wrap-around (last NSEC in zone): owner > next
	return canonicalNameLess(owner, name) || canonicalNameLess(name, next)
}

// findNSEC3ClosestEncloser implements the closest encloser proof algorithm
// (RFC 5155 §8.3): strip labels from qname until we find an ancestor whose hash
// matches an NSEC3 owner AND the next-closer name is covered by another NSEC3.
func findNSEC3ClosestEncloser(qname string, nsec3s []*dns.NSEC3) (ce, nextCloser string, found bool) {
	candidate := dns.Fqdn(qname)
	for {
		nextCloser = candidate
		labels := dns.SplitDomainName(candidate)
		if len(labels) <= 1 {
			break
		}
		candidate = dns.Fqdn(strings.Join(labels[1:], "."))
		for _, n := range nsec3s {
			if !n.Match(candidate) {
				continue
			}
			// Ancestor delegation guard (RFC 6840 §4.1) and DNAME guard.
			if nsec3IsAncestorDelegation(n) || typeInNSEC3Bitmap(n, dns.TypeDNAME) {
				continue
			}
			for _, m := range nsec3s {
				if m.Cover(nextCloser) {
					return candidate, nextCloser, true
				}
			}
		}
	}
	return "", "", false
}

// verifyNSECDenial validates NSEC-based denial of existence per RFC 4035 §5.4
// and RFC 6840. Returns (ok, note); a note prefixed with "indeterminate:" signals
// an indeterminate outcome rather than BOGUS.
func verifyNSECDenial(qname string, qtype uint16, rcode int, nsecs []*dns.NSEC) (bool, string) {
	qname = dns.Fqdn(qname)

	if rcode == dns.RcodeNameError {
		// NXDOMAIN: need an NSEC covering qname AND an NSEC proving no wildcard matches.
		var covering *dns.NSEC
		for _, n := range nsecs {
			if nsecCoversName(n, qname) {
				covering = n
				break
			}
		}
		if covering == nil {
			return false, "no NSEC covers " + qname
		}

		// Closest encloser: longest ancestor of qname that is an NSEC owner.
		closestEncloser := "."
		candidate := qname
	ceSearch:
		for {
			labels := dns.SplitDomainName(candidate)
			if len(labels) == 0 {
				break
			}
			candidate = dns.Fqdn(strings.Join(labels[1:], "."))
			for _, n := range nsecs {
				if strings.EqualFold(dns.Fqdn(n.Hdr.Name), candidate) {
					closestEncloser = candidate
					break ceSearch
				}
			}
		}

		wildcard := "*." + closestEncloser
		wildcardProven := false
		for _, n := range nsecs {
			// RFC 6840 §4.1: NSECs at zone cuts (NS=1, SOA=0) are from the parent zone
			// and MUST NOT be used to prove non-existence in the child zone.
			if nsecIsAncestorDelegation(n) {
				continue
			}
			if nsecCoversName(n, wildcard) {
				wildcardProven = true
				break
			}
			// Wildcard exists but without the queried type (RFC 4035 §5.4).
			if strings.EqualFold(dns.Fqdn(n.Hdr.Name), wildcard) && !typeInNSECBitmap(n, qtype) {
				wildcardProven = true
				break
			}
		}
		if !wildcardProven {
			return false, "no NSEC proves wildcard non-existence at " + wildcard
		}
		return true, fmt.Sprintf("NSEC proves NXDOMAIN: %s covered, wildcard %s absent", qname, wildcard)
	}

	// NODATA: need NSEC at exactly qname with qtype absent.
	for _, n := range nsecs {
		if !strings.EqualFold(dns.Fqdn(n.Hdr.Name), qname) {
			continue
		}
		if nsecIsAncestorDelegation(n) {
			return false, "NSEC at " + qname + " is ancestor delegation, cannot prove NODATA"
		}
		if typeInNSECBitmap(n, qtype) {
			return false, fmt.Sprintf("NSEC bitmap at %s includes %s — type exists", qname, dns.TypeToString[qtype])
		}
		// RFC 6840 §4.3: CNAME absence must also be checked.
		if typeInNSECBitmap(n, dns.TypeCNAME) {
			return false, "NSEC bitmap at " + qname + " includes CNAME — CNAME should have been followed"
		}
		return true, fmt.Sprintf("NSEC proves NODATA: %s absent from %s bitmap", dns.TypeToString[qtype], qname)
	}

	// Wildcard NODATA (RFC 4035 §5.4): no real name exists at qname, but a wildcard
	// ancestor matches it; the wildcard's NSEC bitmap lacks the queried type.
	// Detect CE by stripping labels until *.CE is an NSEC owner with type absent.
	candidate := qname
	for {
		labels := dns.SplitDomainName(candidate)
		if len(labels) <= 1 {
			break
		}
		candidate = dns.Fqdn(strings.Join(labels[1:], "."))
		wildcard := "*." + candidate
		for _, n := range nsecs {
			if !strings.EqualFold(dns.Fqdn(n.Hdr.Name), wildcard) {
				continue
			}
			if nsecIsAncestorDelegation(n) || typeInNSECBitmap(n, dns.TypeCNAME) {
				break
			}
			if typeInNSECBitmap(n, qtype) {
				return false, fmt.Sprintf("NSEC at wildcard %s has %s in bitmap — type exists", wildcard, dns.TypeToString[qtype])
			}
			// Wildcard NSEC found with type absent; now verify qname itself is covered
			// by a separate NSEC (proving the real name doesn't exist).
			for _, m := range nsecs {
				if nsecCoversName(m, qname) {
					return true, fmt.Sprintf("NSEC proves wildcard NODATA: %s matched by %s, %s absent from wildcard bitmap", qname, wildcard, dns.TypeToString[qtype])
				}
			}
			return false, fmt.Sprintf("wildcard NSEC at %s found but no NSEC covers %s", wildcard, qname)
		}
	}

	return false, "no NSEC record found at " + qname
}

// verifyNSEC3Denial validates NSEC3-based denial of existence per RFC 5155 §8
// and RFC 6840.
func verifyNSEC3Denial(qname string, qtype uint16, rcode int, nsec3s []*dns.NSEC3) (bool, string) {
	qname = dns.Fqdn(qname)

	// §8.2: all NSEC3 must share the same algorithm, iterations, and salt.
	ref := nsec3s[0]
	if ref.Hash != 1 {
		return false, "indeterminate: unknown NSEC3 hash algorithm"
	}
	var valid []*dns.NSEC3
	for _, n := range nsec3s {
		if n.Flags > 1 {
			dbg("verifyNSEC3Denial: discarding NSEC3 with unknown flags=0x%x", n.Flags)
			continue
		}
		if n.Hash != ref.Hash || n.Iterations != ref.Iterations || n.Salt != ref.Salt {
			return false, "indeterminate: NSEC3 records in response have inconsistent parameters"
		}
		valid = append(valid, n)
	}
	if len(valid) == 0 {
		return false, "no valid NSEC3 records after parameter filtering"
	}

	if rcode == dns.RcodeNameError {
		// §8.4: closest encloser proof + wildcard coverage.
		ce, _, found := findNSEC3ClosestEncloser(qname, valid)
		if !found {
			return false, "no NSEC3 closest encloser proof found for " + qname
		}
		wildcard := "*." + ce
		wildcardCovered := false
		for _, n := range valid {
			if n.Cover(wildcard) {
				wildcardCovered = true
				break
			}
		}
		if !wildcardCovered {
			return false, "no NSEC3 covers wildcard *." + ce
		}
		return true, fmt.Sprintf("NSEC3 closest encloser proof: ce=%s, next-closer covered, wildcard covered", ce)
	}

	// NODATA: §8.5 (qtype ≠ DS) or §8.6 (qtype == DS).
	for _, n := range valid {
		if n.Match(qname) {
			if nsec3IsAncestorDelegation(n) {
				return false, "matching NSEC3 for " + qname + " is ancestor delegation, cannot prove NODATA"
			}
			if typeInNSEC3Bitmap(n, qtype) {
				return false, fmt.Sprintf("NSEC3 bitmap for %s includes %s — type exists", qname, dns.TypeToString[qtype])
			}
			// RFC 6840 §4.3: CNAME absence check.
			if typeInNSEC3Bitmap(n, dns.TypeCNAME) {
				return false, "NSEC3 bitmap for " + qname + " includes CNAME — CNAME should have been followed"
			}
			if len(n.TypeBitMap) == 0 {
				return true, fmt.Sprintf("NSEC3 proves NODATA: %s is an empty non-terminal", qname)
			}
			return true, fmt.Sprintf("NSEC3 proves NODATA: %s absent from %s bitmap", dns.TypeToString[qtype], qname)
		}
	}

	// §8.6: no matching NSEC3; if qtype == DS, check for opt-out covering.
	if qtype == dns.TypeDS {
		ce, nextCloser, found := findNSEC3ClosestEncloser(qname, valid)
		if found {
			for _, n := range valid {
				if n.Cover(nextCloser) {
					if n.Flags&0x01 != 0 {
						return false, fmt.Sprintf("indeterminate: opt-out covers %s, delegation may be insecure (closest encloser: %s)", qname, ce)
					}
					return false, fmt.Sprintf("NSEC3 covers next-closer for %s but opt-out bit not set", qname)
				}
			}
		}
		return false, "no NSEC3 matches " + qname + " for DS NODATA (no opt-out proof found)"
	}

	// §8.7: wildcard NODATA — closest encloser proof + matching NSEC3 at *.CE with type absent.
	if ce, _, found := findNSEC3ClosestEncloser(qname, valid); found {
		wildcard := "*." + ce
		for _, n := range valid {
			if !n.Match(wildcard) {
				continue
			}
			if nsec3IsAncestorDelegation(n) || typeInNSEC3Bitmap(n, dns.TypeCNAME) {
				break
			}
			if typeInNSEC3Bitmap(n, qtype) {
				return false, fmt.Sprintf("NSEC3 at wildcard *.%s has %s in bitmap — type exists", ce, dns.TypeToString[qtype])
			}
			return true, fmt.Sprintf("NSEC3 proves wildcard NODATA: %s matched by *.%s, %s absent from wildcard NSEC3 bitmap", qname, ce, dns.TypeToString[qtype])
		}
	}

	return false, "no NSEC3 matches " + qname
}

// isWildcardAnswer returns true if any answer RRSIG has Labels < owner label count,
// indicating wildcard expansion (RFC 4034 §3.1.3, RFC 6840 §6).
func isWildcardAnswer(resp *dns.Msg) bool {
	for _, rr := range resp.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if int(sig.Labels) < dns.CountLabel(sig.Hdr.Name) {
				return true
			}
		}
	}
	return false
}

// verifyWildcardNextCloser verifies the next-closer NSEC/NSEC3 proof for wildcard-
// synthesized answers per RFC 5155 §8.8 and RFC 6840 §6.
func verifyWildcardNextCloser(qname string, resp *dns.Msg) (bool, string) {
	qname = dns.Fqdn(qname)
	minLabels := 255
	for _, rr := range resp.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && int(sig.Labels) < minLabels {
			minLabels = int(sig.Labels)
		}
	}
	if minLabels == 255 {
		return false, "wildcard answer has no RRSIG to determine Labels count"
	}
	allLabels := dns.SplitDomainName(qname)
	nLabels := len(allLabels)
	targetLabels := minLabels + 1
	if targetLabels >= nLabels {
		return true, "wildcard answer: next-closer is qname itself"
	}
	nextCloser := dns.Fqdn(strings.Join(allLabels[nLabels-targetLabels:], "."))

	nsecs, nsec3s := extractDenialRRs(resp.Ns)
	if len(nsec3s) > 0 {
		for _, n := range nsec3s {
			if n.Flags <= 1 && n.Cover(nextCloser) {
				return true, fmt.Sprintf("wildcard answer verified: NSEC3 covers next-closer %s", nextCloser)
			}
		}
		return false, fmt.Sprintf("wildcard answer: no NSEC3 covers next-closer %s", nextCloser)
	}
	if len(nsecs) > 0 {
		for _, n := range nsecs {
			if nsecCoversName(n, nextCloser) {
				return true, fmt.Sprintf("wildcard answer verified: NSEC covers next-closer %s", nextCloser)
			}
		}
		return false, fmt.Sprintf("wildcard answer: no NSEC covers next-closer %s", nextCloser)
	}
	return false, "wildcard answer: no NSEC or NSEC3 in authority for next-closer proof"
}

func isCNAME(answers []dns.RR, target string, qtype uint16) bool {
	if qtype == dns.TypeCNAME {
		return false
	}
	for _, rr := range answers {
		if rr.Header().Rrtype == dns.TypeCNAME &&
			strings.EqualFold(rr.Header().Name, target) {
			return true
		}
	}
	return false
}

func extractCNAME(answers []dns.RR, target string) string {
	for _, rr := range answers {
		if cn, ok := rr.(*dns.CNAME); ok &&
			strings.EqualFold(cn.Hdr.Name, target) {
			return cn.Target
		}
	}
	return ""
}

func extractGlue(extra []dns.RR) map[string]string {
	m := make(map[string]string)
	for _, rr := range extra {
		switch v := rr.(type) {
		case *dns.A:
			m[strings.ToLower(v.Hdr.Name)] = v.A.String()
		case *dns.AAAA:
			if _, exists := m[strings.ToLower(v.Hdr.Name)]; !exists {
				m[strings.ToLower(v.Hdr.Name)] = v.AAAA.String()
			}
		}
	}
	return m
}

// ipPort formats a bare IP address into an "addr:port" string suitable for
// net.Dial. IPv6 addresses are wrapped in brackets per RFC 3986.
func ipPort(ip, port string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + port
	}
	return ip + ":" + port
}

func extractNSAddresses(ns []dns.RR, glue map[string]string) []namedAddr {
	var addrs []namedAddr
	seen := map[string]bool{}
	for _, rr := range ns {
		if nsrr, ok := rr.(*dns.NS); ok {
			hostname := nsrr.Ns
			key := strings.ToLower(hostname)
			if ip, ok := glue[key]; ok && !seen[ip] {
				addrs = append(addrs, namedAddr{addr: ipPort(ip, "53"), name: hostname})
				seen[ip] = true
			}
		}
	}
	return shuffledNamed(addrs)
}

func extractFirstNSName(ns []dns.RR) string {
	for _, rr := range ns {
		if nsrr, ok := rr.(*dns.NS); ok {
			return nsrr.Ns
		}
	}
	return ""
}

// resolveNSAddr resolves an NS hostname to A addresses, preserving the name.
func resolveNSAddr(name string, doDNSSEC bool) []namedAddr {
	sub := &QueryRequest{
		QName: name,
		QType: "A",
		Mode:  "recursive",
		Flags: QueryFlags{RD: false, DO: doDNSSEC},
	}
	resp := execRecursive(sub)
	if resp.Error != "" || len(resp.ResolutionChain) == 0 {
		return nil
	}
	last := resp.ResolutionChain[len(resp.ResolutionChain)-1]
	b, err := hex.DecodeString(last.ResponseBytesHex)
	if err != nil {
		return nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(b); err != nil {
		return nil
	}
	var addrs []namedAddr
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			addrs = append(addrs, namedAddr{addr: ipPort(v.A.String(), "53"), name: name})
		case *dns.AAAA:
			addrs = append(addrs, namedAddr{addr: ipPort(v.AAAA.String(), "53"), name: name})
		}
	}
	return addrs
}

func shuffledNamed(s []namedAddr) []namedAddr {
	out := make([]namedAddr, len(s))
	copy(out, s)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}
