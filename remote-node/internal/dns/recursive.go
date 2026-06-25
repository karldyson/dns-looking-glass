package dns

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"dns-looking-glass/internal/dns/edns"

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

	// Pre-build all user-requested EDNS options (NSID, ZONEVERSION, etc.) so they
	// are included in every iterative query.  Build errors are surfaced early.
	reqEdnsOpts, err := edns.Build(req.EDNS.Options)
	if err != nil {
		return &QueryResponse{Error: fmt.Sprintf("edns: %v", err)}
	}
	nsidRequested := false
	for _, opt := range req.EDNS.Options {
		if code, ok := opt["code"].(float64); ok && uint16(code) == dns.EDNS0NSID {
			nsidRequested = true
			break
		}
	}

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

		if req.Flags.DO || len(reqEdnsOpts) > 0 {
			o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			o.SetUDPSize(1232)
			if req.Flags.DO {
				o.SetDo()
			}
			o.Option = append(o.Option, reqEdnsOpts...)
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
		if nsidRequested {
			stepEntry.NSID = extractNSIDFromMsg(resp)
		}
		if len(reqEdnsOpts) > 0 {
			stepEntry.ZoneVersion = extractZoneVersionFromMsg(resp)
			stepEntry.ResponseText = cleanZoneVersionText(stepEntry.ResponseText, stepEntry.ZoneVersion)
		}
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
					for i := range validationSteps {
						validationSteps[i].ValidationStep = true
					}
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
				// Need to resolve NS names — try all listed NS names in case some
				// are unresolvable (only the first was tried previously).
				nsNames := extractAllNSNames(resp.Ns)
				nsResolved := false
				for _, nsName := range nsNames {
					dbg("step %d: resolving NS name %s", step, nsName)
					nsAddrs := resolveNSAddr(nsName, req.Flags.DO)
					if len(nsAddrs) > 0 {
						nameservers = nsAddrs
						nsResolved = true
						break
					}
				}
				if nsResolved {
					continue
				}
				if len(nsNames) > 0 {
					// Delegation received but none of the NS names could be resolved
					// to an address. Add a synthetic step so the chain shows why
					// resolution stopped here rather than silently ending.
					failMsg := fmt.Sprintf("delegation to %s received from %s — NS: %s — "+
						"could not resolve any delegated nameserver to an address "+
						"(NXDOMAIN, NODATA, or unreachable); delegation cannot be followed",
						target, cur.name, strings.Join(nsNames, ", "))
					dbg("step %d: %s", step, failMsg)
					chain = append(chain, ResolutionStep{
						Nameserver:     nsNames[0] + ":53",
						NameserverName: strings.Join(nsNames, ", "),
						QName:          target,
						QType:          dns.TypeToString[currentType],
						ResponseText:   failMsg,
						StepNote:       "delegation cannot be followed — NS name(s) unresolvable",
					})
				}
			}
			dbg("step %d: NODATA or unresolvable", step)
			// NODATA or unresolvable.
			if req.Flags.DO && req.Flags.Validate {
				var validationSteps []ResolutionStep
				dnssecValid, validationSteps = validateChainOfTrust(chain, req)
				for i := range validationSteps {
					validationSteps[i].ValidationStep = true
				}
				chain = append(chain, validationSteps...)
			}
			return buildRecursiveResponse(chain, dnssecValid)

		case dns.RcodeNameError: // NXDOMAIN
			dbg("step %d: NXDOMAIN", step)
			if req.Flags.DO && req.Flags.Validate {
				var validationSteps []ResolutionStep
				dnssecValid, validationSteps = validateChainOfTrust(chain, req)
				for i := range validationSteps {
					validationSteps[i].ValidationStep = true
				}
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
	var lastResponse, lastNS, lastNSID string
	var lastZV map[string]interface{}
	var totalMS float64
	// Use the last resolution step (not a validation step) for the top-level response,
	// so the "answer" box always shows the DNS answer regardless of whether validation ran.
	for i := len(chain) - 1; i >= 0; i-- {
		if !chain[i].ValidationStep {
			lastResponse = chain[i].ResponseText
			lastNS = chain[i].Nameserver
			lastNSID = chain[i].NSID
			lastZV = chain[i].ZoneVersion
			break
		}
	}
	for _, step := range chain {
		totalMS += step.DNSQueryMS
	}
	return &QueryResponse{
		Nameserver:      lastNS,
		ResponseText:    lastResponse,
		NSID:            lastNSID,
		ZoneVersion:     lastZV,
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

// callerDSEntry holds caller-supplied DS records for a zone and whether they
// should replace (override=true) or supplement (override=false) the parent DS.
type callerDSEntry struct {
	ds      []*dns.DS
	replace bool
}

// parseDelegationChain converts the resolution step list into a sequence of zone
// levels. Returns the levels and the index in chain of the last step consumed
// (or -1 if no usable step was found). The caller can use chain[lastIdx+1:] to
// obtain the remaining steps after the terminal answer — useful for CNAME chains
// that cross zone boundaries, where the remainder is the CNAME target's resolution.
func parseDelegationChain(chain []ResolutionStep) (levels []zoneLevel, lastIdx int) {
	lastIdx = -1
	var pendingDS []*dns.DS
	currentZone := "."

	for i, step := range chain {
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
		lastIdx = i

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

	// If the last referral named a child zone but we never received a usable response
	// from its servers (SERVFAIL, unreachable, or synthetic diagnostic step with no
	// wire bytes), add a stub level for that zone with the pending DS from the parent
	// referral. The resolver is parent-centric: DNSSEC status is determined by the
	// parent's DS (or proven absence thereof), not by reaching the child's servers.
	//
	// For unsigned delegations (pendingDS == nil) this stub causes validateChainOfTrust
	// to return "insecure" instead of misidentifying the parent referral as the final
	// answer and returning "indeterminate".
	//
	// For signed delegations where the child is unreachable, the stub carries a non-nil
	// pendingDS but an empty ns.addr; the subsequent DNSKEY fetch fails → "indeterminate",
	// which is the correct result when the signed zone cannot be reached.
	//
	// TODO: a future option to switch to child-centric mode (retry resolution using the
	// child zone's own NS records when they differ from the parent delegation) would
	// complement this; track in GitHub issue.
	if len(levels) > 0 && currentZone != "." && currentZone != levels[len(levels)-1].zone {
		levels = append(levels, zoneLevel{zone: currentZone, ds: pendingDS})
	}

	return levels, lastIdx
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

	reqEdnsOpts, _ := edns.Build(req.EDNS.Options) // error already checked in execRecursive
	nsidRequested := false
	for _, opt := range req.EDNS.Options {
		if code, ok := opt["code"].(float64); ok && uint16(code) == dns.EDNS0NSID {
			nsidRequested = true
			break
		}
	}

	levels, lastChainIdx := parseDelegationChain(chain)
	if len(levels) == 0 {
		dbg("validate: no delegation levels parsed")
		return "indeterminate", nil
	}
	dbg("validate: parsed %d delegation level(s)", len(levels))

	var extraSteps []ResolutionStep
	validatedKeys := make(map[string][]*dns.DNSKEY) // zone → trusted key set

	// Build a lookup map of caller-supplied DS records per zone. This supports two
	// modes: replace (override=true) swaps the parent DS entirely (DS RRSIG check
	// skipped); add (override=false, default) supplements the parent DS so both the
	// old and new keys are accepted during DNSKEY matching.
	callerDSMap := map[string]callerDSEntry{}
	for _, zta := range req.ZoneTrustAnchors {
		zone := strings.ToLower(dns.Fqdn(zta.Zone))
		callerDSMap[zone] = callerDSEntry{ds: convertZoneDS(zta.Zone, zta.DS), replace: zta.Override}
	}

	// Inject caller-supplied DS into delegation levels. For replace mode or zones
	// with no parent DS, overwrite level.ds. Add mode with existing parent DS is
	// handled inline in the main loop so the original DS is preserved for RRSIG checks.
	for i, level := range levels {
		if level.zone == "." {
			continue
		}
		zone := strings.ToLower(dns.Fqdn(level.zone))
		entry, ok := callerDSMap[zone]
		if !ok {
			continue
		}
		if entry.replace || len(level.ds) == 0 {
			levels[i].ds = entry.ds
			dbg("validate: injected %d caller-supplied DS for %s (replace=%v)", len(entry.ds), level.zone, entry.replace)
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

		keyResp, step := fetchDNSKEYResponse(level.zone, level.ns, nsidRequested, reqEdnsOpts)
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
				dbg("validate: no DNSKEY for %s but parent DS exists → BOGUS", level.zone)
				step.StepNote += " — no DNSKEY records but parent DS exists (BOGUS)"
				extraSteps = append(extraSteps, step)
				return false, extraSteps
			}
			dbg("validate: no DNSKEY for %s (no DS either) → indeterminate", level.zone)
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
				if ok, anchorTags := anyKeyMatchesDS(keys, anchorDS); !ok {
					dbg("validate: no root DNSKEY matches IANA trust anchor")
					step.StepNote += " — no root DNSKEY matches IANA DS trust anchor (indeterminate)"
					extraSteps = append(extraSteps, step)
					return "indeterminate", extraSteps
				} else {
					dbg("validate: IANA trust anchor matched")
					step.StepNote += fmt.Sprintf(" — IANA trust anchor matched, %s", formatKeyTags(anchorTags))
				}
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
			// For add mode, supplement the parent DS with caller-supplied DS for key matching.
			// level.ds already reflects replace mode from the pre-injection loop above.
			dsForMatch := level.ds
			levelZone := strings.ToLower(dns.Fqdn(level.zone))
			callerEntry, hasCallerDS := callerDSMap[levelZone]
			if hasCallerDS && !callerEntry.replace && len(level.ds) > 0 {
				dsForMatch = append(append([]*dns.DS{}, level.ds...), callerEntry.ds...)
				dbg("validate: add mode — supplementing %d parent DS with %d caller-supplied DS for %s", len(level.ds), len(callerEntry.ds), level.zone)
			}
			dbg("validate: checking %d DNSKEY(s) against %d DS record(s) for %s", len(keys), len(dsForMatch), level.zone)
			if Debug {
				for _, ds := range dsForMatch {
					dbg("validate:   DS tag=%d alg=%d dtype=%d digest=%.16s…", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
				}
			}
			if ok, matchTags := anyKeyMatchesDS(keys, dsForMatch); !ok {
				dbg("validate: no DNSKEY matches DS for %s → BOGUS", level.zone)
				step.StepNote += " — DNSKEY does not match parent DS records (BOGUS)"
				extraSteps = append(extraSteps, step)
				return false, extraSteps
			} else {
				dbg("validate: DS match OK for %s", level.zone)
				tagStr := formatKeyTags(matchTags)
				if hasCallerDS && !callerEntry.replace && len(level.ds) > 0 {
					step.StepNote += fmt.Sprintf(" — DS match OK, %s (+ %d caller-supplied DS, add mode)", tagStr, len(callerEntry.ds))
				} else if hasCallerDS && callerEntry.replace {
					step.StepNote += fmt.Sprintf(" — DS match OK, %s (caller-supplied override)", tagStr)
				} else {
					step.StepNote += fmt.Sprintf(" — DS match OK, %s", tagStr)
				}
			}
		}

		if err, sigTag := verifyDNSKEYRRSig(keys, keyResp); err != nil {
			if err == dns.ErrAlg {
				algName := dnsKeyAlgName(keys)
				dbg("validate: DNSKEY self-sig for %s uses unsupported algorithm %s — treating as insecure (RFC 4033 §5)", level.zone, algName)
				step.StepNote += fmt.Sprintf(", DNSKEY self-signature uses unsupported algorithm %s — insecure (RFC 4033 §5)", algName)
				extraSteps = append(extraSteps, step)
				return "insecure", extraSteps
			}
			dbg("validate: DNSKEY self-sig failed for %s → BOGUS", level.zone)
			step.StepNote += ", DNSKEY self-signature failed (BOGUS)"
			extraSteps = append(extraSteps, step)
			return false, extraSteps
		} else {
			dbg("validate: DNSKEY self-sig OK for %s", level.zone)
			if sigTag != 0 {
				step.StepNote += fmt.Sprintf(", self-sig OK (keytag=%d)", sigTag)
			} else {
				step.StepNote += ", self-sig OK"
			}
		}

		if i < len(levels)-1 && len(levels[i+1].ds) > 0 {
			childZoneKey := strings.ToLower(dns.Fqdn(levels[i+1].zone))
			childCallerEntry, childHasCallerDS := callerDSMap[childZoneKey]
			if childHasCallerDS && childCallerEntry.replace {
				// DS was replaced by caller — no parent RRSIG exists for it.
				dbg("validate: child zone %s has caller-supplied DS override — skipping DS RRSIG check", levels[i+1].zone)
				step.StepNote += " — child DS is caller-supplied override (RRSIG check skipped)"
			} else {
				dbg("validate: verifying DS RRSIG for child zone %s", levels[i+1].zone)
				keysForDS := keys
				if signer := dsRRSigSigner(level.resp); signer != "" && signer != level.zone {
					// The DS was signed by an intermediate zone not present in the referral
					// chain (e.g. uk. and co.uk. share nameservers so the uk. server returns
					// the junesta.co.uk. DS signed by co.uk.'s ZSK directly).
					dbg("validate: DS signer %q ≠ current zone %q — interpolating intermediate zone(s)", signer, level.zone)
					intKeys, intSteps, intOK, _ := validateIntermediateZones(level.zone, signer, level.ns, keys, nsidRequested, reqEdnsOpts)
					extraSteps = append(extraSteps, intSteps...)
					if !intOK {
						dbg("validate: intermediate zone %s failed → BOGUS", signer)
						step.StepNote += fmt.Sprintf(", intermediate zone %s validation failed (BOGUS)", signer)
						extraSteps = append(extraSteps, step)
						return false, extraSteps
					}
					keysForDS = intKeys
					validatedKeys[signer] = intKeys
				}
				if ok, dsSigTag := verifyDSRRSig(levels[i+1].ds, level.resp, keysForDS); !ok {
					dbg("validate: DS RRSIG failed for child %s → BOGUS", levels[i+1].zone)
					step.StepNote += ", DS signature for child zone failed (BOGUS)"
					extraSteps = append(extraSteps, step)
					return false, extraSteps
				} else {
					dbg("validate: DS RRSIG OK for child %s", levels[i+1].zone)
					if dsSigTag != 0 {
						step.StepNote += fmt.Sprintf(", child DS sig OK (keytag=%d)", dsSigTag)
					} else {
						step.StepNote += ", child DS sig OK"
					}
				}
			}
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
	foundRRSIG := false
	for _, rr := range append(last.resp.Answer, last.resp.Ns...) {
		if sig, ok := rr.(*dns.RRSIG); ok {
			foundRRSIG = true
			if z := strings.ToLower(dns.Fqdn(sig.SignerName)); z != last.zone {
				signerZone = z
			}
			break
		}
	}

	// Fallback 1: SOA owner. When the RRSIG scan found no child zone boundary
	// (no RRSIGs at all, or all RRSIGs are signed by last.zone), look for a SOA
	// whose owner name is a subdomain of last.zone. A SOA owner is the zone apex;
	// finding one here means the server answered directly for an unsigned child
	// without a referral. Covers SOA queries (SOA in answer) and NODATA responses
	// (SOA in authority).
	if signerZone == last.zone {
		qnFqdn := strings.ToLower(dns.Fqdn(req.QName))
		if strings.HasSuffix(qnFqdn, "."+last.zone) {
			for _, rr := range append(last.resp.Answer, last.resp.Ns...) {
				if soa, ok := rr.(*dns.SOA); ok {
					if z := strings.ToLower(dns.Fqdn(soa.Hdr.Name)); z != last.zone {
						signerZone = z
						dbg("validate: child zone %s detected via SOA owner (no RRSIGs — unsigned child?)", signerZone)
						break
					}
				}
			}
		}
	}

	// Fallback 2: qname-derived child zone. When no RRSIG and no SOA revealed a
	// zone boundary, the response may be a positive answer (e.g. TXT, A) from an
	// unsigned child zone served by the parent's shared nameserver — a case where
	// neither RRSIGs nor a SOA appear in the response. Derive the child zone as
	// the immediate delegation below last.zone on the path to the qname.
	//
	// This fallback is only applied when foundRRSIG=false. If an RRSIG exists but
	// its SignerName equals last.zone, the response genuinely came from last.zone;
	// applying the qname heuristic in that case would incorrectly redirect DS/DNSKEY
	// fetches for a legitimately signed name in the parent zone.
	if signerZone == last.zone && !foundRRSIG {
		qnFqdn := strings.ToLower(strings.TrimSuffix(dns.Fqdn(req.QName), "."))
		qnLabels := dns.SplitDomainName(qnFqdn)
		zoneLabels := dns.SplitDomainName(strings.TrimSuffix(last.zone, "."))
		if len(qnLabels) > len(zoneLabels) {
			// qnLabels[childIdx:] gives the labels of the immediate child zone
			// (one label deeper than last.zone on the path to the qname).
			childIdx := len(qnLabels) - len(zoneLabels) - 1
			childZone := dns.Fqdn(strings.Join(qnLabels[childIdx:], "."))
			if childZone != last.zone {
				signerZone = childZone
				dbg("validate: child zone %s inferred from qname (no RRSIG, no SOA — unsigned child?)", signerZone)
			}
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

	// signerParentInsecure is set when the parent of signerZone is itself insecure
	// (no DS in its parent) but the caller supplied a DS override. Per RFC 4033 §5
	// the zone remains insecure regardless; we continue validation to show whether
	// the supplied DS would work, then downgrade the result to "insecure".
	signerParentInsecure := false

	if signerZone != last.zone {
		dbg("validate: signer zone differs — fetching DS for %s from parent server %s", signerZone, last.ns.addr)
		dsResp, dsStep := fetchDSResponse(signerZone, last.ns, nsidRequested, reqEdnsOpts)
		dsStep.StepNote = fmt.Sprintf("Fetching DS for %s (zone boundary not seen in referrals)", signerZone)
		extraSteps = append(extraSteps, dsStep)
		dsStepIdx := len(extraSteps) - 1

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

		signerZoneNorm := strings.ToLower(dns.Fqdn(signerZone))
		callerSuppliedDS := false
		dsForChildMatch := childDS // default: use whatever was fetched from parent

		if entry, ok := callerDSMap[signerZoneNorm]; ok && entry.replace {
			// Replace mode: use caller-supplied DS regardless of what parent returns.
			// The parent's DS RRSIG is skipped because it doesn't cover our new DS.
			dsForChildMatch = entry.ds
			callerSuppliedDS = true
			dbg("validate: using %d caller-supplied DS for %s (replace mode)", len(entry.ds), signerZone)
			extraSteps[len(extraSteps)-1].StepNote += fmt.Sprintf(
				" — caller-supplied DS override (%d record(s)) replaces parent; RRSIG check skipped", len(entry.ds))
		} else if len(childDS) == 0 {
			if entry, ok := callerDSMap[signerZoneNorm]; ok {
				// No parent DS at all — use caller-supplied (add and replace behave the same).
				dsForChildMatch = entry.ds
				callerSuppliedDS = true
				dbg("validate: using %d caller-supplied DS for %s (no parent DS)", len(entry.ds), signerZone)
				extraSteps[len(extraSteps)-1].StepNote += fmt.Sprintf(
					" — no DS in parent; using caller-supplied trust anchor (%d DS record(s))", len(entry.ds))
			} else if dsResp.Rcode == dns.RcodeSuccess || dsResp.Rcode == dns.RcodeNameError {
				// NOERROR + no DS  — parent has no DS for this child; either the
				//   delegation is unsigned (insecure) or no delegation exists (bogus).
				// NXDOMAIN          — parent says the name doesn't exist at all;
				//   if authenticated by NSEC/NSEC3 this is definitively bogus.
				//
				// In both cases, check the authority section for NSEC/NSEC3 denial
				// records.  A verified record lets us distinguish:
				//   • NOERROR: NS in bitmap → real unsigned delegation (insecure)
				//              NS absent    → no delegation (bogus)
				//   • NXDOMAIN: name provably absent from parent  → bogus
				// If no denial records can be verified we fall through to the
				// appropriate default for each rcode.
				dsNSECs, dsNSEC3s := extractDenialRRs(dsResp.Ns)
				if len(dsNSEC3s) > 0 || len(dsNSECs) > 0 {
					// Collect denial RRs and their RRSIGs as generic RR slices for verifySig.
					var denialRRs []dns.RR
					var denialSigs []*dns.RRSIG
					for _, rr := range dsResp.Ns {
						switch v := rr.(type) {
						case *dns.NSEC3:
							denialRRs = append(denialRRs, v)
						case *dns.NSEC:
							denialRRs = append(denialRRs, v)
						case *dns.RRSIG:
							if v.TypeCovered == dns.TypeNSEC3 || v.TypeCovered == dns.TypeNSEC {
								denialSigs = append(denialSigs, v)
							}
						}
					}
					// Verify at least one NSEC/NSEC3 RRSIG using whichever zone's keys signed
					// it. The signing zone may differ from last.zone: when a server is
					// authoritative for multiple zones at different depths (e.g. nsec3.uk.
					// and nsec.nsec3.uk. share nameservers), it can answer a DS fetch for
					// a grandchild with an NXDOMAIN whose denial records are signed by an
					// intermediate zone's ZSK, not by last.zone's ZSK. Using the RRSIG
					// SignerName to drive key selection is the correct generic approach.
					tryVerifyDenial := func(keysForSig []*dns.DNSKEY) bool {
						for _, sig := range denialSigs {
							rrset := rrsetForSig(denialRRs, sig)
							if len(rrset) == 0 {
								continue
							}
							for _, key := range keysForSig {
								if key.KeyTag() == sig.KeyTag {
									if verifySig(sig, key, rrset) == nil {
										return true
									}
								}
							}
						}
						return false
					}
					anyVerified := tryVerifyDenial(keys)
					if !anyVerified && len(denialSigs) > 0 {
						// keys didn't work — check whether the RRSIG SignerName points to an
						// intermediate zone that was skipped. Validate that zone's chain from
						// last.zone and re-try with its keys.
						var denialSigner string
						for _, sig := range denialSigs {
							if sn := strings.ToLower(dns.Fqdn(sig.SignerName)); sn != last.zone {
								denialSigner = sn
								break
							}
						}
						if denialSigner != "" {
							dbg("validate: denial RRSIG SignerName %q ≠ last.zone %q — validating intermediate zone", denialSigner, last.zone)
							dsStepHeld := extraSteps[dsStepIdx]
							extraSteps = extraSteps[:dsStepIdx]
							intKeys, intSteps, intOK, intInsecure := validateIntermediateZones(last.zone, denialSigner, last.ns, keys, nsidRequested, reqEdnsOpts)
							extraSteps = append(extraSteps, intSteps...)
							extraSteps = append(extraSteps, dsStepHeld)
							dsStepIdx = len(extraSteps) - 1
							if intOK && !intInsecure {
								anyVerified = tryVerifyDenial(intKeys)
							}
						}
					}
					if anyVerified {
						if dsResp.Rcode == dns.RcodeNameError {
							// Authenticated NXDOMAIN: the name doesn't exist in the parent
							// at all — no delegation is possible.
							dbg("validate: parent NSEC/NSEC3 proves NXDOMAIN for %s → BOGUS", signerZone)
							extraSteps[len(extraSteps)-1].StepNote += fmt.Sprintf(
								" — parent NSEC/NSEC3 proves %s does not exist; zone not in secure hierarchy — BOGUS", signerZone)
							return false, extraSteps
						}
						// NOERROR: check whether the parent has an NS record at the child zone name.
						// nameProven is true when an NSEC3/NSEC exactly covers the zone name
						// (the name EXISTS in the parent's zone data). nameHasNS tracks whether
						// that exact record also has the NS bit set.
						//
						// When nameProven=false the denial RRSIGs verified but no exact NSEC3/NSEC
						// matched the name — this happens in NSEC3 opt-out zones where unsigned
						// delegations are not represented in the NSEC3 chain. In that case the
						// absence of NS cannot be concluded; fall through to "insecure".
						nameHasNS := false
						nameProven := false
						for _, n3 := range dsNSEC3s {
							if n3.Match(signerZone) {
								nameProven = true
								nameHasNS = typeInNSEC3Bitmap(n3, dns.TypeNS)
								break
							}
						}
						if !nameProven {
							for _, n := range dsNSECs {
								if strings.EqualFold(dns.Fqdn(n.Hdr.Name), dns.Fqdn(signerZone)) {
									nameProven = true
									nameHasNS = typeInNSECBitmap(n, dns.TypeNS)
									break
								}
							}
						}
						if nameProven && !nameHasNS {
							// Parent's denial records prove the name exists without NS records —
							// no valid delegation. Any zone "served" by the shared nameserver
							// is outside the secure hierarchy.
							dbg("validate: parent denial records show no NS delegation for %s → BOGUS", signerZone)
							extraSteps[len(extraSteps)-1].StepNote += fmt.Sprintf(
								" — parent NSEC3/NSEC proves no NS delegation for %s; zone not in secure hierarchy — BOGUS", signerZone)
							return false, extraSteps
						}
						dbg("validate: parent denial records confirm NS delegation exists for %s, no DS → insecure", signerZone)
					}
				}
				if dsResp.Rcode == dns.RcodeNameError {
					// Unverified NXDOMAIN: we can't authenticate the parent's claim.
					dbg("validate: NXDOMAIN for DS of %s but denial records unverified → indeterminate", signerZone)
					extraSteps[len(extraSteps)-1].StepNote += " — parent returned NXDOMAIN for DS but NSEC/NSEC3 proof unverifiable (indeterminate)"
					return "indeterminate", extraSteps
				}
				dbg("validate: NOERROR but no DS for %s → insecure", signerZone)
				extraSteps[len(extraSteps)-1].StepNote += " — no DS records in parent, unsigned delegation (insecure)"
				selfSteps, _ := attemptSelfVerification(signerZone, last, nsidRequested, reqEdnsOpts)
				return "insecure", append(extraSteps, selfSteps...)
			} else {
				dbg("validate: DS response for %s has unexpected rcode %d → indeterminate", signerZone, dsResp.Rcode)
				return "indeterminate", extraSteps
			}
		} else if entry, ok := callerDSMap[signerZoneNorm]; ok && !entry.replace {
			// Add mode: parent DS fetched successfully — supplement it with caller DS.
			// The parent DS RRSIG is still verified (it covers the original DS set only).
			dsForChildMatch = append(append([]*dns.DS{}, childDS...), entry.ds...)
			dbg("validate: supplementing %d parent DS with %d caller-supplied DS for %s (add mode)", len(childDS), len(entry.ds), signerZone)
			extraSteps[len(extraSteps)-1].StepNote += fmt.Sprintf(
				" — + %d caller-supplied DS (add mode, RRSIG covers parent DS only)", len(entry.ds))
		}

		// The DS RRSIG may be signed by an intermediate zone that was skipped because the
		// server answered AA=1 for the child zone directly without giving intermediate
		// referrals (e.g. ns.junesta.uk. serves nsec3.uk., alg-8.nsec3.uk., and
		// ds-alg-2.alg-8.nsec3.uk. and jumps straight to the deepest zone). In that case
		// the DS RRSIG signer won't match last.zone and we need to validate the intermediate
		// zone chain before we can verify the DS signature.
		keysForDS := keys
		dsRRSIGFound := false
		for _, rr := range dsResp.Answer {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDS {
				dsRRSIGFound = true
				dsSigner := strings.ToLower(dns.Fqdn(sig.SignerName))
				if dsSigner != last.zone {
					dbg("validate: DS signer %q ≠ last zone %q — interpolating intermediate zone(s)", dsSigner, last.zone)
					intKeys, intSteps, intOK, intInsecure := validateIntermediateZones(last.zone, dsSigner, last.ns, keys, nsidRequested, reqEdnsOpts)
					extraSteps = append(extraSteps, intSteps...)
					if !intOK {
						if intInsecure {
							dbg("validate: intermediate zone %s is insecure — insecure", dsSigner)
							extraSteps[dsStepIdx].StepNote += fmt.Sprintf(" — intermediate zone %s is insecure", dsSigner)
							selfSteps, _ := attemptSelfVerification(signerZone, last, nsidRequested, reqEdnsOpts)
							return "insecure", append(extraSteps, selfSteps...)
						}
						dbg("validate: intermediate zone %s failed → BOGUS", dsSigner)
						extraSteps[dsStepIdx].StepNote += fmt.Sprintf(" — intermediate zone %s validation failed (BOGUS)", dsSigner)
						return false, extraSteps
					}
					keysForDS = intKeys
				}
				break
			}
		}

		// When the DS has no RRSIG, the absence of a signature alone does not determine
		// whether the delegation is insecure or bogus — a faulty signed zone could also
		// omit the RRSIG. The correct check is whether the intermediate zones between
		// last.zone and signerZone each have a DS record in their parent. A missing DS
		// means an unsigned delegation (insecure); a present DS whose chain fails is bogus.
		// When the parent returned a DS record but it has no RRSIG, check whether the
		// intermediate parent zone is itself insecure (RFC 4033 §5: a break in the chain
		// anywhere makes descendants insecure). This check runs regardless of callerSuppliedDS.
		// Note: len(childDS)==0 (no DS at all) is handled above and reaches here only when
		// callerSuppliedDS=true — in that case the caller is legitimately simulating DS
		// publication in a secure-but-delegating parent, so we skip the no-RRSIG check.
		if len(childDS) > 0 && !dsRRSIGFound {
			signerParent := dns.Fqdn(strings.Join(dns.SplitDomainName(signerZone)[1:], "."))
			if signerParent != last.zone {
				dbg("validate: no RRSIG on DS for %s; checking if intermediate zone %s is signed", signerZone, signerParent)

				// Annotate dsStep to explain why we're checking the parent, then reorder:
				// present the intermediate zone check (evidence) before the DS step (conclusion)
				// so the UI shows steps in logical order — the proof precedes the verdict.
				extraSteps[dsStepIdx].StepNote += " — DS has no RRSIG; checking whether parent zone is signed"
				dsStep := extraSteps[dsStepIdx]
				extraSteps = extraSteps[:dsStepIdx] // drop dsStep; re-append after intSteps

				_, intSteps, intOK, intInsecure := validateIntermediateZones(last.zone, signerParent, last.ns, keys, nsidRequested, reqEdnsOpts)
				extraSteps = append(extraSteps, intSteps...)

				if !intOK && intInsecure {
					if callerSuppliedDS {
						// RFC 4033 §5: parent chain is broken; the zone remains insecure regardless
						// of any DS override. Continue validation to show whether the supplied DS
						// would work, then downgrade the final result to "insecure".
						dbg("validate: %s is insecure; RFC 4033 §5 — testing caller-supplied DS for %s anyway", signerParent, signerZone)
						dsStep.StepNote += fmt.Sprintf(" — %s is insecure (RFC 4033 §5); testing caller-supplied DS", signerParent)
						extraSteps = append(extraSteps, dsStep)
						signerParentInsecure = true
						// fall through to proceed with caller-supplied DS validation
					} else {
						dbg("validate: %s is insecure — insecure", signerParent)
						dsStep.StepNote += fmt.Sprintf(" — %s is insecure", signerParent)
						extraSteps = append(extraSteps, dsStep)
						selfSteps, _ := attemptSelfVerification(signerZone, last, nsidRequested, reqEdnsOpts)
						return "insecure", append(extraSteps, selfSteps...)
					}
				} else if !intOK {
					dbg("validate: intermediate zone %s validation failed", signerParent)
					dsStep.StepNote += fmt.Sprintf(" — intermediate zone %s validation failed (BOGUS)", signerParent)
					extraSteps = append(extraSteps, dsStep)
					return false, extraSteps
				} else {
					// Intermediate zones are signed but DS for signerZone has no RRSIG — bogus.
					dbg("validate: DS for %s has no RRSIG despite signed intermediate zone %s → BOGUS", signerZone, signerParent)
					dsStep.StepNote += " — DS has no RRSIG despite signed parent zone (BOGUS)"
					extraSteps = append(extraSteps, dsStep)
					return false, extraSteps
				}
			} else {
				// parentOfSigner == last.zone: last.zone is a validated signed zone, so its
				// DS for signerZone should be RRSIG-signed. No RRSIG is bogus regardless of
				// whether a caller-supplied DS override was provided.
				dbg("validate: DS for %s has no RRSIG from signed parent zone %s → BOGUS", signerZone, last.zone)
				extraSteps[dsStepIdx].StepNote += " — DS has no RRSIG from signed parent zone (BOGUS)"
				return false, extraSteps
			}
		}

		if !callerSuppliedDS {
			if ok, dsSigTag := verifyDSRRSigInAnswer(dsResp.Answer, keysForDS); !ok {
				dbg("validate: DS RRSIG in answer failed for %s → BOGUS", signerZone)
				extraSteps[dsStepIdx].StepNote += " — DS RRSIG failed (BOGUS)"
				return false, extraSteps
			} else {
				dbg("validate: DS RRSIG OK for %s", signerZone)
				if dsSigTag != 0 {
					extraSteps[dsStepIdx].StepNote += fmt.Sprintf(" — DS sig OK (keytag=%d)", dsSigTag)
				} else {
					extraSteps[dsStepIdx].StepNote += " — DS sig OK"
				}
			}
		}

		childKeyResp, childKeyStep := fetchDNSKEYResponse(signerZone, last.ns, nsidRequested, reqEdnsOpts)
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
			// A DS exists (parent-published or caller-supplied) but the zone has no
			// DNSKEY records — the DS asserts a key that doesn't exist.
			// If the parent chain is already insecure, insecure takes precedence
			// (RFC 4033 §5); otherwise this is a cryptographic failure → BOGUS.
			if signerParentInsecure {
				dbg("validate: no DNSKEY for child zone %s; parent chain insecure → insecure", signerZone)
				childKeyStep.StepNote += " — no DNSKEY records returned; parent chain is insecure (RFC 4033 §5)"
				extraSteps = append(extraSteps, childKeyStep)
				return "insecure", extraSteps
			}
			dbg("validate: no DNSKEY for child zone %s but DS exists → BOGUS", signerZone)
			childKeyStep.StepNote += " — no DNSKEY records but DS exists (BOGUS)"
			extraSteps = append(extraSteps, childKeyStep)
			return false, extraSteps
		}
		if ok, matchTags := anyKeyMatchesDS(childKeys, dsForChildMatch); !ok {
			dbg("validate: child DNSKEY does not match DS for %s → BOGUS", signerZone)
			childKeyStep.StepNote += " — DNSKEY does not match DS (BOGUS)"
			extraSteps = append(extraSteps, childKeyStep)
			return false, extraSteps
		} else {
			childKeyStep.StepNote += fmt.Sprintf(" — DS match OK, %s", formatKeyTags(matchTags))
		}
		if err, sigTag := verifyDNSKEYRRSig(childKeys, childKeyResp); err != nil {
			if err == dns.ErrAlg {
				algName := dnsKeyAlgName(childKeys)
				dbg("validate: child DNSKEY self-sig for %s uses unsupported algorithm %s — treating as insecure (RFC 4033 §5)", signerZone, algName)
				childKeyStep.StepNote += fmt.Sprintf(", DNSKEY self-signature uses unsupported algorithm %s — insecure (RFC 4033 §5)", algName)
				extraSteps = append(extraSteps, childKeyStep)
				return "insecure", extraSteps
			}
			dbg("validate: child DNSKEY self-sig failed for %s → BOGUS", signerZone)
			childKeyStep.StepNote += ", DNSKEY self-signature failed (BOGUS)"
			extraSteps = append(extraSteps, childKeyStep)
			return false, extraSteps
		} else {
			dbg("validate: child DNSKEY self-sig OK for %s", signerZone)
			childKeyStep.StepNote += fmt.Sprintf(", self-sig OK (keytag=%d)", sigTag)
		}
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
		algUnsupported := false
		for _, key := range keys {
			if key.KeyTag() == sig.KeyTag {
				err := verifySig(sig, key, rrset)
				dbg("validate: verify RRSIG type=%s name=%s keytag=%d → %v", dns.TypeToString[sig.TypeCovered], sig.Hdr.Name, sig.KeyTag, err)
				if err == nil {
					sigOK = true
					break
				}
				if err == dns.ErrAlg {
					algUnsupported = true
				}
			}
		}
		if !sigOK {
			verifyStep := verifyStepBase
			if algUnsupported {
				algName := dns.AlgorithmToString[sig.Algorithm]
				if algName == "" {
					algName = fmt.Sprintf("algorithm %d", sig.Algorithm)
				}
				dbg("validate: RRSIG(%s) at %s uses unsupported algorithm %s — treating as insecure (RFC 4033 §5)", dns.TypeToString[sig.TypeCovered], sig.Hdr.Name, algName)
				verifyStep.StepNote = fmt.Sprintf("RRSIG(%s) at %s uses %s (algorithm %d) which is not supported — insecure (RFC 4033 §5)",
					dns.TypeToString[sig.TypeCovered], sig.Hdr.Name, algName, sig.Algorithm)
				verifyStep.ResponseText = fmt.Sprintf("; %s\n\n%s", verifyStep.StepNote, last.resp.String())
				if b, packErr := last.resp.Pack(); packErr == nil {
					verifyStep.ResponseBytesHex = hex.EncodeToString(b)
				}
				return "insecure", append(extraSteps, verifyStep)
			}
			dbg("validate: RRSIG(%s) at %s could not be verified → BOGUS", dns.TypeToString[sig.TypeCovered], sig.Hdr.Name)
			verifyStep.StepNote = fmt.Sprintf("RRSIG(%s) at %s could not be verified — BOGUS", dns.TypeToString[sig.TypeCovered], sig.Hdr.Name)
			verifyStep.ResponseText = fmt.Sprintf("; RRSIG(%s) at %s could not be verified.\n; Result: BOGUS\n\n%s",
				dns.TypeToString[sig.TypeCovered], sig.Hdr.Name, last.resp.String())
			if b, packErr := last.resp.Pack(); packErr == nil {
				verifyStep.ResponseBytesHex = hex.EncodeToString(b)
			}
			return false, append(extraSteps, verifyStep)
		}
		verified = append(verified, sigResult{label: fmt.Sprintf("RRSIG(%s) keytag=%d", dns.TypeToString[sig.TypeCovered], sig.KeyTag)})
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

	// When the authoritative server returns NXDOMAIN and also includes a CNAME in
	// the answer section, the NXDOMAIN applies to the CNAME target (the owner name
	// exists — it has a CNAME — but the target does not). The NSEC/NSEC3 denial
	// records cover the target, so use that as the proof name, not req.QName.
	denialName := dns.Fqdn(req.QName)
	if last.resp.Rcode == dns.RcodeNameError {
		denialName = cnameChainTarget(last.resp.Answer, denialName)
	}

	var denialNote string
	if isDenial || isWildcard {
		nsecs, nsec3s := extractDenialRRs(last.resp.Ns)
		var denialOK bool

		switch {
		case isWildcard:
			denialOK, denialNote = verifyWildcardNextCloser(dns.Fqdn(req.QName), last.resp)
		case len(nsec3s) > 0:
			denialOK, denialNote = verifyNSEC3Denial(denialName, qtype, last.resp.Rcode, nsec3s)
		case len(nsecs) > 0:
			denialOK, denialNote = verifyNSECDenial(denialName, qtype, last.resp.Rcode, nsecs)
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
	if signerParentInsecure {
		note += " — zone validates with supplied DS, but parent chain is insecure (RFC 4033 §5)"
	} else {
		note += " — SECURE"
	}
	dbg("validate: %s", note)
	verifyStep := verifyStepBase
	verifyStep.StepNote = note
	verifyStep.ResponseText = fmt.Sprintf("; %s\n\n%s", note, last.resp.String())
	if b, packErr := last.resp.Pack(); packErr == nil {
		verifyStep.ResponseBytesHex = hex.EncodeToString(b)
	}
	extraSteps = append(extraSteps, verifyStep)

	// Compute the base result: insecure if the parent chain is broken above the
	// signerZone, even though the zone's own DNSKEY/RRSIG validated with the
	// caller-supplied DS.
	baseResult := interface{}(true)
	if signerParentInsecure {
		baseResult = "insecure"
	}

	// If the final answer is a cross-zone CNAME, also validate the CNAME target's
	// chain. The iterative resolver restarts from root for the target, appending
	// those steps after the CNAME step. We validate them separately and return the
	// weaker of the two results: a secure CNAME pointing to an insecure zone is
	// insecure overall, and bogus beats everything.
	if last.resp.Rcode == dns.RcodeSuccess && isCNAMEOnlyAnswer(last.resp.Answer) &&
		lastChainIdx >= 0 && lastChainIdx < len(chain)-1 {
		targetName := cnameChainTarget(last.resp.Answer, dns.Fqdn(req.QName))
		dbg("validate: CNAME to %s — validating target chain (steps %d–%d)", targetName, lastChainIdx+1, len(chain)-1)
		targetReq := *req
		targetReq.QName = targetName
		targetResult, targetSteps := validateChainOfTrust(chain[lastChainIdx+1:], &targetReq)
		extraSteps = append(extraSteps, targetSteps...)
		return weakerValidationResult(baseResult, targetResult), extraSteps
	}

	return baseResult, extraSteps
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
func attemptSelfVerification(zone string, last zoneLevel, nsidRequested bool, reqEdnsOpts []dns.EDNS0) ([]ResolutionStep, string) {
	dbg("validate: attemptSelfVerification for %s", zone)
	keyResp, keyStep := fetchDNSKEYResponse(zone, last.ns, nsidRequested, reqEdnsOpts)
	keyStep.StepNote = fmt.Sprintf("Self-verification: fetching %s DNSKEY (no parent DS — not a chain-of-trust check)", zone)
	if keyResp == nil {
		dbg("validate: self-verify %s: DNSKEY fetch failed", zone)
		keyStep.StepNote += " — fetch failed"
		return []ResolutionStep{keyStep}, "DNSKEY fetch failed — cannot self-verify"
	}
	keys := extractDNSKEYs(keyResp)
	dbg("validate: self-verify %s: got %d DNSKEY(s)", zone, len(keys))
	if len(keys) == 0 {
		dbg("validate: self-verify %s: no DNSKEY records", zone)
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
				dbg("validate: self-verify %s: DNSKEY self-sig expired (crypto OK)", zone)
				keyStep.StepNote += " — DNSKEY self-sig cryptographically OK but RRSIG expired (zone needs re-signing)"
				return []ResolutionStep{keyStep}, "DNSKEY self-sig expired (crypto OK — zone needs re-signing)"
			}
			dbg("validate: self-verify %s: DNSKEY self-sig FAILED", zone)
			keyStep.StepNote += " — DNSKEY self-sig FAILED (signing error)"
			return []ResolutionStep{keyStep}, "DNSKEY self-sig failed (zone signing error?)"
		}
		dbg("validate: self-verify %s: DNSKEY self-sig OK", zone)
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
	dbg("validate: self-verify %s: verified=%d expired=%d failed=%d", zone, len(verified), len(expired), len(failed))

	if len(verified) == 0 && len(expired) == 0 && len(failed) == 0 {
		dbg("validate: self-verify %s: no RRSIGs to verify", zone)
		keyStep.StepNote += " — no RRSIGs in final response to verify"
		return []ResolutionStep{keyStep}, "no RRSIGs to verify (zone may not be signing)"
	}
	if len(failed) > 0 {
		dbg("validate: self-verify %s: FAILED for %v", zone, failed)
		parts := failed
		if len(expired) > 0 {
			parts = append(parts, expired...)
		}
		keyStep.StepNote += fmt.Sprintf(" — self-verification FAILED: %s", strings.Join(parts, ", "))
		return []ResolutionStep{keyStep}, fmt.Sprintf("self-verification failed for %s (zone signing error?)", strings.Join(failed, ", "))
	}
	if len(expired) > 0 && len(verified) == 0 {
		dbg("validate: self-verify %s: all RRSIGs expired (crypto OK)", zone)
		keyStep.StepNote += fmt.Sprintf(" — RRSIG(s) expired (crypto OK): %s (zone needs re-signing)", strings.Join(expired, ", "))
		return []ResolutionStep{keyStep}, fmt.Sprintf("self-verified crypto OK but RRSIG(s) expired: %s — zone needs re-signing", strings.Join(expired, ", "))
	}
	note := strings.Join(verified, ", ")
	if len(expired) > 0 {
		note += fmt.Sprintf("; expired (crypto OK): %s", strings.Join(expired, ", "))
	}
	dbg("validate: self-verify %s: OK — %s", zone, note)
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

// anyKeyMatchesDS returns whether any key hashes to one of the DS records,
// along with the key tags of all matching DNSKEY/DS pairs (deduplicated).
func anyKeyMatchesDS(keys []*dns.DNSKEY, dsRecs []*dns.DS) (bool, []uint16) {
	seen := map[uint16]bool{}
	var matched []uint16
	for _, key := range keys {
		for _, ds := range dsRecs {
			computed := key.ToDS(ds.DigestType)
			if computed != nil && strings.EqualFold(computed.Digest, ds.Digest) {
				if tag := key.KeyTag(); !seen[tag] {
					seen[tag] = true
					matched = append(matched, tag)
				}
			}
		}
	}
	return len(matched) > 0, matched
}

// formatKeyTags formats a slice of key tags as "keytag=N" (one tag) or "keytags=N, M, …" (several).
func formatKeyTags(tags []uint16) string {
	if len(tags) == 1 {
		return fmt.Sprintf("keytag=%d", tags[0])
	}
	parts := make([]string, len(tags))
	for i, t := range tags {
		parts[i] = fmt.Sprintf("%d", t)
	}
	return "keytags=" + strings.Join(parts, ", ")
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

// verifyDNSKEYRRSig verifies the DNSKEY RRset self-signature in keyResp.
// Returns (nil, keyTag) on success, (dns.ErrAlg, 0) if the signing algorithm is
// not supported by this library, or (err, 0) for any other failure.
// Returns (nil, 0) when no RRSIG is present (DS match already proved the key trusted).
func verifyDNSKEYRRSig(keys []*dns.DNSKEY, keyResp *dns.Msg) (error, uint16) {
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
		return nil, 0
	}
	algUnsupported := false
	for _, sig := range rrsigs {
		for _, key := range keys {
			if key.KeyTag() == sig.KeyTag {
				err := verifySig(sig, key, keyRRs)
				if err == nil {
					return nil, sig.KeyTag
				}
				if err == dns.ErrAlg {
					algUnsupported = true
				}
			}
		}
	}
	if algUnsupported {
		return dns.ErrAlg, 0
	}
	return fmt.Errorf("DNSKEY self-signature failed"), 0
}

// verifyDSRRSig returns (true, keyTag) if the DS records in the parent's authority
// section have a valid RRSIG from one of the parent's validated keys, where keyTag
// is the tag of the key that verified. Returns (false, 0) on failure.
func verifyDSRRSig(dsRecs []*dns.DS, parentResp *dns.Msg, parentKeys []*dns.DNSKEY) (bool, uint16) {
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
		return true, 0
	}
	for _, sig := range rrsigs {
		for _, key := range parentKeys {
			if key.KeyTag() == sig.KeyTag {
				if err := verifySig(sig, key, dsRRs); err == nil {
					return true, sig.KeyTag
				}
			}
		}
	}
	return false, 0
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
// It returns the validated DNSKEY set for signerZone, any extra steps, success, and isInsecure.
// isInsecure is true when an intermediate zone has no DS in its parent (unsigned delegation);
// it is false for other failures (RRSIG mismatch, fetch error, etc.) which are bogus/indeterminate.
func validateIntermediateZones(parentZone, signerZone string, ns namedAddr, parentKeys []*dns.DNSKEY, nsidRequested bool, reqEdnsOpts []dns.EDNS0) ([]*dns.DNSKEY, []ResolutionStep, bool, bool) {
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
	dbg("validate: validateIntermediateZones %s→%s: %d zone(s) to traverse", parentZone, signerZone, len(zones))

	var extraSteps []ResolutionStep
	currentKeys := parentKeys

	for _, zone := range zones {
		dbg("validate: intermediate zone %s: fetching DS", zone)
		dsResp, dsStep := fetchDSResponse(zone, ns, nsidRequested, reqEdnsOpts)
		dsStep.StepNote = fmt.Sprintf("Fetching DS for intermediate zone %s (zone boundary inferred from RRSIG signer)", zone)
		extraSteps = append(extraSteps, dsStep)

		if dsResp == nil {
			dbg("validate: intermediate zone %s: DS fetch failed → indeterminate", zone)
			dsStep.StepNote += " — fetch failed"
			return nil, extraSteps, false, false
		}

		var ds []*dns.DS
		for _, rr := range dsResp.Answer {
			if d, ok := rr.(*dns.DS); ok {
				ds = append(ds, d)
			}
		}
		dbg("validate: intermediate zone %s: got %d DS record(s)", zone, len(ds))
		if len(ds) == 0 {
			dbg("validate: intermediate zone %s: no DS → insecure", zone)
			dsStep.StepNote += " — no DS records found; unsigned delegation (insecure)"
			return nil, extraSteps, false, true
		}
		if ok, dsSigTag := verifyDSRRSigInAnswer(dsResp.Answer, currentKeys); !ok {
			dbg("validate: intermediate zone %s: DS RRSIG failed → BOGUS", zone)
			dsStep.StepNote += " — DS RRSIG failed (BOGUS)"
			return nil, extraSteps, false, false
		} else if dsSigTag != 0 {
			dbg("validate: intermediate zone %s: DS RRSIG OK (keytag=%d)", zone, dsSigTag)
			dsStep.StepNote += fmt.Sprintf(" — DS sig OK (keytag=%d)", dsSigTag)
		} else {
			dbg("validate: intermediate zone %s: DS RRSIG OK", zone)
			dsStep.StepNote += " — DS sig OK"
		}

		dbg("validate: intermediate zone %s: fetching DNSKEY", zone)
		keyResp, keyStep := fetchDNSKEYResponse(zone, ns, nsidRequested, reqEdnsOpts)
		keyStep.StepNote = fmt.Sprintf("Validating intermediate zone %s DNSKEY", zone)
		extraSteps = append(extraSteps, keyStep)

		if keyResp == nil {
			dbg("validate: intermediate zone %s: DNSKEY fetch failed → indeterminate", zone)
			keyStep.StepNote += " — fetch failed"
			return nil, extraSteps, false, false
		}
		keys := extractDNSKEYs(keyResp)
		dbg("validate: intermediate zone %s: got %d DNSKEY(s)", zone, len(keys))
		if len(keys) == 0 {
			dbg("validate: intermediate zone %s: no DNSKEY but DS exists → BOGUS", zone)
			keyStep.StepNote += " — no DNSKEY records"
			return nil, extraSteps, false, false
		}
		if ok, matchTags := anyKeyMatchesDS(keys, ds); !ok {
			dbg("validate: intermediate zone %s: DNSKEY does not match DS → BOGUS", zone)
			keyStep.StepNote += " — DNSKEY does not match DS (BOGUS)"
			return nil, extraSteps, false, false
		} else {
			dbg("validate: intermediate zone %s: DS match OK, %s", zone, formatKeyTags(matchTags))
			keyStep.StepNote += fmt.Sprintf(" — DS match OK, %s", formatKeyTags(matchTags))
		}
		if err, sigTag := verifyDNSKEYRRSig(keys, keyResp); err != nil {
			if err == dns.ErrAlg {
				// RFC 4033 §5: unsupported algorithm → treat as if unsigned (insecure).
				dbg("validate: intermediate zone %s: DNSKEY self-sig uses unsupported alg → insecure (RFC 4033 §5)", zone)
				keyStep.StepNote += fmt.Sprintf(", DNSKEY self-signature uses unsupported algorithm %s — insecure (RFC 4033 §5)", dnsKeyAlgName(keys))
				extraSteps = append(extraSteps, keyStep)
				return nil, extraSteps, false, true // isInsecure=true: treat as unsigned per RFC 4033 §5
			}
			dbg("validate: intermediate zone %s: DNSKEY self-sig failed → BOGUS", zone)
			keyStep.StepNote += ", DNSKEY self-signature failed (BOGUS)"
			return nil, extraSteps, false, false
		} else if sigTag != 0 {
			dbg("validate: intermediate zone %s: DNSKEY self-sig OK (keytag=%d)", zone, sigTag)
			keyStep.StepNote += fmt.Sprintf(", self-sig OK (keytag=%d)", sigTag)
		} else {
			dbg("validate: intermediate zone %s: DNSKEY self-sig OK", zone)
			keyStep.StepNote += ", self-sig OK"
		}
		currentKeys = keys
	}

	dbg("validate: validateIntermediateZones %s→%s: all OK, returning %d key(s)", parentZone, signerZone, len(currentKeys))
	return currentKeys, extraSteps, true, false
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
func fetchDSResponse(zone string, ns namedAddr, nsidRequested bool, reqEdnsOpts []dns.EDNS0) (*dns.Msg, ResolutionStep) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeDS)
	m.RecursionDesired = false
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(1232)
	o.SetDo()
	o.Option = append(o.Option, reqEdnsOpts...)
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
	if nsidRequested {
		step.NSID = extractNSIDFromMsg(resp)
	}
	return resp, step
}

// verifyDSRRSigInAnswer verifies that the DS RRset in an answer section (from an
// explicit DS query) is signed by one of the parent zone's validated keys. This
// differs from verifyDSRRSig which looks in the authority section of a referral.
// Returns (true, keyTag) on success, (false, 0) on failure, (true, 0) when no RRSIG present.
func verifyDSRRSigInAnswer(answer []dns.RR, parentKeys []*dns.DNSKEY) (bool, uint16) {
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
		return true, 0
	}
	for _, sig := range rrsigs {
		for _, key := range parentKeys {
			if key.KeyTag() == sig.KeyTag {
				dbg("verifyDSRRSigInAnswer: trying key tag=%d for DS RRSIG", sig.KeyTag)
				if err := verifySig(sig, key, dsRRs); err == nil {
					return true, sig.KeyTag
				}
			}
		}
	}
	return false, 0
}

// fetchDNSKEYResponse queries ns for the DNSKEY RRset at zone, returning the full
// DNS response and a ResolutionStep for the chain.
func fetchDNSKEYResponse(zone string, ns namedAddr, nsidRequested bool, reqEdnsOpts []dns.EDNS0) (*dns.Msg, ResolutionStep) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeDNSKEY)
	m.RecursionDesired = false
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(1232)
	o.SetDo()
	o.Option = append(o.Option, reqEdnsOpts...)
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
	if nsidRequested {
		step.NSID = extractNSIDFromMsg(resp)
	}
	return resp, step
}

func extractNSIDFromMsg(resp *dns.Msg) string {
	for _, extra := range resp.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			parsed := edns.ParseAll(opt)
			if nsidData, ok := parsed[dns.EDNS0NSID]; ok {
				if txt, ok := nsidData["nsid_txt"].(string); ok && txt != "" {
					return txt
				}
				if h, ok := nsidData["nsid_hex"].(string); ok {
					return h
				}
			}
			break
		}
	}
	return ""
}

// extractZoneVersionFromMsg parses the ZONEVERSION option from a response OPT RR.
func extractZoneVersionFromMsg(resp *dns.Msg) map[string]interface{} {
	for _, extra := range resp.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			parsed := edns.ParseAll(opt)
			if zvData, ok := parsed[dns.EDNS0ZONEVERSION]; ok {
				return zvData
			}
			break
		}
	}
	return nil
}

// cleanZoneVersionText replaces miekg's raw-byte ZONEVERSION rendering in a
// response string with a human-readable version derived from parsed option data.
// miekg's EDNS0_ZONEVERSION.String() simply returns the raw Version bytes, which
// display as garbage for non-ASCII serials.
func cleanZoneVersionText(text string, zvData map[string]interface{}) string {
	if zvData == nil {
		return text
	}
	const prefix = "; ZONEVERSION: "
	if !strings.Contains(text, prefix) {
		return text
	}
	readable := fmtZoneVersion(zvData)
	out := &strings.Builder{}
	remaining := text
	for remaining != "" {
		idx := strings.Index(remaining, prefix)
		if idx < 0 {
			out.WriteString(remaining)
			break
		}
		out.WriteString(remaining[:idx])
		out.WriteString(prefix)
		out.WriteString(readable)
		// Consume the raw bytes after the prefix up to the next newline.
		after := remaining[idx+len(prefix):]
		if nl := strings.IndexByte(after, '\n'); nl >= 0 {
			out.WriteByte('\n')
			remaining = after[nl+1:]
		} else {
			remaining = ""
		}
	}
	return out.String()
}

// fmtZoneVersion formats a parsed ZONEVERSION option map as a readable string.
func fmtZoneVersion(zv map[string]interface{}) string {
	typeName, _ := zv["type_name"].(string)
	if typeName == "" {
		if t, ok := zv["type"].(int); ok {
			typeName = fmt.Sprintf("type %d", t)
		}
	}
	labels := 0
	if l, ok := zv["label_count"].(int); ok {
		labels = l
	}
	base := fmt.Sprintf("labels=%d %s", labels, typeName)
	if serial, ok := zv["serial"].(uint32); ok {
		return fmt.Sprintf("%s serial=%d", base, serial)
	}
	// For non-SOA-SERIAL types, show decimal value when the wire data is 4 bytes,
	// plus hex for completeness.
	if val, ok := zv["value"].(uint32); ok {
		if vh, _ := zv["version_hex"].(string); vh != "" {
			return fmt.Sprintf("%s value=%d (0x%s)", base, val, vh)
		}
		return fmt.Sprintf("%s value=%d", base, val)
	}
	if vh, ok := zv["version_hex"].(string); ok {
		return fmt.Sprintf("%s version=%s", base, vh)
	}
	return base
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

// cnameChainTarget follows the CNAME chain in ans starting from start and
// returns the final target name (FQDN). Returns start unchanged if no CNAME
// is found. Guards against infinite loops with a step limit.
func cnameChainTarget(ans []dns.RR, start string) string {
	name := start
	for range 16 {
		found := false
		for _, rr := range ans {
			if cn, ok := rr.(*dns.CNAME); ok &&
				strings.EqualFold(dns.Fqdn(cn.Hdr.Name), name) {
				name = dns.Fqdn(cn.Target)
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return name
}

// dnsKeyAlgName returns the algorithm name string for the first key in the
// slice, or "unknown" if the slice is empty or the algorithm has no name.
func dnsKeyAlgName(keys []*dns.DNSKEY) string {
	if len(keys) == 0 {
		return "unknown"
	}
	if name := dns.AlgorithmToString[keys[0].Algorithm]; name != "" {
		return fmt.Sprintf("%s (algorithm %d)", name, keys[0].Algorithm)
	}
	return fmt.Sprintf("algorithm %d", keys[0].Algorithm)
}

// isCNAMEOnlyAnswer returns true when every non-RRSIG record in ans is a CNAME,
// indicating a cross-zone CNAME redirection rather than a final typed answer.
func isCNAMEOnlyAnswer(ans []dns.RR) bool {
	if len(ans) == 0 {
		return false
	}
	for _, rr := range ans {
		t := rr.Header().Rrtype
		if t != dns.TypeCNAME && t != dns.TypeRRSIG {
			return false
		}
	}
	return true
}

// weakerValidationResult returns the less secure of two validation outcomes.
// Priority (strongest to weakest): true > "insecure" > "indeterminate" > false.
// A bogus result in any part of a CNAME chain makes the whole chain bogus.
func weakerValidationResult(a, b interface{}) interface{} {
	if a == false || b == false {
		return false
	}
	if a == "indeterminate" || b == "indeterminate" {
		return "indeterminate"
	}
	if a == "insecure" || b == "insecure" {
		return "insecure"
	}
	return true
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

func extractAllNSNames(ns []dns.RR) []string {
	var names []string
	seen := map[string]bool{}
	for _, rr := range ns {
		if nsrr, ok := rr.(*dns.NS); ok {
			key := strings.ToLower(nsrr.Ns)
			if !seen[key] {
				names = append(names, nsrr.Ns)
				seen[key] = true
			}
		}
	}
	return names
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
