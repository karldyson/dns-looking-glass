package dns

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func makeKey(t *testing.T, zone string, flags uint16) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("makeKey %s: %v", zone, err)
	}
	return key, priv.(crypto.Signer)
}

func makeKSK(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) { return makeKey(t, zone, 257) }
func makeZSK(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) { return makeKey(t, zone, 256) }

func signRRset(t *testing.T, key *dns.DNSKEY, signer crypto.Signer, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  key.Hdr.Name,
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("signRRset type=%s: %v", dns.TypeToString[sig.TypeCovered], err)
	}
	return sig
}

func packHex(t *testing.T, m *dns.Msg) string {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("packHex: %v", err)
	}
	out := make([]byte, len(b)*2)
	const hexDigits = "0123456789abcdef"
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0xf]
	}
	return string(out)
}

// ── rrsetForSig ───────────────────────────────────────────────────────────────

// TestRrsetForSig_NSEC3MultipleOwners verifies the NSEC3 NXDOMAIN bug fix: when an
// authority section carries multiple NSEC3 records at different hashed owner names,
// rrsetForSig must return only the records at the RRSIG's own owner name.
func TestRrsetForSig_NSEC3MultipleOwners(t *testing.T) {
	names := []string{
		"TE876MNU8R2NQR74E1MINODE9L14859Q.nsec3.uk.",
		"QJ7TMU1PAG49JQUN6H1HC93V0S0U2HCE.nsec3.uk.",
		"SIIVF9CB0GUDEEVU8VNDLR7RVHF9USL5.nsec3.uk.",
	}
	var rrs []dns.RR
	for _, n := range names {
		rrs = append(rrs, &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: n, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 900},
			Hash:       1,
			TypeBitMap: []uint16{dns.TypeA},
		})
	}

	for i, want := range names {
		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: want},
			TypeCovered: dns.TypeNSEC3,
		}
		got := rrsetForSig(rrs, sig)
		if len(got) != 1 {
			t.Errorf("RRSIG at names[%d]: want 1 record, got %d", i, len(got))
			continue
		}
		if got[0].Header().Name != want {
			t.Errorf("RRSIG at names[%d]: want %q, got %q", i, want, got[0].Header().Name)
		}
	}
}

func TestRrsetForSig_CaseInsensitive(t *testing.T) {
	rr := &dns.NSEC3{
		Hdr: dns.RR_Header{Name: "ABC.EXAMPLE.COM.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "abc.example.com."},
		TypeCovered: dns.TypeNSEC3,
	}
	got := rrsetForSig([]dns.RR{rr}, sig)
	if len(got) != 1 {
		t.Errorf("case-insensitive match: want 1 record, got %d", len(got))
	}
}

func TestRrsetForSig_NoMatch(t *testing.T) {
	rr := &dns.NSEC3{
		Hdr: dns.RR_Header{Name: "aaa.example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
	}
	// Wrong type.
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "aaa.example.com."}, TypeCovered: dns.TypeSOA}
	if got := rrsetForSig([]dns.RR{rr}, sig); len(got) != 0 {
		t.Errorf("wrong type: want 0 records, got %d", len(got))
	}
	// Wrong name.
	sig2 := &dns.RRSIG{Hdr: dns.RR_Header{Name: "bbb.example.com."}, TypeCovered: dns.TypeNSEC3}
	if got := rrsetForSig([]dns.RR{rr}, sig2); len(got) != 0 {
		t.Errorf("wrong name: want 0 records, got %d", len(got))
	}
}

// ── rrsetForType ──────────────────────────────────────────────────────────────

func TestRrsetForType(t *testing.T) {
	rrs := []dns.RR{
		&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA}},
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA}},
		&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}},
	}
	got := rrsetForType(rrs, dns.TypeA)
	if len(got) != 1 || got[0].Header().Rrtype != dns.TypeA {
		t.Errorf("rrsetForType(A): want [A], got %v", got)
	}
	if len(rrsetForType(rrs, dns.TypeMX)) != 0 {
		t.Error("rrsetForType(MX): expected empty for absent type")
	}
}

// ── convertTrustAnchors ───────────────────────────────────────────────────────

func TestConvertTrustAnchors(t *testing.T) {
	anchors := []TrustAnchorDS{{
		KeyTag: 20326, Algorithm: 8, DigestType: 2,
		Digest: "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
	}}
	ds := convertTrustAnchors(anchors)
	if len(ds) != 1 {
		t.Fatalf("want 1 DS, got %d", len(ds))
	}
	if ds[0].KeyTag != 20326 {
		t.Errorf("KeyTag: want 20326, got %d", ds[0].KeyTag)
	}
	if ds[0].Hdr.Name != "." {
		t.Errorf("Name: want \".\", got %q", ds[0].Hdr.Name)
	}
	const wantDigest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
	if ds[0].Digest != wantDigest {
		t.Errorf("Digest: want %q, got %q", wantDigest, ds[0].Digest)
	}
}

func TestConvertTrustAnchors_Empty(t *testing.T) {
	if ds := convertTrustAnchors(nil); len(ds) != 0 {
		t.Errorf("nil input: want empty slice, got %d entries", len(ds))
	}
}

// ── anyKeyMatchesDS ───────────────────────────────────────────────────────────

func TestAnyKeyMatchesDS(t *testing.T) {
	ksk1, _ := makeKSK(t, "example.com.")
	ksk2, _ := makeKSK(t, "example.com.")
	ds1 := ksk1.ToDS(dns.SHA256)
	ds2 := ksk2.ToDS(dns.SHA256)

	cases := []struct {
		name string
		keys []*dns.DNSKEY
		ds   []*dns.DS
		want bool
	}{
		{"key1 matches ds1", []*dns.DNSKEY{ksk1}, []*dns.DS{ds1}, true},
		{"key2 does not match ds1", []*dns.DNSKEY{ksk2}, []*dns.DS{ds1}, false},
		{"key2 matches ds2 (two keys presented)", []*dns.DNSKEY{ksk1, ksk2}, []*dns.DS{ds2}, true},
		{"nil keys", nil, []*dns.DS{ds1}, false},
		{"nil DS", []*dns.DNSKEY{ksk1}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := anyKeyMatchesDS(tc.keys, tc.ds); got != tc.want {
				t.Errorf("anyKeyMatchesDS = %v, want %v", got, tc.want)
			}
		})
	}
}

// ── verifyDNSKEYRRSig ─────────────────────────────────────────────────────────

func TestVerifyDNSKEYRRSig_Valid(t *testing.T) {
	ksk, signer := makeKSK(t, "example.com.")
	rrset := []dns.RR{ksk}
	sig := signRRset(t, ksk, signer, rrset)
	msg := &dns.Msg{Answer: []dns.RR{ksk, sig}}
	if !verifyDNSKEYRRSig([]*dns.DNSKEY{ksk}, msg) {
		t.Error("expected true for valid self-signature")
	}
}

func TestVerifyDNSKEYRRSig_NoRRSIG(t *testing.T) {
	ksk, _ := makeKSK(t, "example.com.")
	msg := &dns.Msg{Answer: []dns.RR{ksk}}
	// No RRSIGs — function returns true (trust established via DS comparison).
	if !verifyDNSKEYRRSig([]*dns.DNSKEY{ksk}, msg) {
		t.Error("expected true when no RRSIGs present")
	}
}

func TestVerifyDNSKEYRRSig_WrongKey(t *testing.T) {
	ksk1, signer1 := makeKSK(t, "example.com.")
	ksk2, _ := makeKSK(t, "example.com.")
	sig := signRRset(t, ksk1, signer1, []dns.RR{ksk1})
	msg := &dns.Msg{Answer: []dns.RR{ksk1, sig}}
	// Provide ksk2: different KeyTag → the tag check in the loop never matches.
	if verifyDNSKEYRRSig([]*dns.DNSKEY{ksk2}, msg) {
		t.Error("expected false with wrong key")
	}
}

// ── verifyDSRRSig ─────────────────────────────────────────────────────────────

func TestVerifyDSRRSig_Valid(t *testing.T) {
	parentZSK, parentSigner := makeZSK(t, ".")
	childKSK, _ := makeKSK(t, "uk.")
	ds := childKSK.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: "uk.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 900}

	sig := signRRset(t, parentZSK, parentSigner, []dns.RR{ds})
	parentResp := &dns.Msg{Ns: []dns.RR{ds, sig}}

	if !verifyDSRRSig([]*dns.DS{ds}, parentResp, []*dns.DNSKEY{parentZSK}) {
		t.Error("expected true for valid DS RRSIG")
	}
}

func TestVerifyDSRRSig_NoRRSIG(t *testing.T) {
	childKSK, _ := makeKSK(t, "uk.")
	ds := childKSK.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: "uk.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 900}
	parentZSK, _ := makeZSK(t, ".")
	parentResp := &dns.Msg{Ns: []dns.RR{ds}}
	// No RRSIGs — function returns true.
	if !verifyDSRRSig([]*dns.DS{ds}, parentResp, []*dns.DNSKEY{parentZSK}) {
		t.Error("expected true when no DS RRSIGs present")
	}
}

func TestVerifyDSRRSig_WrongParentKey(t *testing.T) {
	parentZSK, parentSigner := makeZSK(t, ".")
	wrongKey, _ := makeZSK(t, ".")
	childKSK, _ := makeKSK(t, "uk.")
	ds := childKSK.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: "uk.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 900}

	sig := signRRset(t, parentZSK, parentSigner, []dns.RR{ds})
	parentResp := &dns.Msg{Ns: []dns.RR{ds, sig}}

	if verifyDSRRSig([]*dns.DS{ds}, parentResp, []*dns.DNSKEY{wrongKey}) {
		t.Error("expected false with wrong parent key")
	}
}

// ── parseDelegationChain ──────────────────────────────────────────────────────

func TestParseDelegationChain_ThreeLevels(t *testing.T) {
	dsUK := &dns.DS{
		Hdr:        dns.RR_Header{Name: "uk.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 900},
		KeyTag:     1111, Algorithm: 13, DigestType: dns.SHA256,
		Digest:     "AABBCCDD",
	}
	dsNSEC3 := &dns.DS{
		Hdr:        dns.RR_Header{Name: "nsec3.uk.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 900},
		KeyTag:     2222, Algorithm: 13, DigestType: dns.SHA256,
		Digest:     "DEADBEEF",
	}

	rootMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
	rootMsg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "uk.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "ns1.nic.uk."},
		dsUK,
	}

	ukMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
	ukMsg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "nsec3.uk.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "ns.junesta.net.uk."},
		dsNSEC3,
	}

	nxMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeNameError}}
	nxMsg.Ns = []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: "nsec3.uk.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 900},
			Ns:      "ns.junesta.net.uk.",
			Mbox:    "hostmaster.junesta.com.",
			Serial:  2026061901,
			Refresh: 14400, Retry: 900, Expire: 2419200, Minttl: 900,
		},
	}

	chain := []ResolutionStep{
		{QType: "A", Nameserver: "198.41.0.4:53", ResponseBytesHex: packHex(t, rootMsg)},
		{QType: "A", Nameserver: "213.248.220.80:53", ResponseBytesHex: packHex(t, ukMsg)},
		{QType: "A", Nameserver: "136.244.99.193:53", ResponseBytesHex: packHex(t, nxMsg)},
	}

	levels := parseDelegationChain(chain)
	if len(levels) != 3 {
		t.Fatalf("want 3 levels, got %d", len(levels))
	}

	if levels[0].zone != "." {
		t.Errorf("level 0: want zone \".\", got %q", levels[0].zone)
	}
	if levels[0].ds != nil {
		t.Errorf("level 0: want nil ds (root), got %v", levels[0].ds)
	}

	if levels[1].zone != "uk." {
		t.Errorf("level 1: want zone \"uk.\", got %q", levels[1].zone)
	}
	if len(levels[1].ds) != 1 || levels[1].ds[0].KeyTag != 1111 {
		t.Errorf("level 1: want DS KeyTag 1111, got %v", levels[1].ds)
	}

	if levels[2].zone != "nsec3.uk." {
		t.Errorf("level 2: want zone \"nsec3.uk.\", got %q", levels[2].zone)
	}
	if len(levels[2].ds) != 1 || levels[2].ds[0].KeyTag != 2222 {
		t.Errorf("level 2: want DS KeyTag 2222, got %v", levels[2].ds)
	}
	if levels[2].resp.Rcode != dns.RcodeNameError {
		t.Errorf("level 2: want NXDOMAIN rcode, got %d", levels[2].resp.Rcode)
	}
}

func TestParseDelegationChain_AllDNSKEYSteps(t *testing.T) {
	// When the user queries for DNSKEY, all iterative steps have QType="DNSKEY".
	// parseDelegationChain must process them normally (no special filtering).
	dsUK := &dns.DS{
		Hdr:    dns.RR_Header{Name: "uk.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 900},
		KeyTag: 1111, Algorithm: 13, DigestType: dns.SHA256, Digest: "AABB",
	}
	rootMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
	rootMsg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "uk.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "ns1.nic.uk."},
		dsUK,
	}
	// Final DNSKEY answer from uk. nameserver (NODATA — pretend no DNSKEY in uk.).
	answerMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}}
	answerMsg.Ns = []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: "uk.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 900},
			Ns:      "ns1.nic.uk.",
			Mbox:    "hostmaster.nic.uk.",
			Serial:  2026061901,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minttl:  300,
		},
	}

	chain := []ResolutionStep{
		{QType: "DNSKEY", Nameserver: "198.41.0.4:53", ResponseBytesHex: packHex(t, rootMsg)},
		{QType: "DNSKEY", Nameserver: "213.248.220.80:53", ResponseBytesHex: packHex(t, answerMsg)},
	}

	levels := parseDelegationChain(chain)
	if len(levels) != 2 {
		t.Errorf("want 2 levels (root + uk. NODATA), got %d", len(levels))
	}
	if len(levels) >= 1 && levels[0].zone != "." {
		t.Errorf("levels[0].zone = %q, want \".\"", levels[0].zone)
	}
	if len(levels) >= 2 && levels[1].zone != "uk." {
		t.Errorf("levels[1].zone = %q, want \"uk.\"", levels[1].zone)
	}
}

func TestParseDelegationChain_SkipsEmptyResponseHex(t *testing.T) {
	dsUK := &dns.DS{
		Hdr:    dns.RR_Header{Name: "uk.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 900},
		KeyTag: 1111, Algorithm: 13, DigestType: dns.SHA256, Digest: "AABB",
	}
	rootMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
	rootMsg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "uk.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "ns1.nic.uk."},
		dsUK,
	}
	answerMsg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}}
	answerMsg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "uk.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}},
	}

	chain := []ResolutionStep{
		{QType: "A", Nameserver: "198.41.0.4:53", ResponseBytesHex: packHex(t, rootMsg)},
		// Error step with no response bytes — must be skipped.
		{QType: "A", Nameserver: "198.41.0.4:53", ResponseBytesHex: "", ResponseText: "error: connection refused"},
		{QType: "A", Nameserver: "213.248.220.80:53", ResponseBytesHex: packHex(t, answerMsg)},
	}

	levels := parseDelegationChain(chain)
	if len(levels) != 2 {
		t.Errorf("want 2 levels (empty ResponseBytesHex skipped), got %d", len(levels))
	}
}

// ── Network integration tests ─────────────────────────────────────────────────
// Run with: go test ./internal/dns/ -v
// Skip with: go test ./internal/dns/ -short

// testIANATrustAnchors is the current IANA root KSK (key tag 20326).
// Update when the root KSK rolls over.
var testIANATrustAnchors = []TrustAnchorDS{
	{
		KeyTag:     20326,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	},
}

func runRecursiveValidate(t *testing.T, qname, qtype string) *QueryResponse {
	t.Helper()
	req := &QueryRequest{
		QName: qname,
		QType: qtype,
		Mode:  "recursive",
		Flags: QueryFlags{DO: true, Validate: true},
		TrustAnchorMode: "iana",
		TrustAnchors:    testIANATrustAnchors,
	}
	return execRecursive(req)
}

// validationCases is the table of name/type combinations with expected DNSSEC
// validation outcomes. Add new rows here to register additional test zones.
//
//   true            = SECURE       (chain validates end-to-end)
//   false           = BOGUS        (chain broken or signature fails)
//   "indeterminate" = can't complete (no trust anchor, CD bit, etc.)
//   "insecure"      = signed parent explicitly has no DS for child zone
var validationCases = []struct {
	name  string
	qname string
	qtype string
	want  interface{}
}{
	// ── Should validate as SECURE ──────────────────────────────────────────────
	{"SOA answer for signed zone", "nsec3.uk.", "SOA", true},
	{"NXDOMAIN in NSEC3 zone", "nonexistent.nsec3.uk.", "A", true},
	{"NODATA in NSEC3 zone (type exists at parent, not child)", "dangling-ds.nsec3.uk.", "A", true},
	{"zone served by in-zone server for both parent and child", "dangling-ds.nsec3.uk.", "SOA", true},
	// Shared-nameserver: uk. and co.uk. use the same NS; co.uk. DS is signed by
	// uk. ZSK via an intermediate zone boundary that is not in the referral chain.
	{"SOA for zone whose parent shares nameservers with grandparent", "junesta.co.uk.", "SOA", true},
	// Wildcard NODATA: query matches a wildcard but the type is absent from the
	// wildcard RRset; both NSEC and NSEC3 zones use this proof structure.
	{"wildcard NODATA in NSEC3 zone", "jkjhkjkjh.junesta.com.", "TXT", true},
	// ANY queries: both test servers implement RFC 8482 and return a minimal NOERROR
	// response (no RRSIGs) rather than the full RRset. The chain of trust is
	// verified but the response is not cryptographically provable → indeterminate.
	// If a server ever returns a signed ANY answer, this should become true.
	{"ANY query for signed zone apex (RFC 8482 server)", "junesta.com.", "ANY", "indeterminate"},
	// nsec3.uk. also returns RFC 8482 for ANY, even for non-existent names — so
	// we see NOERROR not NXDOMAIN and can't prove anything about the name.
	{"ANY for non-existent name (RFC 8482 server returns NOERROR)", "nonexistent.nsec3.uk.", "ANY", "indeterminate"},

	// ── Should validate as BOGUS ───────────────────────────────────────────────
	// Add bogus test zones below:

	// ── Should be insecure (signed parent, no DS for child) ───────────────────
	// p.c.je exists (c.je delegates to it) but has no DS in c.je → insecure.
	{"query under unsigned delegation in signed parent zone", "i.p.c.je.", "TXT", "insecure"},
	// ox.junesta.net is signed but junesta.net has no DS for it. The NS directly
	// serves ox.junesta.net records without a referral, so signerZone differs from
	// last.zone and we explicitly fetch the DS. NOERROR + no DS → insecure.
	{"HTTPS in zone served without referral and no parent DS", "polecat.ox.junesta.net.", "HTTPS", "insecure"},

	// ── Should be indeterminate (can't complete) ───────────────────────────────
	// Add indeterminate test zones below:
}

func TestIntegration_Validation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration tests (-short)")
	}
	for _, tc := range validationCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := runRecursiveValidate(t, tc.qname, tc.qtype)
			if resp.DNSSECValid != tc.want {
				var notes []string
				for _, s := range resp.ResolutionChain {
					if s.StepNote != "" {
						notes = append(notes, fmt.Sprintf("  [%s %s @ %s] %s", s.QType, s.QName, s.Nameserver, s.StepNote))
					}
				}
				t.Errorf("%s %s: DNSSECValid = %v, want %v (%d steps)\n%s",
					tc.qname, tc.qtype, resp.DNSSECValid, tc.want,
					len(resp.ResolutionChain), strings.Join(notes, "\n"))
			}
		})
	}
}

// TestIntegration_ZoneTrustAnchor verifies that supplying caller DS records for a
// zone with no parent DS upgrades validation from "insecure" to true (SECURE).
// The test queries for polecat.ox.junesta.net HTTPS, which is in a signed zone
// whose parent (junesta.net) has no DS → normally "insecure". We fetch the zone's
// actual DNSKEY, compute the DS, then supply it as a ZoneTrustAnchor and expect
// the result to be true (SECURE, using caller-supplied trust anchor).
func TestIntegration_ZoneTrustAnchor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration tests (-short)")
	}

	// Step 1: confirm the baseline is "insecure" without a caller-supplied DS.
	baseline := runRecursiveValidate(t, "polecat.ox.junesta.net.", "HTTPS")
	if baseline.DNSSECValid != "insecure" {
		t.Skipf("baseline not insecure (got %v) — zone may have acquired a parent DS; skipping zone trust anchor test", baseline.DNSSECValid)
	}

	// Step 2: fetch the actual DNSKEY for ox.junesta.net. and compute the DS.
	// We use a plain recursive query (no DNSSEC validation needed here).
	dnskeyReq := &QueryRequest{
		QName: "ox.junesta.net.",
		QType: "DNSKEY",
		Mode:  "recursive",
		Flags: QueryFlags{DO: true},
	}
	dnskeyResp := execRecursive(dnskeyReq)
	if dnskeyResp.Error != "" {
		t.Fatalf("DNSKEY fetch error: %s", dnskeyResp.Error)
	}

	// Parse DNSKEY records from the response text and compute DS.
	// Use miekg/dns to parse the response wire data from the last step.
	var zoneDS []TrustAnchorDS
	for i := len(dnskeyResp.ResolutionChain) - 1; i >= 0; i-- {
		step := dnskeyResp.ResolutionChain[i]
		if step.ResponseBytesHex == "" {
			continue
		}
		b, err := hex.DecodeString(step.ResponseBytesHex)
		if err != nil || len(b) == 0 {
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(b); err != nil || msg.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range msg.Answer {
			key, ok := rr.(*dns.DNSKEY)
			if !ok || key.Flags&(1<<8) == 0 { // only KSK (flags bit 8 = SEP)
				continue
			}
			ds := key.ToDS(dns.SHA256)
			if ds == nil {
				continue
			}
			zoneDS = append(zoneDS, TrustAnchorDS{
				KeyTag:     ds.KeyTag,
				Algorithm:  ds.Algorithm,
				DigestType: ds.DigestType,
				Digest:     strings.ToUpper(ds.Digest),
			})
		}
		if len(zoneDS) > 0 {
			break
		}
	}

	if len(zoneDS) == 0 {
		t.Skip("could not compute DS from ox.junesta.net DNSKEY — skipping zone trust anchor test")
	}
	t.Logf("computed %d DS record(s) for ox.junesta.net", len(zoneDS))

	// Step 3: run validation with the caller-supplied DS — expect SECURE.
	req := &QueryRequest{
		QName:           "polecat.ox.junesta.net.",
		QType:           "HTTPS",
		Mode:            "recursive",
		Flags:           QueryFlags{DO: true, Validate: true},
		TrustAnchorMode: "iana",
		TrustAnchors:    testIANATrustAnchors,
		ZoneTrustAnchors: []ZoneTrustAnchor{
			{Zone: "ox.junesta.net.", DS: zoneDS},
		},
	}
	resp := execRecursive(req)
	if resp.DNSSECValid != true {
		var notes []string
		for _, s := range resp.ResolutionChain {
			if s.StepNote != "" {
				notes = append(notes, fmt.Sprintf("  [%s %s @ %s] %s", s.QType, s.QName, s.Nameserver, s.StepNote))
			}
		}
		t.Errorf("polecat.ox.junesta.net HTTPS with caller-supplied DS: DNSSECValid = %v, want true (%d steps)\n%s",
			resp.DNSSECValid, len(resp.ResolutionChain), strings.Join(notes, "\n"))
	}
}

// ── canonicalNameLess ─────────────────────────────────────────────────────────

func TestCanonicalNameLess_SameZone(t *testing.T) {
	cases := []struct{ a, b string; want bool }{
		{"a.example.com.", "b.example.com.", true},
		{"b.example.com.", "a.example.com.", false},
		{"example.com.", "a.example.com.", true},  // zone apex < any child
		{"a.example.com.", "example.com.", false},
		{"*.example.com.", "a.example.com.", true}, // * (0x2a) < a (0x61)
	}
	for _, tc := range cases {
		if got := canonicalNameLess(tc.a, tc.b); got != tc.want {
			t.Errorf("canonicalNameLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// ── nsecCoversName ────────────────────────────────────────────────────────────

func TestNSECCoversName_Normal(t *testing.T) {
	// NSEC at a.example.com. with next = c.example.com. covers b.example.com.
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
		NextDomain: "c.example.com.",
		TypeBitMap: []uint16{dns.TypeA},
	}
	if !nsecCoversName(n, "b.example.com.") {
		t.Error("expected b.example.com. to be covered by [a.example.com., c.example.com.)")
	}
	// Endpoints are not covered (strict inequality).
	if nsecCoversName(n, "a.example.com.") {
		t.Error("owner name should not be covered")
	}
	if nsecCoversName(n, "c.example.com.") {
		t.Error("next name should not be covered")
	}
}

func TestNSECCoversName_WrapAround(t *testing.T) {
	// Last NSEC in zone: owner > next (wraps to zone apex).
	// [z.example.com., a.example.com.) covers names > z or < a — e.g. zz.example.com.
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "z.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
		NextDomain: "a.example.com.",
	}
	if !nsecCoversName(n, "zz.example.com.") {
		t.Error("expected zz.example.com. to be covered by wrap-around [z, a)")
	}
	// b.example.com. is in (a, z) — NOT covered by wrap-around.
	if nsecCoversName(n, "b.example.com.") {
		t.Error("b.example.com. should not be covered by wrap-around [z, a)")
	}
}

// ── NSEC3.Match and NSEC3.Cover (via miekg built-ins) ────────────────────────

func TestNSEC3Matches_HitAndMiss(t *testing.T) {
	name := "example.com."
	hash := dns.HashName(name, 1, 0, "")
	n := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: hash + ".example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
		Hash:       1,
		Iterations: 0,
		Salt:       "",
	}
	if !n.Match(name) {
		t.Errorf("expected Match(%q) = true, got false (hash=%s)", name, hash)
	}
	if n.Match("other.example.com.") {
		t.Error("expected Match(other.example.com.) = false")
	}
}

func TestNSEC3Covers_Normal(t *testing.T) {
	ha, iter, salt := uint8(1), uint16(0), ""
	// Compute hashes for three names and sort them to get a known ordering.
	type nh struct{ name, hash string }
	nhs := []nh{
		{"aaa.example.com.", dns.HashName("aaa.example.com.", ha, iter, salt)},
		{"mmm.example.com.", dns.HashName("mmm.example.com.", ha, iter, salt)},
		{"zzz.example.com.", dns.HashName("zzz.example.com.", ha, iter, salt)},
	}
	sort.Slice(nhs, func(i, j int) bool { return nhs[i].hash < nhs[j].hash })

	// Build NSEC3 covering [min, max) — middle hash should be covered.
	n := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: nhs[0].hash + ".example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
		Hash:       ha,
		Iterations: iter,
		Salt:       salt,
		NextDomain: nhs[2].hash,
	}
	if !n.Cover(nhs[1].name) {
		t.Errorf("expected %s (hash %s) to be covered by [%s, %s)", nhs[1].name, nhs[1].hash, nhs[0].hash, nhs[2].hash)
	}
	// miekg Cover() uses a half-open range [owner, next) — the owner hash itself
	// is also covered (Cover returns true when nameHash == ownerHash).
	if !n.Cover(nhs[0].name) {
		t.Errorf("expected owner name %s to be covered by miekg Cover() (range is [owner, next))", nhs[0].name)
	}
	// The next hash should NOT be covered (strict upper bound).
	if n.Cover(nhs[2].name) {
		t.Errorf("next-domain name %s should not be covered (strict upper bound)", nhs[2].name)
	}
}

func TestNSEC3Covers_WrapAround(t *testing.T) {
	ha, iter, salt := uint8(1), uint16(0), ""
	type nh struct{ name, hash string }
	nhs := []nh{
		{"aaa.example.com.", dns.HashName("aaa.example.com.", ha, iter, salt)},
		{"mmm.example.com.", dns.HashName("mmm.example.com.", ha, iter, salt)},
		{"zzz.example.com.", dns.HashName("zzz.example.com.", ha, iter, salt)},
	}
	sort.Slice(nhs, func(i, j int) bool { return nhs[i].hash < nhs[j].hash })

	// Wrap-around NSEC3: owner = max, next = min — covers things OUTSIDE (min, max).
	n := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: nhs[2].hash + ".example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
		Hash:       ha,
		Iterations: iter,
		Salt:       salt,
		NextDomain: nhs[0].hash, // next < owner → wrap-around
	}
	// Middle name (hash between min and max) is NOT covered by wrap-around [max, min).
	if n.Cover(nhs[1].name) {
		t.Errorf("middle name %s should NOT be covered by wrap-around NSEC3 [%s, %s)",
			nhs[1].name, nhs[2].hash, nhs[0].hash)
	}
}

// ── verifyNSECDenial ──────────────────────────────────────────────────────────

func makeNSEC(owner, next string, types ...uint16) *dns.NSEC {
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: dns.Fqdn(next),
		TypeBitMap: types,
	}
}

func TestVerifyNSECDenial_NXDOMAIN_Valid(t *testing.T) {
	// Zone: example.com. with names {example.com., a.example.com., z.example.com.}
	// qname = nonexistent.example.com. falls in (a, z) canonically.
	// Wildcard *.example.com. is covered by [example.com., a.example.com.).
	nsecs := []*dns.NSEC{
		makeNSEC("example.com.", "a.example.com.", dns.TypeNS, dns.TypeSOA),
		makeNSEC("a.example.com.", "z.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, note := verifyNSECDenial("nonexistent.example.com.", dns.TypeA, dns.RcodeNameError, nsecs)
	if !ok {
		t.Errorf("expected ok=true, got note: %s", note)
	}
}

func TestVerifyNSECDenial_NXDOMAIN_NotCovered(t *testing.T) {
	// NSEC range [a, b) does NOT cover nonexistent.example.com. (which > b).
	nsecs := []*dns.NSEC{
		makeNSEC("example.com.", "a.example.com.", dns.TypeNS, dns.TypeSOA),
		makeNSEC("a.example.com.", "b.example.com.", dns.TypeA),
	}
	ok, _ := verifyNSECDenial("nonexistent.example.com.", dns.TypeA, dns.RcodeNameError, nsecs)
	if ok {
		t.Error("expected ok=false: no NSEC covers nonexistent.example.com.")
	}
}

func TestVerifyNSECDenial_NXDOMAIN_MissingWildcard(t *testing.T) {
	// NSEC covers qname but no wildcard proof.
	nsecs := []*dns.NSEC{
		makeNSEC("a.example.com.", "z.example.com.", dns.TypeA),
		// No NSEC covering *.example.com.
	}
	ok, _ := verifyNSECDenial("nonexistent.example.com.", dns.TypeA, dns.RcodeNameError, nsecs)
	if ok {
		t.Error("expected ok=false: wildcard non-existence not proven")
	}
}

func TestVerifyNSECDenial_NODATA_Valid(t *testing.T) {
	nsecs := []*dns.NSEC{
		makeNSEC("foo.example.com.", "g.example.com.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, note := verifyNSECDenial("foo.example.com.", dns.TypeA, dns.RcodeSuccess, nsecs)
	if !ok {
		t.Errorf("expected ok=true, got: %s", note)
	}
}

func TestVerifyNSECDenial_NODATA_TypePresent(t *testing.T) {
	// A is in the bitmap — type exists, so NODATA proof fails.
	nsecs := []*dns.NSEC{makeNSEC("foo.example.com.", "g.example.com.", dns.TypeA)}
	ok, _ := verifyNSECDenial("foo.example.com.", dns.TypeA, dns.RcodeSuccess, nsecs)
	if ok {
		t.Error("expected ok=false: A is in bitmap")
	}
}

func TestVerifyNSECDenial_NODATA_CNAMEPresent(t *testing.T) {
	// CNAME in bitmap — RFC 6840 §4.3: validator must reject this as NODATA proof.
	nsecs := []*dns.NSEC{makeNSEC("foo.example.com.", "g.example.com.", dns.TypeCNAME, dns.TypeRRSIG)}
	ok, _ := verifyNSECDenial("foo.example.com.", dns.TypeA, dns.RcodeSuccess, nsecs)
	if ok {
		t.Error("expected ok=false: CNAME in bitmap (RFC 6840 §4.3)")
	}
}

func TestVerifyNSECDenial_AncestorDelegation(t *testing.T) {
	// NS=1 SOA=0 → ancestor delegation record, must not prove NODATA (RFC 6840 §4.1).
	nsecs := []*dns.NSEC{makeNSEC("foo.example.com.", "g.example.com.", dns.TypeNS, dns.TypeRRSIG)}
	ok, _ := verifyNSECDenial("foo.example.com.", dns.TypeA, dns.RcodeSuccess, nsecs)
	if ok {
		t.Error("expected ok=false: ancestor delegation NSEC must not prove NODATA")
	}
}

// ── verifyNSEC3Denial ─────────────────────────────────────────────────────────

func makeNSEC3(zone string, ha uint8, iter uint16, salt string, name string, flags uint8, types ...uint16) *dns.NSEC3 {
	ownerHash := dns.HashName(name, ha, iter, salt)
	return &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: ownerHash + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       ha,
		Flags:      flags,
		Iterations: iter,
		Salt:       salt,
		TypeBitMap: types,
	}
}

// base32HexAlphabet is the extended-hex alphabet used by NSEC3 (RFC 4648 §7).
const base32HexAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// incrBase32Hex increments a base32hex string by 1 in big-endian order.
func incrBase32Hex(h string) string {
	b := []byte(strings.ToUpper(h))
	for i := len(b) - 1; i >= 0; i-- {
		idx := strings.IndexByte(base32HexAlphabet, b[i])
		if idx < 31 {
			b[i] = base32HexAlphabet[idx+1]
			return string(b)
		}
		b[i] = '0' // carry
	}
	return strings.Repeat("0", len(h)) // overflow wraps to zero
}

// decrBase32Hex decrements a base32hex string by 1 in big-endian order.
func decrBase32Hex(h string) string {
	b := []byte(strings.ToUpper(h))
	for i := len(b) - 1; i >= 0; i-- {
		idx := strings.IndexByte(base32HexAlphabet, b[i])
		if idx > 0 {
			b[i] = base32HexAlphabet[idx-1]
			return string(b)
		}
		b[i] = 'V' // borrow
	}
	return strings.Repeat("V", len(h)) // underflow wraps to max
}

// makeNSEC3Covering builds an NSEC3 whose range [decr(H(name)), incr(H(name)))
// is guaranteed to cover name regardless of hash ordering.
func makeNSEC3Covering(zone string, ha uint8, iter uint16, salt, name string, flags uint8) *dns.NSEC3 {
	h := dns.HashName(name, ha, iter, salt)
	return &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: decrBase32Hex(h) + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       ha,
		Flags:      flags,
		Iterations: iter,
		Salt:       salt,
		NextDomain: incrBase32Hex(h),
	}
}

func TestVerifyNSEC3Denial_NODATA_Valid(t *testing.T) {
	ha, iter, salt := uint8(1), uint16(0), ""
	// NSEC3 matching qname with A absent, DS present.
	n := makeNSEC3("example.com.", ha, iter, salt, "foo.example.com.", 0, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC3)
	ok, note := verifyNSEC3Denial("foo.example.com.", dns.TypeA, dns.RcodeSuccess, []*dns.NSEC3{n})
	if !ok {
		t.Errorf("expected ok=true, got: %s", note)
	}
}

func TestVerifyNSEC3Denial_NODATA_TypePresent(t *testing.T) {
	ha, iter, salt := uint8(1), uint16(0), ""
	n := makeNSEC3("example.com.", ha, iter, salt, "foo.example.com.", 0, dns.TypeA)
	ok, _ := verifyNSEC3Denial("foo.example.com.", dns.TypeA, dns.RcodeSuccess, []*dns.NSEC3{n})
	if ok {
		t.Error("expected ok=false: A in bitmap")
	}
}

func TestVerifyNSEC3Denial_NODATA_CNAMEPresent(t *testing.T) {
	ha, iter, salt := uint8(1), uint16(0), ""
	// RFC 6840 §4.3: CNAME in bitmap → validator must reject.
	n := makeNSEC3("example.com.", ha, iter, salt, "foo.example.com.", 0, dns.TypeCNAME, dns.TypeRRSIG)
	ok, _ := verifyNSEC3Denial("foo.example.com.", dns.TypeA, dns.RcodeSuccess, []*dns.NSEC3{n})
	if ok {
		t.Error("expected ok=false: CNAME in bitmap (RFC 6840 §4.3)")
	}
}

func TestVerifyNSEC3Denial_ENT(t *testing.T) {
	ha, iter, salt := uint8(1), uint16(0), ""
	// Empty type bitmap = empty non-terminal (RFC 6840 §6.4).
	n := makeNSEC3("example.com.", ha, iter, salt, "foo.example.com.", 0 /* no types */)
	ok, note := verifyNSEC3Denial("foo.example.com.", dns.TypeA, dns.RcodeSuccess, []*dns.NSEC3{n})
	if !ok {
		t.Errorf("expected ok=true for ENT (empty bitmap), got: %s", note)
	}
}

func TestVerifyNSEC3Denial_ParamMismatch(t *testing.T) {
	ha, salt := uint8(1), ""
	n1 := makeNSEC3("example.com.", ha, 0, salt, "foo.example.com.", 0, dns.TypeA)
	n2 := makeNSEC3("example.com.", ha, 5, salt, "bar.example.com.", 0, dns.TypeMX) // different iterations
	ok, note := verifyNSEC3Denial("foo.example.com.", dns.TypeA, dns.RcodeSuccess, []*dns.NSEC3{n1, n2})
	if ok {
		t.Error("expected ok=false for parameter mismatch")
	}
	if !strings.HasPrefix(note, "indeterminate:") {
		t.Errorf("expected indeterminate: prefix, got: %s", note)
	}
}

func TestVerifyNSEC3Denial_NXDOMAIN_Valid(t *testing.T) {
	// Construct closest encloser proof for nonexistent.example.com.:
	//   CE = example.com.  (matches NSEC3)
	//   next-closer = nonexistent.example.com. (covered by NSEC3)
	//   wildcard *.example.com. (covered by NSEC3)
	ha, iter, salt := uint8(1), uint16(0), ""
	zone := "example.com."
	ncName := "nonexistent.example.com."

	// NSEC3 matching CE; tiny NextDomain range so it doesn't accidentally cover NC or WC.
	ceN := makeNSEC3(zone, ha, iter, salt, zone, 0, dns.TypeNS, dns.TypeSOA)
	ceN.NextDomain = incrBase32Hex(ceN.Hdr.Name[:strings.Index(ceN.Hdr.Name, ".")])

	// NSEC3 guaranteed to cover the next-closer (nonexistent.example.com.)
	ncCover := makeNSEC3Covering(zone, ha, iter, salt, ncName, 0)
	if !ncCover.Cover(ncName) {
		t.Fatal("makeNSEC3Covering produced a record that doesn't cover ncName (internal error)")
	}

	// NSEC3 guaranteed to cover the wildcard (*.example.com.)
	wcCover := makeNSEC3Covering(zone, ha, iter, salt, "*.example.com.", 0)
	if !wcCover.Cover("*.example.com.") {
		t.Fatal("makeNSEC3Covering produced a record that doesn't cover *.example.com. (internal error)")
	}

	nsec3s := []*dns.NSEC3{ceN, ncCover, wcCover}
	ok, note := verifyNSEC3Denial(ncName, dns.TypeA, dns.RcodeNameError, nsec3s)
	if !ok {
		t.Errorf("expected ok=true for valid closest encloser proof, got: %s", note)
	}
}

func TestVerifyNSEC3Denial_NXDOMAIN_MissingWildcardCoverage(t *testing.T) {
	ha, iter, salt := uint8(1), uint16(0), ""
	zone := "example.com."
	ncName := "nonexistent.example.com."

	ceN := makeNSEC3(zone, ha, iter, salt, zone, 0, dns.TypeNS, dns.TypeSOA)
	ceN.NextDomain = incrBase32Hex(ceN.Hdr.Name[:strings.Index(ceN.Hdr.Name, ".")])

	ncCover := makeNSEC3Covering(zone, ha, iter, salt, ncName, 0)

	// No wildcard-covering NSEC3 — proof must be incomplete.
	// Ensure ncCover doesn't accidentally cover *.example.com. by checking first.
	if ncCover.Cover("*.example.com.") {
		t.Skip("ncCover hash range accidentally covers wildcard; test not meaningful")
	}

	nsec3s := []*dns.NSEC3{ceN, ncCover}
	ok, _ := verifyNSEC3Denial(ncName, dns.TypeA, dns.RcodeNameError, nsec3s)
	if ok {
		t.Error("expected ok=false: wildcard coverage missing")
	}
}

func TestVerifyNSEC3Denial_OptOut_DS(t *testing.T) {
	// §8.6: no matching NSEC3 for qname, closest encloser proof exists with opt-out
	// flag set on the covering NSEC3 → indeterminate for DS qtype.
	ha, iter, salt := uint8(1), uint16(0), ""
	zone := "example.com."
	ncName := "child.example.com."

	ceN := makeNSEC3(zone, ha, iter, salt, zone, 0, dns.TypeNS, dns.TypeSOA)
	ceN.NextDomain = incrBase32Hex(ceN.Hdr.Name[:strings.Index(ceN.Hdr.Name, ".")])

	// Opt-out covering NSEC3 for next-closer (Flags=1).
	ncCover := makeNSEC3Covering(zone, ha, iter, salt, ncName, 1 /* opt-out */)
	if !ncCover.Cover(ncName) {
		t.Fatal("makeNSEC3Covering produced a record that doesn't cover ncName (internal error)")
	}

	nsec3s := []*dns.NSEC3{ceN, ncCover}
	ok, note := verifyNSEC3Denial(ncName, dns.TypeDS, dns.RcodeSuccess, nsec3s)
	if ok {
		t.Error("expected ok=false for opt-out case")
	}
	if !strings.HasPrefix(note, "indeterminate:") {
		t.Errorf("expected indeterminate: prefix for opt-out, got: %s", note)
	}
}

// ── wildcard NODATA ───────────────────────────────────────────────────────────

func TestVerifyNSECDenial_WildcardNODATA_Valid(t *testing.T) {
	// Mirrors the junesta.com. scenario: qname doesn't exist as a real name
	// (covered by an NSEC between two real names), but *.example.com. exists with
	// A, AAAA in its bitmap — TXT is absent, so wildcard NODATA is proven.
	//
	// Canonical ordering for *.example.com. NSEC:
	//   owner = *.example.com. (label "*" has ASCII 42)
	//   ASCII: * (42) < a (97), so *.example.com. < aaa.example.com.
	//
	// Covering NSEC: owner < qname < next
	//   m.example.com. → z.example.com. covers jkjhkjkjh.example.com.
	//   (m < j? No... let's just use a wide range: aaa → zzz)
	qname := "jkjhkjkjh.example.com."
	nsecs := []*dns.NSEC{
		// Wildcard NSEC: *.example.com. exists with A, AAAA but NOT TXT.
		makeNSEC("*.example.com.", "b.example.com.", dns.TypeA, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC),
		// Covering NSEC: proves jkjhkjkjh.example.com. doesn't exist as a real name.
		makeNSEC("aaa.example.com.", "zzz.example.com.", dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, note := verifyNSECDenial(qname, dns.TypeTXT, dns.RcodeSuccess, nsecs)
	if !ok {
		t.Errorf("expected ok=true for wildcard NODATA, got: %s", note)
	}
	if !strings.Contains(note, "wildcard NODATA") {
		t.Errorf("expected note to mention wildcard NODATA, got: %s", note)
	}
}

func TestVerifyNSECDenial_WildcardNODATA_TypePresent(t *testing.T) {
	// TXT IS in the wildcard bitmap — not NODATA.
	qname := "jkjhkjkjh.example.com."
	nsecs := []*dns.NSEC{
		makeNSEC("*.example.com.", "b.example.com.", dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC),
		makeNSEC("aaa.example.com.", "zzz.example.com.", dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, _ := verifyNSECDenial(qname, dns.TypeTXT, dns.RcodeSuccess, nsecs)
	if ok {
		t.Error("expected ok=false: TXT is in wildcard bitmap")
	}
}

func TestVerifyNSECDenial_WildcardNODATA_MissingCoverage(t *testing.T) {
	// Wildcard NSEC found with type absent, but no NSEC covers qname → incomplete proof.
	qname := "jkjhkjkjh.example.com."
	nsecs := []*dns.NSEC{
		// Wildcard exists but doesn't cover qname (no coverage NSEC present).
		makeNSEC("*.example.com.", "b.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
		// Only an unrelated NSEC that doesn't cover qname.
		makeNSEC("zzz.example.com.", "zzza.example.com.", dns.TypeRRSIG, dns.TypeNSEC),
	}
	ok, _ := verifyNSECDenial(qname, dns.TypeTXT, dns.RcodeSuccess, nsecs)
	if ok {
		t.Error("expected ok=false: no NSEC covers qname")
	}
}

func TestVerifyNSEC3Denial_WildcardNODATA_Valid(t *testing.T) {
	ha, iter, salt := uint8(1), uint16(0), ""
	zone := "example.com."
	qname := "nonexistent.example.com."

	// CE = example.com. (matching NSEC3).
	ceN := makeNSEC3(zone, ha, iter, salt, zone, 0, dns.TypeNS, dns.TypeSOA)
	ceN.NextDomain = incrBase32Hex(ceN.Hdr.Name[:strings.Index(ceN.Hdr.Name, ".")])

	// Covering NSEC3 for next-closer (nonexistent.example.com.).
	ncCover := makeNSEC3Covering(zone, ha, iter, salt, qname, 0)

	// Matching NSEC3 at *.example.com. with A in bitmap but NOT TXT.
	wildN := makeNSEC3(zone, ha, iter, salt, "*.example.com.", 0, dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3)

	nsec3s := []*dns.NSEC3{ceN, ncCover, wildN}
	ok, note := verifyNSEC3Denial(qname, dns.TypeTXT, dns.RcodeSuccess, nsec3s)
	if !ok {
		t.Errorf("expected ok=true for NSEC3 wildcard NODATA, got: %s", note)
	}
	if !strings.Contains(note, "wildcard NODATA") {
		t.Errorf("expected note to mention wildcard NODATA, got: %s", note)
	}
}

func TestVerifyNSEC3Denial_WildcardNODATA_TypePresent(t *testing.T) {
	ha, iter, salt := uint8(1), uint16(0), ""
	zone := "example.com."
	qname := "nonexistent.example.com."

	ceN := makeNSEC3(zone, ha, iter, salt, zone, 0, dns.TypeNS, dns.TypeSOA)
	ceN.NextDomain = incrBase32Hex(ceN.Hdr.Name[:strings.Index(ceN.Hdr.Name, ".")])
	ncCover := makeNSEC3Covering(zone, ha, iter, salt, qname, 0)
	// TXT IS in the wildcard bitmap.
	wildN := makeNSEC3(zone, ha, iter, salt, "*.example.com.", 0, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC3)

	nsec3s := []*dns.NSEC3{ceN, ncCover, wildN}
	ok, _ := verifyNSEC3Denial(qname, dns.TypeTXT, dns.RcodeSuccess, nsec3s)
	if ok {
		t.Error("expected ok=false: TXT is in wildcard NSEC3 bitmap")
	}
}

// ── isWildcardAnswer ──────────────────────────────────────────────────────────

func TestIsWildcardAnswer(t *testing.T) {
	// Labels < CountLabel(owner) → wildcard.
	sig := &dns.RRSIG{
		Hdr:    dns.RR_Header{Name: "foo.example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		Labels: 2, // *.example.com. expanded to foo.example.com.; labels count = 2
	}
	respWild := &dns.Msg{Answer: []dns.RR{sig}}
	if !isWildcardAnswer(respWild) {
		t.Error("expected isWildcardAnswer=true when Labels < label count")
	}

	// Labels == CountLabel(owner) → not wildcard.
	sigNorm := &dns.RRSIG{
		Hdr:    dns.RR_Header{Name: "foo.example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		Labels: 3, // matches label count of foo.example.com. (foo, example, com)
	}
	respNorm := &dns.Msg{Answer: []dns.RR{sigNorm}}
	if isWildcardAnswer(respNorm) {
		t.Error("expected isWildcardAnswer=false for normal answer")
	}
}

// ── TC=1 UDP fallback to TCP ──────────────────────────────────────────────────

// TestExchangeWithTCPFallback_Truncated verifies that exchangeWithTCPFallback
// retries over TCP when the UDP response has TC=1, and that the returned note
// says so. It spins up a fake UDP server that always sets TC=1 and a fake TCP
// server that returns a normal NOERROR response.
func TestExchangeWithTCPFallback_Truncated(t *testing.T) {
	answer := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.2.3.4"),
	}

	// UDP handler: always reply with TC=1 and an empty answer.
	udpMux := dns.NewServeMux()
	udpMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	udpSrv := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: udpMux}
	udpStarted := make(chan struct{})
	udpSrv.NotifyStartedFunc = func() { close(udpStarted) }
	go func() { _ = udpSrv.ListenAndServe() }()
	<-udpStarted
	defer udpSrv.Shutdown()
	addr := udpSrv.PacketConn.LocalAddr().String()

	// TCP handler on the same port: reply normally with one A record.
	tcpMux := dns.NewServeMux()
	tcpMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{answer}
		_ = w.WriteMsg(m)
	})
	tcpSrv := &dns.Server{Addr: addr, Net: "tcp", Handler: tcpMux}
	tcpStarted := make(chan struct{})
	tcpSrv.NotifyStartedFunc = func() { close(tcpStarted) }
	go func() { _ = tcpSrv.ListenAndServe() }()
	<-tcpStarted
	defer tcpSrv.Shutdown()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	resp, note, err := exchangeWithTCPFallback(q, addr)
	if err != nil {
		t.Fatalf("exchangeWithTCPFallback: %v", err)
	}
	if note == "" {
		t.Error("expected a TC fallback note, got empty string")
	}
	if !strings.Contains(note, "TC=1") {
		t.Errorf("TC fallback note does not mention TC=1: %q", note)
	}
	if !strings.Contains(note, "TCP") {
		t.Errorf("TC fallback note does not mention TCP: %q", note)
	}
	if len(resp.Answer) != 1 {
		t.Errorf("expected TCP response with 1 answer, got %d", len(resp.Answer))
	}
}

// TestExchangeWithTCPFallback_NoTruncation verifies that when UDP responds
// without TC=1, no TCP retry is made and the note is empty.
func TestExchangeWithTCPFallback_NoTruncation(t *testing.T) {
	answer := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.2.3.4"),
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{answer}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ListenAndServe() }()
	<-started
	defer srv.Shutdown()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	resp, note, err := exchangeWithTCPFallback(q, srv.PacketConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("exchangeWithTCPFallback: %v", err)
	}
	if note != "" {
		t.Errorf("expected empty note for non-truncated response, got %q", note)
	}
	if len(resp.Answer) != 1 {
		t.Errorf("expected 1 answer, got %d", len(resp.Answer))
	}
}

// ── GAP 1: RRSIG validity period (RFC 4034 §3.1.5) ───────────────────────────

func TestVerifySig_Valid(t *testing.T) {
	ksk, priv := makeKSK(t, "example.com.")
	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}
	sig := signRRset(t, ksk, priv, []dns.RR{a})
	if err := verifySig(sig, ksk, []dns.RR{a}); err != nil {
		t.Errorf("verifySig for valid RRSIG: want nil, got %v", err)
	}
}

func TestVerifySig_Expired(t *testing.T) {
	ksk, priv := makeKSK(t, "example.com.")
	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}
	sig := signRRset(t, ksk, priv, []dns.RR{a})
	// Force the RRSIG to be expired.
	sig.Expiration = uint32(time.Now().Add(-2 * time.Hour).Unix())
	sig.Inception = uint32(time.Now().Add(-3 * time.Hour).Unix())
	if err := verifySig(sig, ksk, []dns.RR{a}); err == nil {
		t.Error("verifySig for expired RRSIG: want error, got nil")
	}
}

func TestVerifySig_NotYetValid(t *testing.T) {
	ksk, priv := makeKSK(t, "example.com.")
	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}
	sig := signRRset(t, ksk, priv, []dns.RR{a})
	// Force the RRSIG into the future.
	sig.Inception = uint32(time.Now().Add(1 * time.Hour).Unix())
	sig.Expiration = uint32(time.Now().Add(25 * time.Hour).Unix())
	if err := verifySig(sig, ksk, []dns.RR{a}); err == nil {
		t.Error("verifySig for not-yet-valid RRSIG: want error, got nil")
	}
}

// ── GAP 2: ancestor-delegation guard in NXDOMAIN wildcard proof ───────────────

// TestVerifyNSECDenial_NXDOMAIN_WildcardAncestorDelegation verifies that a
// wildcard-covering NSEC at a zone cut (NS=1, SOA=0) is rejected per RFC 6840 §4.1.
func TestVerifyNSECDenial_NXDOMAIN_WildcardAncestorDelegation(t *testing.T) {
	// NSEC covers qname (proves the name doesn't exist).
	cover := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "z.example.com.",
		TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG},
	}
	// Wildcard-covering NSEC is a delegation NSEC (NS=1, SOA=0) — from parent zone.
	wcDelegation := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "!.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "b.example.com.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG}, // NS present, SOA absent → delegation
	}
	// wcDelegation covers "*.example.com." in canonical order ("!" < "*" < "b").
	ok, note := verifyNSECDenial("foo.example.com.", dns.TypeA, dns.RcodeNameError, []*dns.NSEC{cover, wcDelegation})
	if ok {
		t.Errorf("expected BOGUS when wildcard NSEC is ancestor delegation, got ok=true note=%q", note)
	}
}

func TestIntegration_NoValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration tests (-short)")
	}
	req := &QueryRequest{
		QName: "nonexistent.nsec3.uk.",
		QType: "A",
		Mode:  "recursive",
		Flags: QueryFlags{DO: true, Validate: false},
	}
	resp := execRecursive(req)
	if resp.DNSSECValid != nil {
		t.Errorf("DNSSECValid: want nil when Validate=false, got %v", resp.DNSSECValid)
	}
}

// TestIntegration_DSAdd verifies that supplying a correct caller DS for a zone
// that already has a parent-published DS (add mode, override=false) still
// produces SECURE — the caller DS is redundant but harmless.
func TestIntegration_DSAdd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration tests (-short)")
	}

	// First fetch the real DS for junesta.net. from its parent zone.
	msg := new(dns.Msg)
	msg.SetQuestion("junesta.net.", dns.TypeDS)
	msg.SetEdns0(1232, true)
	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	// Query one of the .net nameservers.
	var dsRecords []TrustAnchorDS
	netNS := []string{"a.gtld-servers.net:53", "b.gtld-servers.net:53"}
	for _, ns := range netNS {
		r, _, err := c.Exchange(msg, ns)
		if err != nil || r == nil {
			continue
		}
		for _, rr := range r.Ns {
			if ds, ok := rr.(*dns.DS); ok {
				dsRecords = append(dsRecords, TrustAnchorDS{
					KeyTag:     ds.KeyTag,
					Algorithm:  ds.Algorithm,
					DigestType: ds.DigestType,
					Digest:     strings.ToUpper(ds.Digest),
				})
			}
		}
		if len(dsRecords) > 0 {
			break
		}
	}
	if len(dsRecords) == 0 {
		t.Skip("could not fetch junesta.net DS from parent — skipping")
	}

	req := &QueryRequest{
		QName:            "junesta.net.",
		QType:            "SOA",
		Mode:             "recursive",
		Flags:            QueryFlags{DO: true, Validate: true},
		TrustAnchorMode:  "iana",
		ZoneTrustAnchors: []ZoneTrustAnchor{{Zone: "junesta.net.", DS: dsRecords, Override: false}},
	}
	resp := runRecursiveValidate(t, req.QName, req.QType)
	// Re-run with zone trust anchors set.
	resp = execRecursive(req)
	if resp.DNSSECValid != true {
		t.Errorf("DSAdd: DNSSECValid = %v, want true (redundant caller DS should not break validation)", resp.DNSSECValid)
	}
}

// TestIntegration_DSReplace_Bogus verifies that supplying a wrong DS in replace
// mode (override=true) causes validation to return BOGUS — the DNSKEY cannot
// match a bad DS hash.
func TestIntegration_DSReplace_Bogus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration tests (-short)")
	}

	badDS := TrustAnchorDS{
		KeyTag:     9999,
		Algorithm:  13,
		DigestType: 2,
		Digest:     strings.Repeat("FF", 32), // 64 hex chars — valid length but wrong digest
	}
	req := &QueryRequest{
		QName:            "junesta.net.",
		QType:            "SOA",
		Mode:             "recursive",
		Flags:            QueryFlags{DO: true, Validate: true},
		TrustAnchorMode:  "iana",
		ZoneTrustAnchors: []ZoneTrustAnchor{{Zone: "junesta.net.", DS: []TrustAnchorDS{badDS}, Override: true}},
	}
	resp := execRecursive(req)
	if resp.DNSSECValid != false {
		t.Errorf("DSReplace_Bogus: DNSSECValid = %v, want false (wrong caller DS should yield BOGUS)", resp.DNSSECValid)
	}
}
