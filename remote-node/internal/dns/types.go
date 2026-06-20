package dns

// TrustAnchorDS is a DS record used as a DNSSEC trust anchor for the root zone.
// The web server fetches these from https://data.iana.org/root-anchors/root-anchors.xml
// and passes them in the query request so the Go node never needs direct web access.
type TrustAnchorDS struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"` // uppercase hex
}

// ZoneTrustAnchor lets callers supply DS records for a specific zone to test
// pre-publication scenarios without the DS being in the parent zone yet.
//
// Override controls how the caller-supplied DS interacts with the parent DS:
//   - false (default/omitted): add mode — caller DS is accepted alongside any
//     parent-published DS; useful for testing that a new KSK won't break resolution.
//   - true: replace mode — caller DS replaces whatever the parent publishes; the
//     DS RRSIG check against the parent is skipped; useful for testing a complete
//     DS swap before the change is made.
type ZoneTrustAnchor struct {
	Zone     string          `json:"zone"`               // zone name, e.g. "example.com."
	DS       []TrustAnchorDS `json:"ds"`                 // DS records to use as trust anchor
	Override bool            `json:"override,omitempty"` // true = replace parent DS; false = add alongside
}

// QueryRequest is the JSON body received on POST /.
type QueryRequest struct {
	QName            string            `json:"qname"`
	QType            string            `json:"qtype"`
	Mode             string            `json:"mode"`             // "localhost" | "target" | "recursive"
	Nameserver       string            `json:"nameserver"`       // used when mode == "target"
	Port             int               `json:"port"`
	UseTCP           bool              `json:"use_tcp"`
	Flags            QueryFlags        `json:"flags"`
	EDNS             EDNSOptions       `json:"edns"`
	TrustAnchorMode  string            `json:"trust_anchor_mode,omitempty"`  // "iana" | "local"
	TrustAnchors     []TrustAnchorDS   `json:"trust_anchors,omitempty"`      // DS records for "iana" mode
	ZoneTrustAnchors []ZoneTrustAnchor `json:"zone_trust_anchors,omitempty"` // caller-supplied DS per zone
}

// QueryFlags maps to the DNS header flag bits the user can set.
type QueryFlags struct {
	RD       bool `json:"rd"`
	AD       bool `json:"ad"`
	CD       bool `json:"cd"`
	DO       bool `json:"do"`
	Validate bool `json:"validate"` // perform DNSKEY fetch + sig.Verify (recursive mode only)
}

// EDNSOptions carries EDNS0 parameters from the request.
type EDNSOptions struct {
	UDPSize uint16                   `json:"udp_size"`
	Options []map[string]interface{} `json:"options"`
}

// QueryResponse is the JSON body returned from POST /.
type QueryResponse struct {
	DNSQueryMS      float64           `json:"dns_query_ms"`
	Nameserver      string            `json:"nameserver"`
	ResponseText    string            `json:"response_text"`
	QueryBytesHex   string            `json:"query_bytes_hex"`
	ResponseBytesHex string           `json:"response_bytes_hex"`
	NSID            string            `json:"nsid,omitempty"`
	DNSSECValid     interface{}       `json:"dnssec_valid"` // null | true | false | "indeterminate" | "insecure"
	ResolutionChain []ResolutionStep  `json:"resolution_chain"`
	Error           string            `json:"error,omitempty"`
}

// ResolutionStep holds the result of one iterative query in recursive mode.
type ResolutionStep struct {
	Nameserver       string  `json:"nameserver"`                // ip:port
	NameserverName   string  `json:"nameserver_name,omitempty"` // hostname, if known
	QName            string  `json:"qname"`
	QType            string  `json:"qtype"`
	StepNote         string  `json:"step_note,omitempty"` // human-readable annotation for validation steps
	ResponseText     string  `json:"response_text"`
	QueryBytesHex    string  `json:"query_bytes_hex"`
	ResponseBytesHex string  `json:"response_bytes_hex"`
	DNSQueryMS       float64 `json:"dns_query_ms"`
}
