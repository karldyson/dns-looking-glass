package edns

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/miekg/dns"
)

func init() {
	Register(&zoneversionOption{})
}

type zoneversionOption struct{}

func (z *zoneversionOption) Code() uint16 { return dns.EDNS0ZONEVERSION }

// FromRequest sends an empty OPTION-DATA per RFC 9660 §3.1.  The client uses
// an empty option to signal ZONEVERSION support; the server fills in
// LabelCount, Type, and Version in its response.
//
// EDNS0_LOCAL is used instead of EDNS0_ZONEVERSION because miekg/dns's
// EDNS0_ZONEVERSION.pack() always emits the two-byte {LabelCount, Type}
// header even when both are zero, whereas a conforming request must be
// exactly zero bytes in OPTION-DATA.
func (z *zoneversionOption) FromRequest(_ map[string]interface{}) (dns.EDNS0, error) {
	return &dns.EDNS0_LOCAL{Code: dns.EDNS0ZONEVERSION, Data: []byte{}}, nil
}

// ParseResponse decodes one ZONEVERSION option from a server response OPT RR.
//
// Only type 0 (SOA-SERIAL, RFC 9660) is currently defined; additional type
// codes are being specified in a forthcoming internet draft.  Unknown types
// are returned with their raw OPTION-DATA as a hex string so callers can
// inspect them without this code needing to be updated first.
//
// When a server returns multiple ZONEVERSION options (one per zone level on
// the delegation path, e.g. one for "com." and one for "example.com."), the
// ParseAll loop in registry.go will call this once per option, but the
// map it populates is keyed by option code so only the last call's result
// is retained.  All ZONEVERSION values remain visible in the response_text
// field (miekg/dns includes them in its dig-style OPT representation as
// "; ZONEVERSION: …" lines).
func (z *zoneversionOption) ParseResponse(opt dns.EDNS0) map[string]interface{} {
	zv, ok := opt.(*dns.EDNS0_ZONEVERSION)
	if !ok {
		return nil
	}

	out := map[string]interface{}{
		"label_count": int(zv.LabelCount),
		"type":        int(zv.Type),
	}

	switch zv.Type {
	case 0:
		// SOA-SERIAL: VERSION is a 4-byte big-endian unsigned 32-bit SOA serial.
		out["type_name"] = "SOA-SERIAL"
		if len(zv.Version) == 4 {
			out["serial"] = binary.BigEndian.Uint32([]byte(zv.Version))
		}
	default:
		if zv.Type >= 246 {
			out["type_name"] = "private-use"
		} else {
			out["type_name"] = "unassigned"
		}
		if len(zv.Version) > 0 {
			out["version_hex"] = hex.EncodeToString([]byte(zv.Version))
			// 4-byte Version is the same wire footprint as SOA-SERIAL; decode as
			// uint32 so the decimal value is visible (matches kdig "UNKNOWN N" output).
			if len(zv.Version) == 4 {
				out["value"] = binary.BigEndian.Uint32([]byte(zv.Version))
			}
		}
	}

	return out
}
