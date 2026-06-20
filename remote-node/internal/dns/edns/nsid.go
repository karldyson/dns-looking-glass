package edns

import (
	"github.com/miekg/dns"
)

func init() {
	Register(&nsidOption{})
}

type nsidOption struct{}

func (n *nsidOption) Code() uint16 { return dns.EDNS0NSID }

func (n *nsidOption) FromRequest(_ map[string]interface{}) (dns.EDNS0, error) {
	return &dns.EDNS0_NSID{Code: dns.EDNS0NSID}, nil
}

func (n *nsidOption) ParseResponse(opt dns.EDNS0) map[string]interface{} {
	nsid, ok := opt.(*dns.EDNS0_NSID)
	if !ok {
		return nil
	}
	return map[string]interface{}{
		"nsid_hex": nsid.Nsid,
		"nsid_txt": nsidHex2ASCII(nsid.Nsid),
	}
}

// nsidHex2ASCII attempts to decode a hex NSID string into printable ASCII.
func nsidHex2ASCII(hex string) string {
	if len(hex)%2 != 0 {
		return ""
	}
	b := make([]byte, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		hi := hexVal(hex[i])
		lo := hexVal(hex[i+1])
		if hi < 0 || lo < 0 {
			return ""
		}
		c := byte(hi<<4 | lo)
		if c >= 0x20 && c < 0x7f {
			b[i/2] = c
		} else {
			b[i/2] = '.'
		}
	}
	return string(b)
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
