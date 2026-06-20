package edns

import (
	"fmt"

	"github.com/miekg/dns"
)

// Option describes how to build and parse a single EDNS option code.
type Option interface {
	// Code returns the EDNS option code this implementation handles.
	Code() uint16
	// FromRequest builds a dns.EDNS0 value from the raw JSON params for this option.
	FromRequest(params map[string]interface{}) (dns.EDNS0, error)
	// ParseResponse extracts structured data from a response EDNS0 value.
	ParseResponse(opt dns.EDNS0) map[string]interface{}
}

var registry = map[uint16]Option{}

// Register adds an Option implementation to the global registry.
func Register(o Option) {
	registry[o.Code()] = o
}

// Build converts a slice of raw JSON option objects into dns.EDNS0 values
// using registered implementations. Unknown codes are silently skipped.
func Build(rawOptions []map[string]interface{}) ([]dns.EDNS0, error) {
	var out []dns.EDNS0
	for _, raw := range rawOptions {
		codeFloat, ok := raw["code"].(float64)
		if !ok {
			return nil, fmt.Errorf("edns option missing numeric 'code' field")
		}
		code := uint16(codeFloat)
		impl, known := registry[code]
		if !known {
			continue
		}
		opt, err := impl.FromRequest(raw)
		if err != nil {
			return nil, fmt.Errorf("edns option %d: %w", code, err)
		}
		out = append(out, opt)
	}
	return out, nil
}

// ParseAll extracts structured data from all EDNS0 options in a response OPT RR.
func ParseAll(opt *dns.OPT) map[uint16]map[string]interface{} {
	result := make(map[uint16]map[string]interface{})
	for _, o := range opt.Option {
		impl, known := registry[o.Option()]
		if !known {
			continue
		}
		result[o.Option()] = impl.ParseResponse(o)
	}
	return result
}
