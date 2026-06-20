package edns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func init() {
	Register(&ecsOption{})
}

type ecsOption struct{}

func (e *ecsOption) Code() uint16 { return dns.EDNS0SUBNET }

func (e *ecsOption) FromRequest(params map[string]interface{}) (dns.EDNS0, error) {
	subnet := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET}

	familyFloat, _ := params["family"].(float64)
	subnet.Family = uint16(familyFloat)
	if subnet.Family == 0 {
		subnet.Family = 1 // default IPv4
	}

	addrStr, _ := params["address"].(string)
	if addrStr == "" {
		addrStr = "0.0.0.0"
	}
	ip := net.ParseIP(addrStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid ECS address: %q", addrStr)
	}
	if subnet.Family == 1 {
		if v4 := ip.To4(); v4 != nil {
			subnet.Address = v4
		} else {
			return nil, fmt.Errorf("ECS family 1 but address is not IPv4: %q", addrStr)
		}
	} else {
		subnet.Address = ip.To16()
	}

	srcFloat, ok := params["source_prefix"].(float64)
	if ok {
		subnet.SourceNetmask = uint8(srcFloat)
	} else {
		if subnet.Family == 1 {
			subnet.SourceNetmask = 24
		} else {
			subnet.SourceNetmask = 48
		}
	}

	scopeFloat, ok := params["scope_prefix"].(float64)
	if ok {
		subnet.SourceScope = uint8(scopeFloat)
	}

	return subnet, nil
}

func (e *ecsOption) ParseResponse(opt dns.EDNS0) map[string]interface{} {
	subnet, ok := opt.(*dns.EDNS0_SUBNET)
	if !ok {
		return nil
	}
	return map[string]interface{}{
		"family":        subnet.Family,
		"address":       subnet.Address.String(),
		"source_prefix": subnet.SourceNetmask,
		"scope_prefix":  subnet.SourceScope,
	}
}
