package dns

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"dns-looking-glass/internal/dns/edns"

	"github.com/miekg/dns"
)

// Execute dispatches a QueryRequest to the appropriate mode handler.
func Execute(req *QueryRequest) *QueryResponse {
	if req.Mode == "" {
		req.Mode = "localhost"
	}
	switch req.Mode {
	case "localhost":
		req.Nameserver = "127.0.0.1"
		if req.Port == 0 {
			req.Port = 53
		}
		return execDirect(req)
	case "target":
		if req.Port == 0 {
			req.Port = 53
		}
		return execDirect(req)
	case "recursive":
		return execRecursive(req)
	default:
		return &QueryResponse{Error: fmt.Sprintf("unknown mode: %q", req.Mode)}
	}
}

// execDirect performs a single DNS exchange to the specified nameserver.
func execDirect(req *QueryRequest) *QueryResponse {
	qtype, ok := dns.StringToType[strings.ToUpper(req.QType)]
	if !ok {
		return &QueryResponse{Error: fmt.Sprintf("unknown qtype: %q", req.QType)}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(req.QName), qtype)
	msg.RecursionDesired = req.Flags.RD
	msg.AuthenticatedData = req.Flags.AD
	msg.CheckingDisabled = req.Flags.CD

	if req.Flags.DO || req.EDNS.UDPSize > 0 || len(req.EDNS.Options) > 0 {
		udpSize := req.EDNS.UDPSize
		if udpSize == 0 {
			udpSize = 1232
		}
		opts, err := edns.Build(req.EDNS.Options)
		if err != nil {
			return &QueryResponse{Error: fmt.Sprintf("edns: %v", err)}
		}
		o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		o.SetUDPSize(udpSize)
		if req.Flags.DO {
			o.SetDo()
		}
		o.Option = opts
		msg.Extra = append(msg.Extra, o)
	}

	network := "udp"
	if req.UseTCP {
		network = "tcp"
	}

	server := fmt.Sprintf("%s:%d", req.Nameserver, req.Port)

	queryBytes, _ := msg.Pack()

	client := &dns.Client{
		Net:     network,
		Timeout: 5 * time.Second,
	}

	start := time.Now()
	resp, _, err := client.Exchange(msg, server)
	elapsed := time.Since(start).Seconds() * 1000

	if err != nil {
		return &QueryResponse{
			DNSQueryMS:    elapsed,
			Nameserver:    server,
			QueryBytesHex: hex.EncodeToString(queryBytes),
			Error:         err.Error(),
		}
	}

	responseBytes, _ := resp.Pack()

	qr := &QueryResponse{
		DNSQueryMS:       elapsed,
		Nameserver:       server,
		ResponseText:     resp.String(),
		QueryBytesHex:    hex.EncodeToString(queryBytes),
		ResponseBytesHex: hex.EncodeToString(responseBytes),
		DNSSECValid:      nil,
		ResolutionChain:  []ResolutionStep{},
	}

	// Extract NSID and any other registered EDNS options from response.
	for _, extra := range resp.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			parsed := edns.ParseAll(opt)
			if nsidData, ok := parsed[dns.EDNS0NSID]; ok {
				if txt, ok := nsidData["nsid_txt"].(string); ok {
					qr.NSID = txt
				}
				if qr.NSID == "" {
					if h, ok := nsidData["nsid_hex"].(string); ok {
						qr.NSID = h
					}
				}
			}
		}
	}

	return qr
}
