package dns

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

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

	resp, _, _, note, err := exchangeWithTCPFallback(q, addr)
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

	resp, _, _, note, err := exchangeWithTCPFallback(q, srv.PacketConn.LocalAddr().String())
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

// ── Integration: query path without DNSSEC validation ─────────────────────────

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
