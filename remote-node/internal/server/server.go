package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	dnsquery "dns-looking-glass/internal/dns"
	"dns-looking-glass/internal/version"
)

type Server struct {
	port      int
	bindAddrs []string
}

func New(port int, bind string) *Server {
	var addrs []string
	for _, a := range strings.Split(bind, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		addrs = []string{"127.0.0.1"}
	}
	return &Server{port: port, bindAddrs: addrs}
}

// ListenAndServe starts one HTTP listener per bind address on the configured port.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", handlePing)
	mux.HandleFunc("/", handleQuery)

	if len(s.bindAddrs) == 1 {
		addr := net.JoinHostPort(s.bindAddrs[0], fmt.Sprintf("%d", s.port))
		log.Printf("listening on %s", addr)
		return http.ListenAndServe(addr, mux)
	}

	// Multiple bind addresses — start each in a goroutine and report first error.
	errc := make(chan error, len(s.bindAddrs))
	var wg sync.WaitGroup
	for _, bind := range s.bindAddrs {
		addr := net.JoinHostPort(bind, fmt.Sprintf("%d", s.port))
		log.Printf("listening on %s", addr)
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			if err := http.ListenAndServe(a, mux); err != nil {
				errc <- fmt.Errorf("%s: %w", a, err)
			}
		}(addr)
	}
	return <-errc
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version.Version,
		"built":   version.BuildTime,
	})
}

func handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req dnsquery.QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if req.QName == "" {
		writeError(w, http.StatusBadRequest, "qname is required")
		return
	}
	if req.QType == "" {
		req.QType = "A"
	}

	start := time.Now()
	resp := dnsquery.Execute(&req)
	_ = start // dns_query_ms is set inside Execute

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
