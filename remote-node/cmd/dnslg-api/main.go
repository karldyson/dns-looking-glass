package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"

	dnsquery "dns-looking-glass/internal/dns"
	"dns-looking-glass/internal/server"
	"dns-looking-glass/internal/version"

	// Import edns implementations so their init() functions register options.
	_ "dns-looking-glass/internal/dns/edns"
)

func main() {
	port := flag.Int("port", 53080, "TCP port to listen on")
	bind := flag.String("bind", "127.0.0.1", "Comma-separated list of addresses to bind (e.g. \"0.0.0.0,::\" for dual-stack)")
	debugMode := flag.Bool("debug", false, "Log DNS query and DNSSEC validation details to stderr")
	showVersion := flag.Bool("version", false, "Print version and exit")
	showRevision := flag.Bool("revision", false, "Print full build/VCS revision info and exit")
	flag.Parse()

	if *debugMode {
		dnsquery.Debug = true
	}

	if *showRevision {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			panic("not ok reading build info!")
		}
		fmt.Printf("%s version information:\ncommit %s\n%+v\n", os.Args[0], version.Version, bi)
		return
	}

	if *showVersion {
		fmt.Printf("%s version %s\n", os.Args[0], version.Version)
		return
	}

	log.Printf("dnslg-api %s (built %s) starting on port %d, bind %s", version.Version, version.BuildTime, *port, *bind)
	srv := server.New(*port, *bind)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}
