package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Generic EDNS option

type EdnsoptStruct struct {
	code uint16
	data string // hex-encoded data string
}

//
// Options
//

type OptionsStruct struct {
	port         int
	tcp          bool
	itimeout     time.Duration
	tcptimeout   time.Duration
	retries      int
	ignore       bool
	adflag       bool
	cdflag       bool
	edns         bool
	edns_flags   uint16
	edns_opt     []*EdnsoptStruct
	dnssec       bool
	bufsize      uint16
	servers      []string
	tsig         string
	batchfile    string
	dbfile       string
}

var Options OptionsStruct = OptionsStruct{port: 53, tcp: false,
	itimeout: TimeoutInitial, tcptimeout: TimeoutTCP, retries: Retries,
	adflag: false, cdflag: false, edns: false, dnssec: false}

/*
 * parseArgs() - parse command line arguments and set options
 */

func parseArgs(args []string) {

	var i int
	var arg string

FORLOOP:
	for i, arg = range args {

		switch {
		case arg == "-h":
			usage()
		case arg == "-v":
			fmt.Println(Progname + " version " + Version)
			os.Exit(1)
		case arg == "+tcp":
			Options.tcp = true
		case arg == "+ignore":
			Options.ignore = true
		case arg == "+dnssec":
			Options.dnssec = true
			Options.edns = true
		case strings.HasPrefix(arg, "@"):
			Options.servers = []string{arg[1:]}
		case strings.HasPrefix(arg, "-p"):
			n, err := strconv.Atoi(arg[2:])
			if err != nil {
				fmt.Printf("Invalid port (-p): %s\n", arg[2:])
				usage()
			}
			Options.port = n
		case strings.HasPrefix(arg, "+bufsize="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "+bufsize="))
			if err != nil {
				fmt.Printf("Invalid bufsize: %s\n", arg)
				usage()
			}
			Options.bufsize = uint16(n)
			Options.edns = true
		case strings.HasPrefix(arg, "+ednsflags="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "+ednsflags="))
			if err != nil {
				fmt.Printf("Invalid ednsflags: %s\n", arg)
				usage()
			}
			Options.edns = true
			Options.edns_flags = uint16(n)
		case strings.HasPrefix(arg, "+ednsopt="):
			s := strings.SplitN(strings.TrimPrefix(arg, "+ednsopt="), ":", 2)
			n, err := strconv.Atoi(s[0])
			if err != nil {
				fmt.Printf("Invalid ednsopt: %s\n", arg)
				usage()
			}
			o := new(EdnsoptStruct)
			o.code = uint16(n)
			if len(s) == 2 {
				o.data = s[1]
			}
			Options.edns = true
			Options.edns_opt = append(Options.edns_opt, o)
		case strings.HasPrefix(arg, "+retry="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "+retry="))
			if err != nil {
				fmt.Printf("Invalid retry parameter: %s\n", arg)
				usage()
			}
			Options.retries = n
		case strings.HasPrefix(arg, "+time="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "+time="))
			if err != nil {
				fmt.Printf("Invalid timeout parameter: %s\n", arg)
				usage()
			}
			Options.itimeout = time.Duration(n) * time.Second
			Options.tcptimeout = time.Duration(n) * time.Second
		case strings.HasPrefix(arg, "+parallel="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "+parallel="))
			if err != nil {
				fmt.Printf("Invalid #parallel queries: %s\n", arg)
				usage()
			}
			numParallel = uint16(n)
		case strings.HasPrefix(arg, "-"):
			fmt.Printf("Invalid option: %s\n", arg)
			usage()
		case strings.HasPrefix(arg, "+"):
			fmt.Printf("Invalid option: %s\n", arg)
			usage()
		default:
			break FORLOOP
		}

	}

	if len(args)-i != 2 {
		fmt.Printf("ERROR: Exactly 2 arguments required: batchfile dbfile.\n")
		usage()
	}

	Options.batchfile = args[i]
	Options.dbfile = args[i+1]
	return
}
