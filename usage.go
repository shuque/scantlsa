package main

import (
	"fmt"
	"os"
)

/*
 * usage() - Print usage string and exit.
 */

func usage() {
	fmt.Println(Progname + " version " + Version)
	fmt.Printf("Usage: %s [<options>] <batchfile> <dbfile>\n", Progname)
	fmt.Printf("\n<batchfile> is a file containing a list of DNS zones, one per line.\n")
	fmt.Printf("<dbfile> is a sqlite3 database file to write results to.\n")
	fmt.Printf(`
Supported Options:
  -h                   Print this usage string and exit
  -v                   Print program version and exit
  @server              Use specified server name or address as resolver
  -pNNN                Use NNN as the port number (default is 53)
  +tcp                 Use TCP as transport (default is UDP)
  +ignore              Ignore truncation, i.e. don't retry with TCP
  +retry=N             Set number of tries for UDP queries (default 3)
  +time=N              Set timeout (default is 3s for UDP, 5s for TCP)
  +dnssec              Set DNSSEC-OK bit
  +bufsize=N           Use EDNS0 UDP payload size of N
  +ednsflags=N         Set EDNS flags field to N
  +ednsopt=###[:value] Set generic EDNS option
  +nocreate            Don't create the database; assume it exists
  +parallel=N          Use N concurrent queries at a time in batchfile mode
`)
	os.Exit(1)
}
