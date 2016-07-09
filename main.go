package main

import (
	"bufio"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

var Version string = "0.11"
var Progname string = path.Base(os.Args[0])

/*
 * Default parameters and counters.
 */

var TimeoutInitial time.Duration = time.Second * 2
var TimeoutTCP time.Duration = time.Second * 5
var Retries int = 3
var BufsizeDefault uint16 = 4096
var MaxServers = 20
var countZones = 0

/* 
 * For goroutine communications and synchronization:
 *    wg: a sync counter to determine when last routine has ended.
 *    numParallel: the default number of concurrent queries we allow.
 *    tokens: a counting semapahore to bound the parallelism.
 *    results: the channel over which query results are communicated.
 */

var wg sync.WaitGroup
var numParallel uint16 = 40
var tokens chan struct{}
var results chan *ResponseInfo

/*
 * Response Information structure
 */

type ResponseInfo struct {
	zone       string
	service    string
	timestamp  int64
	qname      string
	qtype      string
	qclass     string
	tlsa_port  uint16
	tlsa_proto string
	tlsa_base  string
	truncated  bool
	retried    bool
	timeout    bool
	response   *dns.Msg
	ad_bit     int
	alias      string
	rtt        time.Duration
	err        error
	server     string
}

/*
 * getSysResolver() - obtain system default resolver addresses
 */

func getSysResolvers() (resolvers []string, err error) {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil {
		resolvers = config.Servers
	} else {
		fmt.Println("Error processing /etc/resolv.conf: " + err.Error())
	}
	return
}

/*
 * makeOptrr() - construct OPT Pseudo RR structure
 */

func makeOptRR() *dns.OPT {

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	if Options.bufsize > 0 {
		opt.SetUDPSize(Options.bufsize)
	} else {
		opt.SetUDPSize(BufsizeDefault)
	}
	if Options.dnssec {
		opt.SetDo()
	}

	if Options.edns_flags != 0 {
		opt.Hdr.Ttl |= uint32(Options.edns_flags)
	}

	if Options.edns_opt != nil {
		for _, o := range Options.edns_opt {
			e := new(dns.EDNS0_LOCAL)
			e.Code = o.code
			h, err := hex.DecodeString(o.data)
			if err != nil {
				log.Fatalf("Error decoding generic edns option data.\n")
			}
			e.Data = h
			opt.Option = append(opt.Option, e)
		}
	}

	return opt
}

/*
 * addressString() - return address:port string
 */

func addressString(addr string, port int) string {
	if strings.Index(addr, ":") == -1 {
		return addr + ":" + strconv.Itoa(port)
	} else {
		return "[" + addr + "]" + ":" + strconv.Itoa(port)
	}
}

/*
 * makeMessage() - construct DNS message structure
 */

func makeMessage(qname, qtype, qclass string) *dns.Msg {

	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.AuthenticatedData = true
	// Note: some resolvers (like 8.8.8.8) won't set AD bit if CD=1 and AD=1
	m.CheckingDisabled = true

	if Options.edns {
		m.Extra = append(m.Extra, makeOptRR())
	}

	m.Question = make([]dns.Question, 1)
	qtype_int, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		fmt.Printf("%s: Unrecognized query type.\n", qtype)
		usage()
	}
	qclass_int, ok := dns.StringToClass[strings.ToUpper(qclass)]
	if !ok {
		fmt.Printf("%s: Unrecognized query class.\n", qclass)
		usage()
	}
	m.Question[0] = dns.Question{qname, qtype_int, qclass_int}

	return m
}

/*
 * doQuery() - perform DNS query with timeouts and retries as needed
 */

func doQuery(qname, qtype, qclass string, use_tcp bool) (response *dns.Msg, server string, rtt time.Duration, err error) {

	var retries = Options.retries
	var timeout = Options.itimeout

	m := makeMessage(qname, qtype, qclass)

	if use_tcp {
		return sendRequest(m, true, Options.tcptimeout)
	}

	for retries > 0 {
		response, server, rtt, err = sendRequest(m, false, timeout)
		if err == nil {
			break
		} else {
			// is there a better way to check for timeout error?
			if !strings.Contains(err.Error(), "i/o timeout") {
				break
			}
			retries--
			if retries > 0 {
				timeout = timeout * 2
			}
		}
	}

	return response, server, rtt, err
}

/*
 * sendRequest() - send a DNS query
 */

func sendRequest(m *dns.Msg, use_tcp bool, timeout time.Duration) (response *dns.Msg, server string, rtt time.Duration, err error) {

	server = Options.servers[0]

	c := new(dns.Client)
	c.Timeout = timeout

	if use_tcp {
		c.Net = "tcp"
	} else {
		c.Net = "udp"
	}

	response, rtt, err = c.Exchange(m, addressString(server, Options.port))

	return response, server, rtt, err
}

/*
 * processResponse() - process info about a DNS response. Successful
 *                     responses are entered into the sqlite database.
 *                     Failures are printed to stdout.
 */

func processResponse(db *sql.DB, stmt *sql.Stmt, r *ResponseInfo) {

	if r.err != nil && !r.truncated {
		fmt.Printf("ERROR: %s %s %s Query fail: %s\n", r.zone, r.service, r.qname, r.err)
		return
	}

	opt := r.response.IsEdns0()
	if opt != nil {
		rcode_hi_bits := (opt.Hdr.Ttl >> 24) & 0xff
		if rcode_hi_bits != 0 {
			r.response.MsgHdr.Rcode = opt.ExtendedRcode()
		}
	}

	switch r.response.MsgHdr.Rcode {
	case 0, 3:
		break
	default:
		fmt.Printf("ERROR: %s %s %s RCODE: %d\n", r.zone, r.service, r.qname, r.response.MsgHdr.Rcode)
		return
	}

	if r.response.MsgHdr.AuthenticatedData {
		r.ad_bit = 1
	} else {
		r.ad_bit = 0
	}

	if len(r.response.Answer) > 0 {
		for _, rr := range r.response.Answer {
			if tlsa, ok := rr.(*dns.TLSA); ok {
				if tlsa.Hdr.Name != r.qname {
					r.alias = tlsa.Hdr.Name
				}
				_ = insertDB(db, stmt, r, tlsa)
			}
		}
	}

	return
}

/*
 * queryWildCardTLSA()
 */

func queryWildCardTLSA(zone string) {

	queryTLSA(zone, "wild", 0, "tcp", zone)
	queryTLSA(zone, "wild", 0, "", zone)
	return
}

/*
 * queryXmppTLSA()
 */

func queryXmppTLSA(zone string) {

	response, _, _, err := doQuery("_xmpp-client._tcp."+zone, "SRV", "IN", false)
	if err == nil && response.MsgHdr.Rcode == 0 &&
		len(response.Answer) != 0 {
		for _, rr := range response.Answer {
			if srv, ok := rr.(*dns.SRV); ok {
				queryTLSA(zone, "xmpp-client", srv.Port, "tcp", srv.Target)
			}
		}
	}

	response, _, _, err = doQuery("_xmpp-server._tcp."+zone, "SRV", "IN", false)
	if err == nil && response.MsgHdr.Rcode == 0 &&
		len(response.Answer) != 0 {
		for _, rr := range response.Answer {
			if srv, ok := rr.(*dns.SRV); ok {
				queryTLSA(zone, "xmpp-server", srv.Port, "tcp", srv.Target)
			}
		}
	}

	return
}

/*
 * queryMailTLSA()
 */

func queryMailTLSA(zone string) {

	response, _, _, err := doQuery(zone, "MX", "IN", false)
	if err != nil || response.MsgHdr.Rcode != 0 ||
		len(response.Answer) == 0 {
		queryTLSA(zone, "smtp", 25, "tcp", zone)
		queryTLSA(zone, "smtp", 465, "tcp", zone)
		queryTLSA(zone, "smtp", 587, "tcp", zone)
		return
	}
	for _, rr := range response.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			queryTLSA(zone, "smtp", 25, "tcp", mx.Mx)
			queryTLSA(zone, "smtp", 465, "tcp", mx.Mx)
			queryTLSA(zone, "smtp", 587, "tcp", mx.Mx)
		}
	}
	return
}

/*
 * queryWebTLSA()
 */

func queryWebTLSA(zone, prefix string, port uint16) {

	if prefix == "" {
		queryTLSA(zone, "http", port, "tcp", zone)
	} else {
		queryTLSA(zone, "http", port, "tcp", prefix+"."+zone)
	}
	return
}

/*
 * queryTLSA() - send DNS TLSA query, populate ResponseInfo structure,
 *               and write it to the results channel. The results 
 *               channel is read by the main goroutine in runBatchFile().
 */

func queryTLSA(zone, service string, port uint16, proto, base string) {

	var qname string

	if service == "wild" {
		if proto == "" {
			qname = fmt.Sprintf("*.%s", base)
		} else {
			qname = fmt.Sprintf("*._%s.%s", proto, base)
		}
	} else {
		qname = fmt.Sprintf("_%d._%s.%s", port, proto, base)
	}

	r := new(ResponseInfo)
	r.zone, r.service = zone, service
	r.tlsa_port, r.tlsa_proto, r.tlsa_base = port, proto, base
	r.qname, r.qtype, r.qclass = qname, "TLSA", "IN"

	response, server, rtt, err := doQuery(qname, "TLSA", "IN", false)
	if err == dns.ErrTruncated {
		r.truncated = true
	}
	if err != nil && !strings.Contains(err.Error(), "i/o timeout") {
		r.timeout = true
	}
	r.response = response
	r.timestamp = time.Now().Unix()
	r.rtt = rtt
	r.server = server
	r.err = err
	results <- r

}

/*
 * queryZone() - dispatch all TLSA queries for given zone. Releases token
 *               and decrements wg counter after completion.
 */

func queryZone(zone string) {

	defer wg.Done()

	queryWebTLSA(zone, "", 443)
	queryWebTLSA(zone, "www", 443)
	queryMailTLSA(zone)
	queryXmppTLSA(zone)
	queryWildCardTLSA(zone)

	<-tokens // Release token.

}

/*
 * runBatchFile() - process batch file of zones, obtain token (blocking
 *                  if channel is full), then fire off concurrent goroutines
 *                  to dispatch TLSA queries for each zone, incrementing the
 *                  wg sync counter before each goroutine invocation. The 
 *                  queryZone() goroutine releases tokens and decrements the
 *                  wg counter as it completes.
 */

func runBatchFile(batchfile string, db *sql.DB, stmt *sql.Stmt) {

	var zone string

	go func() {
		f, err := os.Open(batchfile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			zone = fields[0]
			if zone == "" {
				fmt.Printf("Batchfile line error: %s\n", line)
				continue
			}
			wg.Add(1)
			tokens <- struct{}{} // Obtain token; blocks if channel is full.
			go queryZone(zone)
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
		wg.Wait()
		close(results)
	}()

	for r := range results {
		processResponse(db, stmt, r)
	}
	return
}

/*
 * realPath()
 */

func realPath(filename string) string {

	if path.IsAbs(filename) {
		return filename
	} else {
		cwd, _ := os.Getwd()
		return path.Join(cwd, filename)
	}
}

/*
 * main()
 */

func main() {

	var err error

	log.SetFlags(0)
	parseArgs(os.Args[1:])

	tokens = make(chan struct{}, int(numParallel))
	results = make(chan *ResponseInfo)

	if len(Options.servers) == 0 || Options.servers[0] == "" {
		Options.servers, err = getSysResolvers()
		if err != nil {
			log.Fatalf("failed to get resolver adddresses: %s\n", err)
		}
	}
	if len(Options.servers) > MaxServers {
		Options.servers = Options.servers[0:MaxServers]
	}

	db, stmt := createDB(Options.dbfile)
	if db == nil {
		log.Fatalf("failed to create sqlite3 database %s.\n", Options.dbfile)
	}
	defer db.Close()
	defer stmt.Close()

	fmt.Printf("DEBUG: batchfile: %s\n", Options.batchfile)
	fmt.Printf("DEBUG: dbfile: %s\n", Options.dbfile)
	fmt.Printf("DEBUG: resolver: %s\n", Options.servers[0])
	fmt.Printf("DEBUG: numParallel: %d\n\n", numParallel)

	t0 := time.Now()
	runBatchFile(Options.batchfile, db, stmt)
	elapsedTime := time.Since(t0)
	fmt.Printf("\nElapsed time: %s\n", elapsedTime.String())
	_ = recordMetaInfo(db, t0, elapsedTime)

	return

}
