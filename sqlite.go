package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

/*
 * Database Schema and Indices
 */

var SCHEMA_INFO = `
CREATE TABLE info
   (infile text,
    dbfile text,
    resolver text,
    threads int,
    start int,
    elapsed int);
`

var SCHEMA_TLSA = `
CREATE TABLE tlsa
   (zone text,
    service text,
    timestamp int,
    name text,
    port int,
    proto text,
    usage int,
    selector int,
    mtype int,
    certdata text,
    ad_bit int,
    alias text,
    validates int,
    validates_info text);
`

var INDEX_TLSA = `
CREATE UNIQUE INDEX if not exists tlsa_uniq ON tlsa (zone, service, name, port, proto, usage, selector, mtype, certdata, ad_bit, alias);
`

var SCHEMA_DNSSEC = `
CREATE TABLE dnssec
   (zone text,
    timestamp int,
    flags int,
    proto int,
    algo int,
    pubkey text,
    ad_bit int);
`

var INDEX_DNSSEC = `
CREATE UNIQUE INDEX if not exists dnssec_uniq ON dnssec (zone, flags, proto, algo, pubkey);
`

/*
 * initDB() - create sqlite3 database to hold TLSA scan results
 */

func initDB(dbname string) (db *sql.DB, stmt *sql.Stmt) {

	if !Options.nocreate {
		os.Remove(dbname)
		os.Remove(dbname + "-journal")
	}

	db, err := sql.Open("sqlite3", dbname)
	if err != nil {
		log.Fatal(err)
	}

	if !Options.nocreate {
		sqlStmt := SCHEMA_INFO + SCHEMA_TLSA + INDEX_TLSA
		_, err = db.Exec(sqlStmt)
		if err != nil {
			log.Fatalf("%s: %s\n", err, sqlStmt)
		}
	}

	stmt, err = db.Prepare("insert into tlsa values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		log.Fatal(err)
	}

	return db, stmt
}

/*
 * insertDB() - insert TLSA record entry into database
 */

func insertDB(db *sql.DB, stmt *sql.Stmt, r *ResponseInfo, tlsa *dns.TLSA) bool {

	_, err := stmt.Exec(r.zone,
		r.service,
		time.Now().Unix(),
		r.tlsa_base,
		r.tlsa_port,
		r.tlsa_proto,
		tlsa.Usage,
		tlsa.Selector,
		tlsa.MatchingType,
		tlsa.Certificate,
		r.ad_bit,
		r.alias,
		0, "")

	if err != nil {
		fmt.Printf("Insert error for %v %v: %s\n", r, tlsa, err)
		return false
	}

	return true
}

/*
 * recordMetaInfo()
 */

func recordMetaInfo(db *sql.DB, start time.Time, elapsed time.Duration) bool {

	sqlStmt := "insert into info(infile, dbfile, resolver, threads, start, elapsed)" +
		"values(?, ?, ?, ?, ?, ?)"
	_, err := db.Exec(sqlStmt, realPath(Options.batchfile),
		realPath(Options.dbfile), Options.servers[0], numParallel,
		start.Unix(), elapsed.Seconds())
	if err != nil {
		fmt.Printf("Error recording metainfo: %q: %s\n", err, sqlStmt)
		return false
	}

	return true
}
