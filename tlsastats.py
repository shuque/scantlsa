#!/usr/bin/env python
#

"""
tlsa.db schemas

TABLE info
   (infile text,
    dbfile text,
    resolver text,
    threads int,
    start int,
    elapsed int);

TABLE tlsa
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
"""

import os, sys, sqlite3, time

conn = sqlite3.connect(sys.argv[1])
c = conn.cursor()

## Meta info

infile, dbfile, resolver, threads, start, elapsed = \
            c.execute("select * from info limit 1").fetchone()
print("""\
Input file:  {}
DB file:     {}
Resolver:    {}
#Threads:    {}
StartTime:   {}
ElapsedTime: {}

""".format(infile, dbfile, resolver, threads, 
           time.ctime(start), elapsed))

## Number of Distinct Zones and TLSA Zones
stmt = "select count(distinct zone) from tlsa limit 1"
infile_zonecount = len(list(open(infile)))
zonecount, = c.execute(stmt).fetchone()
print("Total# Zones in infile: %7d" % infile_zonecount)
print("#Distinct TLSA Zones  : %7d (%5.1f%%)" % 
      (zonecount,
      (zonecount * 100.0/infile_zonecount)))

## Number of TLSA records (total)
stmt = "select count(*) from tlsa limit 1"
tlsa_count, = c.execute(stmt).fetchone()
print("Total #TLSA records:    %7d" % tlsa_count)

## Total number of distinct <Zone, service> pairs
stmt = "select count(*) from (select distinct zone, service from tlsa)"
cnt, = c.execute(stmt).fetchone()
print("#distinct <Zone, service>:  %7d" % cnt)

## Total number of distinct TLSA RRsets
stmt = "select count(*) from (select distinct port, proto, name from tlsa)"
cnt, = c.execute(stmt).fetchone()
print("#distinct TLSA RRsets:  %7d" % cnt)

## Count of distinct services by all TLSA records
stmt = "select count(service), service from tlsa group by service order by count(service) desc"
print("Count of services by all TLSA records:")
for cnt, svc in c.execute(stmt).fetchall():
    print("  %7d %s" % (cnt, svc))

## Count of distinct services by zones
stmt = "select count(service), service from (select distinct zone, service from tlsa) group by service order by count(service) desc"
print("Count of distinct services by zones:")
for cnt, svc in c.execute(stmt).fetchall():
    print("  %7d %s" % (cnt, svc))

## Count of distinct services by <Zone, RRset> tuples
stmt = "select count(service), service from (select distinct zone, service, port, proto, name from tlsa) group by service order by count(service) desc;"
print("Count of distinct services by <Zone, RRset> tuples")
for cnt, svc in c.execute(stmt).fetchall():
    print("  %7d %s" % (cnt, svc))

## Count of distinct services by <RRset> tuples
stmt = "select count(service), service from (select distinct service, port, proto, name from tlsa) group by service order by count(service) desc;"
print("Count of distinct services by <RRset> tuples")
for cnt, svc in c.execute(stmt).fetchall():
    print("  %7d %s" % (cnt, svc))


## Number of distinct ports
stmt = "select count(distinct port) from tlsa limit 1"
port_count, = c.execute(stmt).fetchone()
print("Total #distinct ports:  %7d" % port_count)

## List of distinct ports
stmt = "select distinct port from tlsa order by port"
print("List of ports:")
for row in c.execute(stmt).fetchall():
    port, = row
    if port == 0:
        print("  %7d (wildcard; not a real port)" % port)
    else:
        print("  %7d" % port)

## Top 20 RRsets and their counts
stmt = "select count(*), port, proto, name from tlsa group by port, proto, name order by count(*) desc limit 20"
print("Top 20 RRsets and their counts")
for cnt, port, proto, name in c.execute(stmt).fetchall():
    print("  %7d _%d._%s.%s" % (cnt, port, proto, name))

conn.close()

