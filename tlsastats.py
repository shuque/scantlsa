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

TLSA_USAGE = {
    0: "PKIX-TA", 
    1: "PKIX-EE",
    2: "DANE-TA",
    3: "DANE-EE"
}
TLSA_SELECTOR = {
    0: "Cert", 
    1: "SPKI"
}
TLSA_MTYPE = {
    0: "Full", 
    1: "SHA2-256",
    2: "SHA2-512"
}


def percentage(a, b):
    """what percentage of b is a?"""
    return (a * 100.0) / b


conn = sqlite3.connect(sys.argv[1])
c = conn.cursor()

# Format strings ..
FMT1 = "%-30s: %7d"
FMT2 = "%-30s: %7d (%5.1f%%)"

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
print(FMT1 % ("Total# Zones in infile", infile_zonecount))
print(FMT2 % ("#Distinct TLSA Zones", zonecount,
              zonecount * 100.0/infile_zonecount))

## Number of <Zone, TLSA records> (total)
stmt = "select count(*) from tlsa limit 1"
cnt_zone_tlsa, = c.execute(stmt).fetchone()
print(FMT1 % ("Total #Zone,TLSA records", cnt_zone_tlsa))

## Total number of distinct <Zone, service> pairs
stmt = "select count(*) from (select distinct zone, service from tlsa)"
cnt_zone_service, = c.execute(stmt).fetchone()
print(FMT1 % ("#distinct <Zone, service>", cnt_zone_service))

## Total number of distinct TLSA RRsets
stmt = "select count(*) from (select distinct port, proto, name from tlsa)"
cnt_tlsa_rrset, = c.execute(stmt).fetchone()
print(FMT1 % ("#distinct TLSA RRsets", cnt_tlsa_rrset))

## Total number of distinct TLSA RRs
stmt = "select count(*) from (select distinct port, proto, name, usage, selector, mtype, certdata from tlsa)"
cnt_tlsa_rr, = c.execute(stmt).fetchone()
print(FMT1 % ("#distinct TLSA RRs", cnt_tlsa_rr))

## Number of distinct ports
stmt = "select count(distinct port) from tlsa limit 1"
port_count, = c.execute(stmt).fetchone()
print(FMT1 % ("Total #distinct ports", port_count))


print('')

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
print("Count of distinct services by <Zone, RRset> tuples:")
for cnt, svc in c.execute(stmt).fetchall():
    print("  %7d %s" % (cnt, svc))

## Count of distinct services by <RRset> tuples
stmt = "select count(service), service from (select distinct service, port, proto, name from tlsa) group by service order by count(service) desc;"
print("Count of distinct services by <RRset> tuples:")
for cnt, svc in c.execute(stmt).fetchall():
    print("  %7d %s" % (cnt, svc))

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
print("Top 20 RRsets and their counts:")
for cnt, port, proto, name in c.execute(stmt).fetchall():
    print("  %7d _%d._%s.%s" % (cnt, port, proto, name))

## Top 20 RRs (not RRsets) and their counts 
stmt = "select count(*), port, proto, name from tlsa group by port, proto, name, usage, selector, mtype, certdata order by count(*) desc limit 20"
print("Top 20 RRs (not RRsets) and their counts:")
for cnt, port, proto, name in c.execute(stmt).fetchall():
    print("  %7d _%d._%s.%s <.. rdata>" % (cnt, port, proto, name))

## Top 20 RRsets to which zones point to (and how many zones)
stmt = 'select count(owner), owner from (select distinct zone, printf("_%d._%s.%s", port, proto, name) as owner from tlsa) group by owner order by count(owner) desc limit 20'
print("Top 20 TLSA RRsets by #zones which point to them:")
for cnt, owner in c.execute(stmt).fetchall():
    print("  %7d %s" % (cnt, owner))

## TLSA Certificate Usage parameter counts across unique RRs
stmt = "select count(*), usage from (select distinct port, proto, name, usage, selector, mtype, certdata from tlsa) group by usage order by count(*) desc"
print("TLSA Certificate Usage parameter counts across unique RRs:")
for cnt, usage in c.execute(stmt).fetchall():
    print("  %7d %s (%d) %5.1f%%" %
          (cnt, TLSA_USAGE.get(usage, "UNKNOWN"), usage,
           percentage(cnt, cnt_tlsa_rr)))

## TLSA Selector parameter counts across unique RRs
stmt = "select count(*), selector from (select distinct port, proto, name, usage, selector, mtype, certdata from tlsa) group by selector order by count(*) desc"
print("TLSA Certificate Usage parameter counts across unique RRs:")
for cnt, selector in c.execute(stmt).fetchall():
    print("  %7d %s (%d) %5.1f%%" %
          (cnt, TLSA_SELECTOR.get(selector, "UNKNOWN"), selector,
           percentage(cnt, cnt_tlsa_rr)))

## TLSA Matching Type parameter counts across unique RRs
stmt = "select count(*), mtype from (select distinct port, proto, name, usage, selector, mtype, certdata from tlsa) group by mtype order by count(*) desc"
print("TLSA Matching Type parameter counts across unique RRs:")
for cnt, mtype in c.execute(stmt).fetchall():
    print("  %7d %s (%d) %5.1f%%" %
          (cnt, TLSA_MTYPE.get(mtype, "UNKNOWN"), mtype,
           percentage(cnt, cnt_tlsa_rr)))

## TODO: wildcard analysis

## SMTP specific analysis, e.g. how many MX RRsets involved, etc.

conn.close()

