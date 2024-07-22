#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys,argparse,logging,time
import sqlite3

ulog_table = """
CREATE TABLE ulog (
    oob_time_sec int,
    oob_prefix TEXT,
    ip_saddr_str TEXT,
    ip_daddr_str TEXT,
    ip_protocol INTEGER,
    tcp_sport INTEGER,
    tcp_dport INTEGER,
    udp_sport INTEGER,
    udp_dport INTEGER,
    mac_saddr_str TEXT,
    mac_daddr_str TEXT,
    oob_in TEXT
);
"""

readtime_table = """
CREATE TABLE readtime (
    ulog_rowid int PRIMARY KEY,
    time_sec int
);
"""

"""
# example ulogd.conf
[global]
logfile="/var/log/ulogd/ulogd.log"

stack=log:NFLOG,base:BASE,ifi:IFINDEX,ip2str:IP2STR,print:PRINTPKT,emu:LOGEMU
stack=log:NFLOG,base:BASE,ifi:IFINDEX,ip2str:IP2STR,hwhdr:HWHDR,sqlite3:SQLITE3

[log]
group=0

[emu]
file="/var/log/ulogd/ulogd_syslogemu.log"
sync=1

[sqlite3]
table="ulog"
db="/var/log/ulogd/ulogd.sqlite3db"
"""

"""
#!/usr/sbin/nft -f
# example nftables ruleset

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;

        # Log all TCP SYN packets (IPv4 and IPv6)
        ip protocol tcp tcp flags syn ct state new log prefix "Attempted TCP4 SYN:" group 0
        ip6 nexthdr tcp tcp flags syn ct state new log prefix "Attempted TCP6 SYN:" group 0
    }
}
"""

def protonum_to_name(num):
    if num == 1:
        return "ICMP"
    elif num == 6:
        return "TCP"
    elif num == 17:
        return "UDP"
    elif num == 58:
        return "ICMPv6"
    else:
        return "UNKNOWN"

def print_log(f, oob_time_sec, oob_prefix, ip_saddr_str, ip_protocol, tcp_dport, udp_dport, mac_saddr_str, oob_in):
    time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(oob_time_sec))
    to_str = ("%d/tcp" % tcp_dport) if tcp_dport is not None else ("%d/udp" % udp_dport) if udp_dport is not None else protonum_to_name(ip_protocol)

    print("%s: %s FROM=%s(%s) TO=%s ON=%s" 
          % (time_str,oob_prefix,ip_saddr_str, mac_saddr_str, to_str, oob_in), file=f)

def create_ulog_table(db):
    cursor = db.cursor()
    try:
        cursor.execute(ulog_table)
    finally:
        cursor.close()
    logging.info("Created ulog table")

def create_readtime_table(db):
    cursor = db.cursor()
    try:
        cursor.execute(readtime_table)
    finally:
        cursor.close()
    logging.info("Created readtime table")

def main(dbfile, outfile, mark_read):
    logging.debug(dbfile, outfile, mark_read)

    # open sqlite database
    logging.info("Opening sqlite database: %s" % dbfile)
    db = sqlite3.connect(dbfile, autocommit=True)
    try:
        # check if the table exists
        cursor = db.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ulog'")
        if cursor.fetchone() is None:
            create_ulog_table(db)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='readtime'")
        if cursor.fetchone() is None:
            create_readtime_table(db)
        # read the ulog
        cursor.execute("select ulog.rowid,oob_time_sec,oob_prefix,ip_saddr_str,ip_protocol,tcp_dport,udp_dport,mac_saddr_str,oob_in from ulog left outer join readtime on ulog.rowid=readtime.ulog_rowid where readtime.time_sec is null")
        rows = cursor.fetchall()
        for row in rows:
            rowid, oob_time_sec,oob_prefix,ip_saddr_str, ip_protocol, tcp_dport, udp_dport, mac_saddr_str, oob_in = row
            if outfile is not None:
                with open(outfile, 'a') as f:
                    print_log(f, oob_time_sec, oob_prefix, ip_saddr_str, ip_protocol, tcp_dport, udp_dport, mac_saddr_str, oob_in)
            else:
                print_log(sys.stdout, oob_time_sec, oob_prefix, ip_saddr_str, ip_protocol, tcp_dport, udp_dport, mac_saddr_str, oob_in)
            if mark_read:
                current_time_in_src = time.time()
                cursor.execute("REPLACE INTO readtime(ulog_rowid,time_sec) values(?,?)", (rowid, current_time_in_src))
        cursor.close()
    finally:
        db.close()
        logging.info("Closed sqlite database")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Watch ulog stored in sqlite file')
    parser.add_argument("--outfile", help="Output file to write the parsed ulog. stdout if not specified", type=str, default=None)
    parser.add_argument("--mark-read", help="Mark the ulog as read", action="store_true")
    parser.add_argument("--loglevel", help="Set the logging level", type=str, default="INFO")
    parser.add_argument('dbfile', metavar='dbfile', type=str, help='The ulog sqlite file to parse')

    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)

    try:
        main(args.dbfile, args.outfile, args.mark_read)
    except Exception as e:
        if args.outfile is not None:
            with open(args.outfile, 'a') as f:
                f.write(str(e))
        else:
            logging.error(e)
        exit(1)
