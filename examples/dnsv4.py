#!/usr/bin/python

# dnsv4.py - DNSv4 query tool
# Copyright (C) 2011 Nadeem Douba
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Nadeem Douba <ndouba at gmail dot com>
# 348 Patricia Ave, Ottawa, ON, K1Z 6G6
# Canada


import sys
import argparse
import libnet
from libnet.constants import *


class TYPE:
	RESERVED='\x00\x00'
	A='\x00\x01'
	NS='\x00\x02'
	MD='\x00\x03'
	MF='\x00\x04'
	CNAME='\x00\x05'
	SOA='\x00\x06'
	MB='\x00\x07'
	MG='\x00\x08'
	MR='\x00\x09'
	NULL='\x00\x0a'
	WKS='\x00\x0b'
	PTR='\x00\x0c'
	HINFO='\x00\x0d'
	MINFO='\x00\x0e'
	MX='\x00\x0f'
	TXT='\x00\x10'
	RP='\x00\x11'
	AFSDB='\x00\x12'
	X25='\x00\x13'
	ISDN='\x00\x14'
	RT='\x00\x15'
	NSAP='\x00\x16'
	NSAP_PTR='\x00\x17'
	SIG='\x00\x18'
	KEY='\x00\x19'
	PX='\x00\x1a'
	GPOS='\x00\x1b'
	AAAA='\x00\x1c'
	LOC='\x00\x1d'
	NXT='\x00\x1e'
	EID='\x00\x1f'
	NIMLOC='\x00\x20'
	SRV='\x00\x21'
	ATMA='\x00\x22'
	NAPTR='\x00\x23'
	KX='\x00\x24'
	CERT='\x00\x25'
	A6='\x00\x26'
	DNAME='\x00\x27'
	SINK='\x00\x28'
	OPT='\x00\x29'
	APL='\x00\x2a'
	DS='\x00\x2b'
	SSHFP='\x00\x2c'
	IPSECKEY='\x00\x2d'
	RRSIG='\x00\x2e'
	NSEC='\x00\x2f'
	DNSKEY='\x00\x30'
	DHCID='\x00\x31'
	NSEC3='\x00\x32'
	NSEC3PARAM='\x00\x33'
	HIP='\x00\x37'
	NINFO='\x00\x38'
	RKEY='\x00\x39'
	TALINK='\x00\x3a'
	SPF='\x00\x63'
	UINFO='\x00\x64'
	UID='\x00\x65'
	GID='\x00\x66'
	UNSPEC='\x00\x67'
	TKEY='\x00\xf9'
	TSIG='\x00\xfa'
	IXFR='\x00\xfb'
	AXFR='\x00\xfc'
	MAILB='\x00\xfd'
	MAILA='\x00\xfe'
	ALL='\x00\xff'
	DNSSEC_TRUSTED_AUTHORITIES='\x80\x00'
	DNSSEC_LOOKASIDE_VALIDATION='\x80\x01'

class CLASS:
	RESERVED='\x00\x00'
	IN='\x00\x01'
	CH='\x00\x03'
	HS='\x00\x04'
	NONE='\xff\xfe'
	ANY='\xff\xff'

def toquery(query, query_type, query_class):

	q = ''

	for i in query:
		q += '%c%s' % (len(i), i)

	q += '\x00'+query_type+query_class

	return q

def build_query(name, query_type, query_class):

	if query_type == TYPE.PTR:
		return build_inptr_query(name, query_class)
	
	return toquery(name.split('.'), TYPE.A, CLASS.IN)


def build_inptr_query(name, query_class):

	q = ''
	
	l = name.split('.')
	l.reverse()
	l.extend(['in-addr', 'arpa'])
	
	return toquery(l, TYPE.PTR, query_class)

if __name__ == '__main__':

	# Parse the arguments
	parser = argparse.ArgumentParser(description='Creates and injects a UDP-based DNSV4 IN A query.')
	parser.add_argument('-i', metavar='interface', required=True, help='the injection interface.')
	parser.add_argument('-d', metavar='destination', required=True, help='the destination to resolve')
	parser.add_argument('-n', metavar='nameserver', required=True, help='DNS server.')
	parser.add_argument('-q', metavar='query_type', required=False, help='DNS query type (e.g. A, MX, NS, etc.).', default='A', choices=filter(lambda n: not(n.startswith('__')), dir(TYPE)))
	parser.add_argument('-c', metavar='query_class', required=False, help='DNS query type (e.g. A, MX, NS, etc.).', default='IN', choices=filter(lambda n: not(n.startswith('__')), dir(CLASS)))
	args = parser.parse_args(sys.argv[1:])

	c = libnet.context(device=args.i, injection_type=RAW4)
	print 'Building DNS getheader:'
	dns_ptag = c.build_dnsv4(id=3,flags=256,num_q=1,num_anws_rr=0,num_auth_rr=0,num_addi_rr=0,payload=build_query(args.d, eval('TYPE.%s' % args.q), eval('CLASS.%s' % args.c)))
	print c.getheader(dns_ptag)

	print 'Building UDP getheader:'
	udp_ptag = c.build_udp(dp=53)
	print c.getheader(udp_ptag)

	print 'Building IPv4 getheader:'
	ipv4_ptag = c.build_ipv4(dst=c.name2addr4('4.2.2.1', DONT_RESOLVE), prot=17)
	print c.getheader(ipv4_ptag)

	print 'Sending packet:'
	print c.getpacket()
	c.write()

	print 'Stats:'
	print c.stats()
