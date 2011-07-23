#!/usr/bin/python

# icmp4echo - ICMP injector example
# Copyright (C) 2011  Fausto Marzi
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
# Fausto Marzi <fausto dot marzi at gmail dot com>

import libnet
from libnet.constants import *
import re
import optparse #Deprecated. Starting from Python 2.7 version you should use argparse instead.
import sys
import time


# We use ArgParse as module to pass options
parser = optparse.OptionParser("usage: %prog [options] -i interface -d host")
parser.add_option("-i", action="store", dest="netif", default=False, help="Specify whith network interface to use.")
parser.add_option("-c", action="store", dest="count", default=0, type="int", help="How many packets to send. Default infinite.")
parser.add_option("-D", action="store", dest="delay", default=1, type="int", help="Delay between each packet in seconds. 0 send packet as fast as possible (be careful). Default 1.")
parser.add_option("-s", action="store", dest="srcip", default=0, help="The source IP. Default use the IP of the chosen interface.")
parser.add_option("-d", action="store", dest="dstip", default=0, help="The destination IP where you want send packets to. Mandatory.")
parser.add_option("-o", action="store", dest="iptos", default=0, type="int", help="Set value for the Type of Service field in IP header. Default 0.")
parser.add_option("-I", action="store", dest="ipid", default=0, type="int", help="Set value for the IP ID field in IP header. Default 0.")
parser.add_option("-f", action="store", dest="ipfrag", default=0, type="int", help="Set value for the fragment bits and offest field in IP Header. Default 0")
parser.add_option("-t", action="store", dest="ipttl", default=128, type="int", help="Set TTL value in IP Header. Default 128.")
parser.add_option("-p", action="store", dest="ipproto", default=1, type="int", help="Set the upper layer Proto value in IP Header. Default 1 (ICMP).")
parser.add_option("--iechoreq", action="store_true", dest="iechoreq", help="With this option you can send ICMP Type ECHO Request packets. Default.")
parser.add_option("--iechorep", action="store_true", dest="iechorep", help="With this option you can send ICMP Type ECHO Reply packets.")
parser.add_option("-P",	action="store",	dest="payload", help="Add a Payload string to the packet. Default No Payload.")

# Parse all options. To use an options you have to use options."dest", like options.dstip for Destination IP
(options, args) = parser.parse_args()

if len(sys.argv) < 2:
	parser.print_help()	
	sys.exit(0)	

# Controls

# Check if the dstination IP and network interface
if not (options.dstip and options.netif):
        print "\nError: Options -i interface and -d host are mandatories.\n"
	parser.print_help()
        sys.exit(0)

#Test if ICMP Type is REQUEST or REPLY
if options.iechorep:
        itype = ICMP_ECHOREPLY
else:
        itype = ICMP_ECHO


#Initialize libnet context
inj = libnet.context(RAW4, options.netif)

if not inj:
	print "\nInitialization failed! Please check if you have rights or if you have entered a valid network interface or valid dst IP\n."
	parser.print_help()
	sys.exit(0)

if options.srcip == 0:
	options.srcip	= inj.get_ipaddr4()
else:	
	options.srcip   = inj.name2addr4(options.srcip, RESOLVE)

# With PyLibnet you have to start to building packets from the upper layer. In this case ICMP
icmptag = inj.build_icmpv4_echo(type=itype, code=1, seq=1, payload=options.payload) 

options.dstip 	= inj.name2addr4(options.dstip, RESOLVE)

iptag = inj.build_ipv4(tos=options.iptos, id=options.ipid, frag=options.ipfrag, ttl=options.ipttl, prot=options.ipproto, sum=0, src=options.srcip, dst=options.dstip, payload=None, ptag=0)


# Probably there's a better way to do this
if options.count == 0:
	i = 2
	while True: 
		try:
			inj.write()
			icmptag = inj.build_icmpv4_echo(type=itype, code=1, seq=i, payload=options.payload, ptag=icmptag) 
			time.sleep(options.delay)
		except KeyboardInterrupt:
			break
		i += 1
else:
	i = 2
	while(options.count >= 1):
        	try:
                	inj.write()
			icmptag = inj.build_icmpv4_echo(type=itype, code=1, seq=i, payload=options.payload, ptag=icmptag) 
                	time.sleep(options.delay)
        	except  KeyboardInterrupt:
                	break
        	options.count -= 1
		i += 1
 



print inj.stats()
#print inj.getheader(iptag)
