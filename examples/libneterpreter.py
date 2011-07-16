#!/usr/bin/python

# libneterpreter - interactive libnet interpreter
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

# Nadeem Douba <ndouba at gmail dot com>
# 348 Patricia Ave, Ottawa, ON, K1Z 6G6
# Canada

import getopt

import sys

from code import InteractiveConsole

import libnet
from libnet.constants import *

import rlcompleter
import readline


def usage():
	print "\nUsage: %s -i <device> [-t <type>]" % sys.argv[0]
	print "\nOptions:\n"
	print "  -i <device>  -  Where <device> is the interface's device name (e.g. 'eth0') that will be used to inject packets"
	print "  -t <type>    -  Where <type> is the injection type (default: RAW). Can be one of the following:"
	print "                  LINK, LINK_ADV, RAW4, RAW4_ADV, RAW6, or RAW6_ADV.\n"



def parseargs(argv):
	try:
		opts, args = getopt.getopt(argv, "hi:t:", ["device=", "type="])
	except getopt.GetoptError as err:
		# print help information and exit:
		print(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(2)

	device = None
	injection_type = RAW4

	for o, a in opts:
		if o in ("-i", "--device"):
			device = a
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		elif o in ("-t", "--type"):
			if a.upper() in ("LINK", "LINK_ADV", "RAW4", "RAW4_ADV", "RAW6", "RAW6_ADV"):
				injection_type = locals()[a.upper()]
			else:
				print "Invalid injection type: %s" % a.upper()
				usage()
				sys.exit(2)

	if device is None:
		print "You must specify an interface."
		usage()
		sys.exit()

	return device, injection_type


def main(argv, locals=None):

	device, injection_type = parseargs(argv)

	# Setup readline for easy function reference
	readline.parse_and_bind("tab: complete")

	# Initialize libnet context
	try:
		c = libnet.context(device=device, injection_type=injection_type)
	except libnet.error as err:
		print(err)
		sys.exit(-1)

	sys.ps1 = 'libnet> '
	
	# Create some easy aliases for everything
	for i in dir(c):
		if i.startswith('build_'):
			locals[i.replace('build_','',1)] = eval('c.%s' % i)
		elif i.startswith('autobuild_'):
			locals[i.replace('build','',1)] = eval('c.%s' % i)
		elif i.startswith('get'):
			locals[i.replace('get','',1)] = eval('c.%s' % i)
		elif i.startswith('diag_'):
			locals[i.replace('diag_','',1)] = eval('c.%s' % i)
		if i.startswith('__') == False:
			locals[i] = eval('c.%s' % i)

	# Spawn the libnet shell
	c = InteractiveConsole(locals=locals)
	c.interact(banner='Welcome to the libnet interactive console.\nAuthor: Nadeem Douba\n')

if __name__ == '__main__':

	main(sys.argv[1:], locals())
