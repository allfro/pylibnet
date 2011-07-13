#!/usr/bin/python

from distutils.core import setup, Extension
import re
import os
import sys

include_dir = None
lib_dir = None

prefixes = ['/usr','/usr/local','/sw','/opt/local']

print 'Searching for libnet...'
for p in prefixes:
	if os.path.isfile(p+os.sep+'include'+os.sep+'libnet.h'):
		include_dir = p+os.sep+'include'
		break

if include_dir is None:
	print 'Could not locate the include file "libnet.h"'
	sys.exit(-1);

for p in prefixes:
	if os.path.isfile(p+os.sep+'lib'+os.sep+'libnet.a'):
		lib_dir = p+os.sep+'lib'
		break

if lib_dir is None:
	print 'Could not locate the static library "libnet.a"'
	sys.exit(-1)

version = ''
try:
	f = open(include_dir+os.sep+'libnet.h')
	for l in f:
		if l.find('LIBNET_VERSION') != -1:
			version = l
			break;
except:
	print 'Could not open "libnet.h" to check for version number.'
	sys.exit(-1)

version_nums = re.findall('\d+', version)

defines = [
		('LIBNET_MAJOR_VERSION', version_nums[0]),
		('LIBNET_MINOR_VERSION', version_nums[1]),
		('LIBNET_RELEASE', version_nums[2]),
    ('MAJOR_VERSION', '2'),
    ('MINOR_VERSION', '0')
]


libnet_module = Extension('libnet',
    define_macros = defines,
    include_dirs = [include_dir],
    libraries = ['net'],
    library_dirs = [lib_dir],
    sources = ['src/libnetmodule.c'])

setup (name = 'pylibnet',
    version = '2.0-beta-rc10',
    description = 'Python Libnet Extension',
    author = 'Nadeem Douba',
		license = 'GNU GPL',
    author_email = 'ndouba@cygnos.com',
    url = 'http://pylibnet.sourceforge.net',
    long_description = '''
    Python extension for the Libnet packet injection library.
    ''',
    ext_modules = [libnet_module])
