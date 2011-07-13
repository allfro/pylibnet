/*
 pylibnet - Python module for the libnet packet injection library
 Copyright (C) 2009  Nadeem Douba

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 Nadeem Douba <ndouba at gmail dot com>
 348 Patricia Ave, Ottawa, ON, K1Z 6G6
 Canada
*/


typedef struct {
	PyObject_HEAD
	libnet_t *l;
	u_int8_t *ipaddr4;
	u_int8_t *ipaddr6;
	u_int8_t *hwaddr;
} context;

static void
context_dealloc(context *self)
{
	libnet_destroy(self->l);
	free(self->ipaddr4);
	free(self->ipaddr6);
	self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
context_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{

	context *self;

	self = (context *)type->tp_alloc(type, 0);
	
	return (PyObject *)self;

}

static int
context_init(context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t ipaddr4;
	struct libnet_in6_addr ipaddr6;
	char err_buf[LIBNET_ERRBUF_SIZE];
	char *device=NULL;
	int injection_type=LIBNET_LINK;

	static char *kwlist[] = {"injection_type", "device", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|is", kwlist, 
				&injection_type, &device))
		return -1; 

	if (device == NULL) {
		PyErr_SetString(PyErr_LibnetError, "A device name must be specified.");
		return -1;
	}

	self->l = libnet_init(injection_type, device, err_buf);

	if (self->l == NULL) {
		PyErr_SetString(PyErr_LibnetError, err_buf);
		return -1;
	}

	ipaddr4 = libnet_get_ipaddr4(self->l);
	if (ipaddr4 == 0xFFFF) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return -1;
	}

	self->ipaddr4 = (u_int8_t *)malloc(sizeof(u_int32_t));
	memcpy((void *)self->ipaddr4, (const void *)&ipaddr4, sizeof(u_int32_t));

	ipaddr6 = libnet_get_ipaddr6(self->l);
	self->ipaddr6 = (u_int8_t *)malloc(sizeof(struct libnet_in6_addr));
	memcpy((void *)self->ipaddr6, (const void *)&ipaddr6, sizeof(struct libnet_in6_addr));

	self->hwaddr = (u_int8_t *)libnet_get_hwaddr(self->l);

	if (self->hwaddr == NULL) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return -1;
	}

	if (libnet_seed_prand(self->l) == -1) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return -1;
	}

	return 0;

}

#include "builders.c"
#include "misc.c"

static PyMemberDef context_members[] = {
	{NULL}  /* Sentinel */
};

PyDoc_STRVAR(context_doc,
		"context(injection_type, device)\n\nCreates the libnet environment. It initializes the library and returns a \n"
			"libnet context. If the injection_type is LINK or LINK_ADV, the\n"
			"function initializes the injection primitives for the link-layer interface\n"
			"enabling the application programmer to build packets starting at the\n"
			"data-link layer (which also provides more granular control over the IP\n"
			"layer). If libnet uses the link-layer and the device argument is non-None,\n"
			"the function attempts to use the specified network device for packet\n"
			"injection. This is either a canonical string that references the device\n"
			"(such as \"eth0\" for a 100MB Ethernet card on Linux or \"fxp0\" for a 100MB\n"
			"Ethernet card on OpenBSD) or the dots and decimals representation of the\n"
			"device's IP address (192.168.0.1). If device is None, libnet attempts to\n"
			"find a suitable device to use. If the injection_type is RAW4 or\n"
			"RAW4_ADV, the function initializes the injection primitives for the\n"
			"IPv4 raw socket interface. The final argument, err_buf, should be a buffer\n"
			"of size ERRBUF_SIZE and holds an error message if the function fails.\n"
			"This function requires root privileges to execute successfully. Upon\n"
			"success, the function returns a valid libnet context for use in later\n"
			"function calls; upon failure, the function returns None.\n"
			"\nParameters:\n\n"
			"injection_type - packet injection type (LINK, LINK_ADV, RAW4, RAW4_ADV, RAW6, RAW6_ADV)\n"
			"device - the interface to use (None and libnet will choose one)\n"
			"\nReturns: libnet context ready for use or None on error.\n\n");

static PyMethodDef context_methods[] = {
	{
		"diag_dump_context", (PyCFunction)context_diag_dump_context, METH_NOARGS, NULL
	},
	{
		"diag_dump_pblock", (PyCFunction)context_diag_dump_pblock, METH_NOARGS, NULL
	},
	{
		"diag_dump_hex", (PyCFunction)context_diag_dump_hex, METH_VARARGS | METH_KEYWORDS, NULL
	},
	{
		"destroy", (PyCFunction)context_dealloc, METH_NOARGS,
		"Shuts down the libnet session referenced by l. It closes the network \n"
			"interface and frees all internal memory structures associated with l.  \n"
	},
	{
		"clear_packet", (PyCFunction)context_clear_packet, METH_NOARGS,
		"Clears the current packet referenced and frees all pblocks. Should be\n"
			"called when the programmer want to send a completely new packet of\n"
			"a different type using the same context.\n"
	},
	{
		"stats", (PyCFunction)context_stats, METH_NOARGS,
		"Fills in a stats structure with packet injection statistics\n"
			"(packets written, bytes written, packet sending errors).\n"
			"\nReturns: a dictionary containing the transmission statistics."
	},
	{
		"getfd", (PyCFunction)context_getfd, METH_NOARGS,
		"Returns the FILENO of the file descriptor used for packet injection.\n"
			"\nReturns: the file number of the file descriptor used for packet injection"
	},
	{
		"getdevice", (PyCFunction)context_getdevice, METH_NOARGS,
		"Returns the canonical name of the device used for packet injection.\n"
			"it can be None without being an error.\n"
			"\nReturns: the canonical name of the device used for packet injection. Note "
	},
	{
		"getpbuf", (PyCFunction)context_getpbuf, METH_VARARGS | METH_KEYWORDS,
		"Returns the pblock buffer contents for the specified ptag; a\n"
			"subsequent call to getpbuf_size() should be made to determine the\n"
			"size of the buffer.\n"
			"\nParameters:\n\n"
			"ptag - the ptag reference number\n"
			"\nReturns: a pointer to the pblock buffer or None on error"
	},
	{
		"getpbuf_size", (PyCFunction)context_getpbuf_size, METH_VARARGS | METH_KEYWORDS,
		"Returns the pblock buffer size for the specified ptag; a\n"
			"previous call to getpbuf() should be made to pull the actual buffer\n"
			"contents.\n"
			"\nParameters:\n\n"
			"ptag - the ptag reference number\n"
			"\nReturns: the size of the pblock buffer"
	},
	{
		"geterror", (PyCFunction)context_geterror, METH_NOARGS,
		"Returns the last error set inside of the referenced libnet context. This\n"
			"function should be called anytime a function fails or an error condition\n"
			"is detected inside of libnet.\n"
			"\nReturns: an error string or None if no error has occured"
	},
	{
		"getheader_size", (PyCFunction)context_getheader_size, METH_NOARGS,
		"Returns the sum of the size of all of the pblocks inside of the context (this should\n"
			"be the resuling packet size).\n"
			"\nReturns: the size of the packet in l"
	},
	{
		"seed_prand", (PyCFunction)context_seed_prand, METH_NOARGS,
		"Seeds the psuedo-random number generator.\n"
			"\nReturns: 1 on success, -1 on failure"
	},
	{
		"get_prand", (PyCFunction)context_get_prand, METH_VARARGS | METH_KEYWORDS,
		"Generates an unsigned psuedo-random value within the range specified by\n"
			"mod.\n"
			"PR2    0 - 1\n"
			"PR8    0 - 255\n"
			"PR16   0 - 32767\n"
			"PRu16  0 - 65535\n"
			"PR32   0 - 2147483647\n"
			"PRu32  0 - 4294967295\n"
			"\nParameters:\n\n"
			"mod - one of the PR* constants\n"
			"\nReturns: 1 on success, -1 on failure" 
	},
	{
		"toggle_checksum", (PyCFunction)context_toggle_checksum, METH_VARARGS | METH_KEYWORDS,
		"If a given protocol header is built with the checksum field set to \"0\", by\n"
			"default libnet will calculate the header checksum prior to injection. If the\n"
			"header is set to any other value, by default libnet will not calculate the\n"
			"header checksum. To over-ride this behavior, use toggle_checksum().\n"
			"Switches auto-checksumming on or off for the specified ptag. If mode is set\n"
			"to ON, libnet will mark the specificed ptag to calculate a checksum \n"
			"for the ptag prior to injection. This assumes that the ptag refers to a \n"
			"protocol that has a checksum field. If mode is set to OFF, libnet\n"
			"will clear the checksum flag and no checksum will be computed prior to \n"
			"injection. This assumes that the programmer will assign a value (zero or\n"
			"otherwise) to the checksum field.  Often times this is useful if a\n"
			"precomputed checksum or some other predefined value is going to be used.\n"
			"Note that when libnet is initialized with RAW4, the IPv4 header\n"
			"checksum will always be computed by the kernel prior to injection, \n"
			"regardless of what the programmer sets.\n"
			"\nParameters:\n\n"
			"ptag - the ptag reference number\n"
			"mode - ON or OFF\n"
			"\nReturns: 1 on success, -1 on failure"
	},
	{
		"addr2name4", (PyCFunction)context_addr2name4, METH_VARARGS | METH_KEYWORDS,
		"Takes a network byte ordered IPv4 address and returns a pointer to either a \n"
			"canonical DNS name (if it has one) or a string of dotted decimals. This may\n"
			"incur a DNS lookup if the hostname and mode is set to RESOLVE. If\n"
			"mode is set to DONT_RESOLVE, no DNS lookup will be performed and\n"
			"the function will return a pointer to a dotted decimal string. The function\n"
			"cannot fail -- if no canonical name exists, it will fall back on returning\n"
			"a dotted decimal string. This function is non-reentrant.\n"
			"\nParameters:\n\n"
			"in - network byte ordered IPv4 address\n"
			"use_name - RESOLVE or DONT_RESOLVE\n"
			"\nReturns: a pointer to presentation format string"
	},
	{
		"name2addr4", (PyCFunction)context_name2addr4, METH_VARARGS | METH_KEYWORDS,
		"Takes a dotted decimal string or a canonical DNS name and returns a \n"
			"network byte ordered IPv4 address. This may incur a DNS lookup if mode is\n"
			"set to RESOLVE and host_name refers to a canonical DNS name. If mode\n"
			"is set to DONT_RESOLVE no DNS lookup will occur. The function can\n"
			"fail if DNS lookup fails or if mode is set to DONT_RESOLVE and\n"
			"host_name refers to a canonical DNS name.\n"
			"name\n"
			"\nParameters:\n\n"
			"host_name - pointer to a string containing a presentation format host\n"
			"use_name - RESOLVE or DONT_RESOLVE\n"
			"\nReturns: network byte ordered IPv4 address or -1 (2^32 - 1) on error "
	},
	{
		"name2addr6", (PyCFunction)context_name2addr6, METH_VARARGS | METH_KEYWORDS,
		"Takes a dotted decimal string or a canonical DNS name and returns a \n"
			"network byte ordered IPv6 address. This may incur a DNS lookup if mode is\n"
			"set to RESOLVE and host_name refers to a canonical DNS name. If mode\n"
			"is set to DONT_RESOLVE no DNS lookup will occur. The function can\n"
			"fail if DNS lookup fails or if mode is set to DONT_RESOLVE and\n"
			"host_name refers to a canonical DNS name.\n"
			"name\n"
			"\nParameters:\n\n"
			"host_name - pointer to a string containing a presentation format host\n"
			"use_name - RESOLVE or DONT_RESOLVE\n"
			"\nReturns: network byte ordered IPv6 address structure "
	},
	{
		"addr2name6_r", (PyCFunction)context_addr2name6_r, METH_VARARGS | METH_KEYWORDS,
		"Takes a network byte ordered IPv6 address and returns a pointer to either a \n"
			"canonical DNS name (if it has one) or a string of dotted decimals. This may\n"
			"incur a DNS lookup if the hostname and mode is set to RESOLVE. If\n"
			"mode is set to DONT_RESOLVE, no DNS lookup will be performed and\n"
			"the function will return a pointer to a dotted decimal string. The function\n"
			"cannot fail -- if no canonical name exists, it will fall back on returning\n"
			"a dotted decimal string. This function is non-reentrant.\n"
			"\nParameters:\n\n"
			"in - network byte ordered IPv6 address\n"
			"use_name - RESOLVE or DONT_RESOLVE\n"
			"\nReturns: a pointer to presentation format string"
	},
	{
		"addr2name6", (PyCFunction)context_addr2name6_r, METH_VARARGS | METH_KEYWORDS,
		"An alias for addr2name6_r."
	},/*
	{
		"plist_chain_new", (PyCFunction)context_plist_chain_new, METH_VARARGS | METH_KEYWORDS,
		"Creates a new port list. Port list chains are useful for TCP and UDP-based\n"
			"applications that need to send packets to a range of ports (contiguous or\n"
			"otherwise). The port list chain, which token_list points to, should contain\n"
			"a series of int8_tacters from the following list: \"0123456789,-\" of the\n"
			"general format \"x - y, z\", where \"xyz\" are port numbers between 0 and \n"
			"65,535. plist points to the front of the port list chain list for use in \n"
			"further plist_chain() functions. Upon success, the function returns\n"
			"1. Upon failure, the function returns -1 and geterror() can tell you\n"
			"why.\n"
			"\nParameters:\n\n"
			"plist - if successful, will refer to the portlist, if not, None\n"
			"token_list - string containing the port list primitive\n"
			"\nReturns: 1 on success, -1 on failure"
	},
	{
		"plist_chain_next_pair", (PyCFunction)context_plist_chain_next_pair, METH_VARARGS | METH_KEYWORDS,
		"Returns the next port list chain pair from the port list chain plist. bport\n"
			"and eport contain the starting port number and ending port number, \n"
			"respectively. Upon success, the function returns 1 and fills in the port\n"
			"variables; however, if the list is empty, the function returns 0 and sets \n"
			"both port variables to 0. Upon failure, the function returns -1.\n"
			"\nParameters:\n\n"
			"plist - previously created portlist\n"
			"bport - will contain the beginning port number or 0\n"
			"eport - will contain the ending port number or 0\n"
			"\nReturns: 1 on success, 0 if empty, -1 on failure"
	},
	{
		"plist_chain_dump", (PyCFunction)context_plist_chain_dump, METH_VARARGS | METH_KEYWORDS,
		"Runs through the port list and prints the contents of the port list chain\n"
			"list to stdout.\n"
			"\nParameters:\n\n"
			"plist - previously created portlist\n"
			"\nReturns: 1 on success, -1 on failure"
	},
	{
		"plist_chain_dump_string", (PyCFunction)context_plist_chain_dump_string, METH_VARARGS | METH_KEYWORDS,
		"Runs through the port list and prints the contents of the port list chain\n"
			"list to string. This function uses strdup and is not re-entrant.  It also\n"
			"has a memory leak and should not really be used.\n"
			"None on error\n"
			"\nParameters:\n\n"
			"plist - previously created portlist\n"
			"\nReturns: a printable string containing the port list contents on success"
	},
	{
		"plist_chain_free", (PyCFunction)context_plist_chain_free, METH_VARARGS | METH_KEYWORDS,
		"Frees all memory associated with port list chain.\n"
			"\nParameters:\n\n"
			"plist - previously created portlist\n"
			"\nReturns: 1 on success, -1 on failure"
	},*/
	{
		"build_802_1q", (PyCFunction)context_build_802_1q, METH_VARARGS | METH_KEYWORDS,
		"Builds an IEEE 802.1q VLAN tagging header. Depending on the value of\n"
			"len_proto, the function wraps the 802.1q header inside either an IEEE 802.3\n"
			"header or an RFC 894 Ethernet II (DIX) header (both resulting in an 18-byte\n"
			"frame). If len is 1500 or less, most receiving protocol stacks parse the\n"
			"frame as an IEEE 802.3 encapsulated frame. If len is one of the Ethernet type\n"
			"values, most protocol stacks parse the frame as an RFC 894 Ethernet II\n"
			"encapsulated frame. Note the length value is calculated without the 802.1q\n"
			"header of 18 bytes.\n"
			"\nParameters:\n\n"
			"dst - pointer to a six byte source ethernet address\n"
			"src - pointer to a six byte destination ethernet address\n"
			"tpi - tag protocol identifier\n"
			"priority - priority\n"
			"cfi - canonical format indicator\n"
			"vlan_id - vlan identifier\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_802_1x", (PyCFunction)context_build_802_1x, METH_VARARGS | METH_KEYWORDS,
		"Builds an IEEE 802.1x extended authentication protocol header.\n"
			"\nParameters:\n\n"
			"eap_ver - the EAP version\n"
			"eap_type - the EAP type\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_802_2", (PyCFunction)context_build_802_2, METH_VARARGS | METH_KEYWORDS,
		"Builds an IEEE 802.2 LLC header.\n"
			"\nParameters:\n\n"
			"dsap - destination service access point\n"
			"ssap - source service access point\n"
			"control - control field\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_802_2snap", (PyCFunction)context_build_802_2snap, METH_VARARGS | METH_KEYWORDS,
		"Builds an IEEE 802.2 LLC SNAP header.\n"
			"\nParameters:\n\n"
			"dsap - destination service access point\n"
			"ssap - source service access point\n"
			"control - control field\n"
			"oui - Organizationally Unique Identifier\n"
			"type - upper layer protocol\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_802_3", (PyCFunction)context_build_802_3, METH_VARARGS | METH_KEYWORDS,
		"Builds an IEEE 802.3 header. The 802.3 header is almost identical to the \n"
			"RFC 894 Ethernet II header, the exception being that the field immediately\n"
			"following the source address holds the frame's length (as opposed to the\n"
			"layer 3 protocol). You should only use this function when libnet is\n"
			"initialized with the LINK interface.\n"
			"\nParameters:\n\n"
			"dst - destination ethernet address\n"
			"src - source ethernet address\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ethernet", (PyCFunction)context_build_ethernet, METH_VARARGS | METH_KEYWORDS,
		"Builds an Ethernet header. The RFC 894 Ethernet II header is almost \n"
			"identical to the IEEE 802.3 header, with the exception that the field \n"
			"immediately following the source address holds the layer 3 protocol (as\n"
			"opposed to frame's length). You should only use this function when \n"
			"libnet is initialized with the LINK interface. \n"
			"\nParameters:\n\n"
			"dst - destination ethernet address\n"
			"src - source ethernet address\n"
			"type - upper layer protocol type\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"autobuild_ethernet", (PyCFunction)context_autobuild_ethernet, METH_VARARGS | METH_KEYWORDS,
		"Autobuilds an Ethernet header. The RFC 894 Ethernet II header is almost \n"
			"identical to the IEEE 802.3 header, with the exception that the field \n"
			"immediately following the source address holds the layer 3 protocol (as\n"
			"opposed to frame's length). You should only use this function when \n"
			"libnet is initialized with the LINK interface. \n"
			"\nParameters:\n\n"
			"dst - destination ethernet address\n"
			"type - upper layer protocol type\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_fddi", (PyCFunction)context_build_fddi, METH_VARARGS | METH_KEYWORDS,
		"Builds a Fiber Distributed Data Interface (FDDI) header.\n"
			"\nParameters:\n\n"
			"dst - destination fddi address\n"
			"src - source fddi address\n"
			"fc - class format and priority\n"
			"dsap - destination service access point\n"
			"ssap - source service access point\n"
			"cf - cf\n"
			"oui - 3 byte IEEE organizational code\n"
			"type - upper layer protocol \n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"autobuild_fddi", (PyCFunction)context_autobuild_fddi, METH_VARARGS | METH_KEYWORDS,
		"Autobuilds a Fiber Distributed Data Interface (FDDI) header.\n"
			"\nParameters:\n\n"
			"dst - destination fddi address\n"
			"fc - class format and priority\n"
			"dsap - destination service access point\n"
			"ssap - source service access point\n"
			"cf - cf\n"
			"oui - IEEE organizational code\n"
			"type - upper layer protocol \n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_arp", (PyCFunction)context_build_arp, METH_VARARGS | METH_KEYWORDS,
		"Builds an Address Resolution Protocol (ARP) header.  Depending on the op \n"
			"value, the function builds one of several different types of RFC 826 or\n"
			"RFC 903 RARP packets.\n"
			"\nParameters:\n\n"
			"hrd - hardware address format\n"
			"pro - protocol address format\n"
			"hln - hardware address length\n"
			"pln - protocol address length\n"
			"op - ARP operation type\n"
			"sha - sender's hardware address\n"
			"spa - sender's protocol address\n"
			"tha - target hardware address\n"
			"tpa - targer protocol address\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"autobuild_arp", (PyCFunction)context_autobuild_arp, METH_VARARGS | METH_KEYWORDS,
		"Autouilds an Address Resolution Protocol (ARP) header.  Depending on the op \n"
			"value, the function builds one of several different types of RFC 826 or\n"
			"RFC 903 RARP packets.\n"
			"\nParameters:\n\n"
			"op - ARP operation type\n"
			"sha - sender's hardware address\n"
			"spa - sender's protocol address\n"
			"tha - target hardware address\n"
			"tpa - targer protocol address\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_tcp", (PyCFunction)context_build_tcp, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 793 Transmission Control Protocol (TCP) header.\n"
			"\nParameters:\n\n"
			"len - total length of the TCP packet (for checksum calculation)\n"
			"sp - source port\n"
			"dp - destination port\n"
			"seq - sequence number\n"
			"ack - acknowledgement number\n"
			"control - control flags\n"
			"win - window size\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"urg - urgent pointer\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_tcp_options", (PyCFunction)context_build_tcp_options, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 793 Transmission Control Protocol (TCP) options header.\n"
			"The function expects options to be a valid TCP options string of size \n"
			"options_s, which is no larger than 40 bytes (the maximum size of an \n"
			"options string). The function checks to ensure that the packet consists of \n"
			"a TCP header preceded by an IPv4 header, and that the addition of the\n"
			"options string would not result in a packet larger than 65,535 bytes\n"
			"(IPMAXPACKET). The function counts up the number of 32-bit words in the\n"
			"options string and adjusts the TCP header length value as necessary.\n"
			"\nParameters:\n\n"
			"options - byte string of TCP options\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_udp", (PyCFunction)context_build_udp, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 768 User Datagram Protocol (UDP) header.\n"
			"\nParameters:\n\n"
			"sp - source port\n"
			"dp - destination port\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_cdp", (PyCFunction)context_build_cdp, METH_VARARGS | METH_KEYWORDS,
		"Builds a Cisco Discovery Protocol (CDP) header. Cisco Systems designed CDP\n"
			"to aid in the network management of adjacent Cisco devices. The CDP protocol\n"
			"specifies data by using a type/length/value (TLV) setup. The first TLV can\n"
			"specified by using the functions type, length, and value arguments. To\n"
			"specify additional TLVs, the programmer could either use the payload \n"
			"interface or build_data() to construct them.\n"
			"\nParameters:\n\n"
			"version - CDP version\n"
			"ttl - time to live (time information should be cached by recipient)\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"type - type of data contained in value\n"
			"value - the CDP information string\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_icmpv4_echo", (PyCFunction)context_build_icmpv4_echo, METH_VARARGS | METH_KEYWORDS,
		"Builds an IP version 4 RFC 792 Internet Control Message Protocol (ICMP)\n"
			"echo request/reply header\n"
			"\nParameters:\n\n"
			"type - type of ICMP packet (should be ICMP_ECHOREPLY or ICMP_ECHO)\n"
			"code - code of ICMP packet (should be 0)\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"id - identification number\n"
			"seq - packet sequence number\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_icmpv4_mask", (PyCFunction)context_build_icmpv4_mask, METH_VARARGS | METH_KEYWORDS,
		"Builds an IP version 4 RFC 792 Internet Control Message Protocol (ICMP)\n"
			"IP netmask request/reply header.\n"
			"\nParameters:\n\n"
			"type - type of ICMP packet (should be ICMP_MASKREQ or ICMP_MASKREPLY)\n"
			"code - code of ICMP packet (should be 0)\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"id - identification number\n"
			"seq - packet sequence number\n"
			"mask - subnet mask\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_icmpv4_unreach", (PyCFunction)context_build_icmpv4_unreach, METH_VARARGS | METH_KEYWORDS,
		"Builds an IP version 4 RFC 792 Internet Control Message Protocol (ICMP)\n"
			"unreachable header. The IP header that caused the error message should be \n"
			"built by a previous call to build_ipv4().\n"
			"\nParameters:\n\n"
			"type - type of ICMP packet (should be ICMP_UNREACH)\n"
			"code - code of ICMP packet (should be one of the 16 unreachable codes)\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_icmpv4_redirect", (PyCFunction)context_build_icmpv4_redirect, METH_VARARGS | METH_KEYWORDS,
		"Builds an IP version 4 RFC 792 Internet Message Control Protocol (ICMP) \n"
			"redirect header.  The IP header that caused the error message should be \n"
			"built by a previous call to build_ipv4().\n"
			"\nParameters:\n\n"
			"type - type of ICMP packet (should be ICMP_REDIRECT)\n"
			"code - code of ICMP packet (should be one of the four redirect codes)\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"gateway - network byte-order gateway IPv4 address\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_icmpv4_timeexceed", (PyCFunction)context_build_icmpv4_timeexceed, METH_VARARGS | METH_KEYWORDS,
		"Builds an IP version 4 RFC 792 Internet Control Message Protocol (ICMP) time\n"
			"exceeded header.  The IP header that caused the error message should be \n"
			"built by a previous call to build_ipv4().\n"
			"\nParameters:\n\n"
			"type - type of ICMP packet (should be ICMP_TIMXCEED)\n"
			"code - code of ICMP packet (ICMP_TIMXCEED_INTRANS / ICMP_TIMXCEED_REASS)\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"payload - optional payload or None\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_icmpv4_timestamp", (PyCFunction)context_build_icmpv4_timestamp, METH_VARARGS | METH_KEYWORDS,
		"Builds an IP version 4 RFC 792 Internet Control Message Protocol (ICMP)\n"
			"timestamp request/reply header.\n"
			"\nParameters:\n\n"
			"type - type of ICMP packet (should be ICMP_TSTAMP or ICMP_TSTAMPREPLY)\n"
			"code - code of ICMP packet (should be 0)\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"id - identification number\n"
			"seq - sequence number\n"
			"otime - originate timestamp\n"
			"rtime - receive timestamp\n"
			"ttime - transmit timestamp\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_igmp", (PyCFunction)context_build_igmp, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 1112 Internet Group Memebership Protocol (IGMP) header.\n"
			"\nParameters:\n\n"
			"type - packet type\n"
			"code - packet code (should be 0)\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"ip - IPv4 address\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipv4", (PyCFunction)context_build_ipv4, METH_VARARGS | METH_KEYWORDS,
		"Builds a version 4 RFC 791 Internet Protocol (IP) header.\n"
			"\nParameters:\n\n"
			"tos - type of service bits\n"
			"id - IP identification number\n"
			"frag - fragmentation bits and offset\n"
			"ttl - time to live in the network\n"
			"prot - upper layer protocol\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"src - source IPv4 address (little endian)\n"
			"dst - destination IPv4 address (little endian)\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipv4_options", (PyCFunction)context_build_ipv4_options, METH_VARARGS | METH_KEYWORDS,
		"Builds an version 4 Internet Protocol (IP) options header. The function \n"
			"expects options to be a valid IP options string of size options_s, no larger\n"
			"than 40 bytes (the maximum size of an options string). The function checks \n"
			"to make sure that the preceding header is an IPv4 header and that the \n"
			"options string would not result in a packet larger than 65,535 bytes \n"
			"(IPMAXPACKET). The function counts up the number of 32-bit words in the \n"
			"options string and adjusts the IP header length value as necessary.\n"
			"\nParameters:\n\n"
			"options - byte string of IP options\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"autobuild_ipv4", (PyCFunction)context_autobuild_ipv4, METH_VARARGS | METH_KEYWORDS,
		"Autobuilds a version 4 Internet Protocol (IP) header. The function is useful  * to build an IP header quickly when you do not need a granular level of\n"
			"control. The function takes the same len, prot, and dst arguments as \n"
			"build_ipv4(). The function does not accept a ptag argument, but it\n"
			"does return a ptag. In other words, you can use it to build a new IP header\n"
			"but not to modify an existing one.\n"
			"\nParameters:\n\n"
			"prot - upper layer protocol\n"
			"dst - destination IPv4 address (little endian)\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipv6", (PyCFunction)context_build_ipv6, METH_VARARGS | METH_KEYWORDS,
		"Builds a version 6 RFC 2460 Internet Protocol (IP) header.\n"
			"\nParameters:\n\n"
			"tc - traffic class\n"
			"fl - flow label\n"
			"nh - next header\n"
			"hl - hop limit\n"
			"src - source IPv6 address\n"
			"dst - destination IPv6 address\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipv6_frag", (PyCFunction)context_build_ipv6_frag, METH_VARARGS | METH_KEYWORDS,
		"Builds a version 6 RFC 2460 Internet Protocol (IP) fragmentation header.\n"
			"\nParameters:\n\n"
			"nh - next header\n"
			"reserved - unused value... OR IS IT!\n"
			"frag - fragmentation bits (ala ipv4)\n"
			"id - packet identification\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipv6_routing", (PyCFunction)context_build_ipv6_routing, METH_VARARGS | METH_KEYWORDS,
		"Builds a version 6 RFC 2460 Internet Protocol (IP) routing header. This\n"
			"function is special in that it uses the payload interface to include the \n"
			"type-specific data; that is the routing information. Most often this will\n"
			"be a number of 128-bit IPv6 addresses. The application programmer will build\n"
			"a byte string of IPv6 address and pass them to the function using the\n"
			"payload interface.\n"
			"\nParameters:\n\n"
			"rtype - routing header type\n"
			"nh - next header\n"
			"segments - number of routing segments that follow\n"
			"payload - optional payload of routing information\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipv6_destopts", (PyCFunction)context_build_ipv6_destopts, METH_VARARGS | METH_KEYWORDS,
		"Builds a version 6 RFC 2460 Internet Protocol (IP) destination options\n"
			"header. This function is special in that it uses the payload interface to\n"
			"include the options data. The application programmer will build an IPv6 \n"
			"options byte string and pass it to the function using the payload interface.\n"
			"\nParameters:\n\n"
			"nh - next header\n"
			"payload - options payload\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipv6_hbhopts", (PyCFunction)context_build_ipv6_hbhopts, METH_VARARGS | METH_KEYWORDS,
		"Builds a version 6 RFC 2460 Internet Protocol (IP) hop by hop options\n"
			"header. This function is special in that it uses the payload interface to\n"
			"include the options data. The application programmer will build an IPv6\n"
			"hop by hop options byte string and pass it to the function using the payload\n"
			"interface.\n"
			"\nParameters:\n\n"
			"nh - next header\n"
			"payload - options payload\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"autobuild_ipv6", (PyCFunction)context_autobuild_ipv6, METH_VARARGS | METH_KEYWORDS,
		"This function is not yet implement and is a NONOP.\n"
			"\nParameters:\n\n"
			"nh - next header\n"
			"dst - destination IPv6 address\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_isl", (PyCFunction)context_build_isl, METH_VARARGS | METH_KEYWORDS,
		"Builds a Cisco Inter-Switch Link (ISL) header.\n"
			"\nParameters:\n\n"
			"dhost - destination address (should be 01:00:0c:00:00)\n"
			"type - type of frame\n"
			"user - user defined data\n"
			"shost - source mac address\n"
			"snap - SNAP information (0xaaaa03 + vendor code)\n"
			"vid - 15 bit VLAN ID, 1 bit BPDU or CDP indicator\n"
			"index - port index\n"
			"reserved - used for FDDI and token ring\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipsec_esp_hdr", (PyCFunction)context_build_ipsec_esp_hdr, METH_VARARGS | METH_KEYWORDS,
		"Builds an Internet Protocol Security Encapsulating Security Payload header.\n"
			"\nParameters:\n\n"
			"spi - security parameter index\n"
			"seq - ESP sequence number\n"
			"iv - initialization vector\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipsec_esp_ftr", (PyCFunction)context_build_ipsec_esp_ftr, METH_VARARGS | METH_KEYWORDS,
		"Builds an Internet Protocol Security Encapsulating Security Payload footer.\n"
			"\nParameters:\n\n"
			"nh - next header\n"
			"auth - authentication data\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ipsec_ah", (PyCFunction)context_build_ipsec_ah, METH_VARARGS | METH_KEYWORDS,
		"Builds an Internet Protocol Security Authentication header.\n"
			"\nParameters:\n\n"
			"nh - next header\n"
			"res - reserved\n"
			"spi - security parameter index\n"
			"seq - sequence number\n"
			"auth - authentication data\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_dnsv4", (PyCFunction)context_build_dnsv4, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 1035 version 4 DNS header. Additional DNS payload information\n"
			"should be specified using the payload interface.\n"
			"\nParameters:\n\n"
			"id - DNS packet id\n"
			"flags - control flags\n"
			"num_q - number of questions\n"
			"num_anws_rr - number of answer resource records\n"
			"num_auth_rr - number of authority resource records\n"
			"num_addi_rr - number of additional resource records\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_rip", (PyCFunction)context_build_rip, METH_VARARGS | METH_KEYWORDS,
		"Builds a Routing Information Protocol header (RFCs 1058 and 2453).\n"
			"\nParameters:\n\n"
			"cmd - command\n"
			"version - protocol version\n"
			"rd - version one: 0, version two: routing domain\n"
			"af - address family\n"
			"rt - version one: 0, version two: route tag\n"
			"addr - IPv4 address\n"
			"mask - version one: 0, version two: subnet mask\n"
			"next_hop - version one: 0, version two: next hop address\n"
			"metric - routing metric\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_rpc_call", (PyCFunction)context_build_rpc_call, METH_VARARGS | METH_KEYWORDS,
		"Builds an Remote Procedure Call (Version 2) Call message header as\n"
			"specified in RFC 1831. This builder provides the option for\n"
			"specifying the record marking which is required when used with\n"
			"streaming protocols (TCP).\n"
			"\nParameters:\n\n"
			"rm - record marking indicating the position in a stream, 0 otherwise\n"
			"xid - transaction identifier used to link calls and replies\n"
			"prog_num - remote program specification typically between 0 - 1fffffff\n"
			"prog_vers - remote program version specification\n"
			"procedure - procedure to be performed by remote program\n"
			"cflavor - authentication credential type\n"
			"clength - credential length (should be 0)\n"
			"cdata - opaque credential data (currently unused)\n"
			"vflavor - authentication verifier type\n"
			"vlength - verifier length (should be 0)\n"
			"vdata - opaque verifier data (currently unused)\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_stp_conf", (PyCFunction)context_build_stp_conf, METH_VARARGS | METH_KEYWORDS,
		"Builds an IEEE 802.1d Spanning Tree Protocol (STP) configuration header.\n"
			"STP frames are usually encapsulated inside of an 802.2 + 802.3 frame \n"
			"combination.\n"
			"\nParameters:\n\n"
			"id - protocol id\n"
			"version - protocol version\n"
			"bpdu_type - bridge protocol data unit type\n"
			"flags - flags\n"
			"root_id - root id\n"
			"root_pc - root path cost\n"
			"bridge_id - bridge id\n"
			"port_id - port id\n"
			"message_age - message age\n"
			"max_age - max age\n"
			"hello_time - hello time\n"
			"f_delay - forward delay\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_stp_tcn", (PyCFunction)context_build_stp_tcn, METH_VARARGS | METH_KEYWORDS,
		"Builds an IEEE 802.1d Spanning Tree Protocol (STP) topology change\n"
			"notification header. STP frames are usually encapsulated inside of an\n"
			"802.2 + 802.3 frame combination.\n"
			"\nParameters:\n\n"
			"id - protocol id\n"
			"version - protocol version\n"
			"bpdu_type - bridge protocol data unit type\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_token_ring", (PyCFunction)context_build_token_ring, METH_VARARGS | METH_KEYWORDS,
		"Builds a token ring header.\n"
			"\nParameters:\n\n"
			"ac - access control\n"
			"fc - frame control\n"
			"dst - destination address\n"
			"src - source address\n"
			"dsap - destination service access point\n"
			"ssap - source service access point\n"
			"cf - control field\n"
			"oui - Organizationally Unique Identifier\n"
			"type - upper layer protocol type\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"autobuild_token_ring", (PyCFunction)context_autobuild_token_ring, METH_VARARGS | METH_KEYWORDS,
		"Auto-builds a token ring header.\n"
			"\nParameters:\n\n"
			"ac - access control\n"
			"fc - frame control\n"
			"dst - destination address\n"
			"dsap - destination service access point\n"
			"ssap - source service access point\n"
			"cf - control field\n"
			"oui - Organizationally Unique Identifier\n"
			"type - upper layer protocol type\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_vrrp", (PyCFunction)context_build_vrrp, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 2338 Virtual Router Redundacy Protool (VRRP) header. Use the\n"
			"payload interface to specify address and autthentication information. To\n"
			"build a \"legal\" packet, the destination IPv4 address should be the multicast  * address 224.0.0.18, the IP TTL should be set to 255, and the IP protocol\n"
			"should be set to 112.\n"
			"\nParameters:\n\n"
			"version - VRRP version (should be 2)\n"
			"type - VRRP packet type (should be 1 -- ADVERTISEMENT)\n"
			"vrouter_id - virtual router identification\n"
			"priority - priority (higher numbers indicate higher priority)\n"
			"ip_count - number of IPv4 addresses contained in this advertisement\n"
			"auth_type - type of authentication (0, 1, 2 -- see RFC)\n"
			"advert_int - interval between advertisements\n"
			"sum - checksum (0 for libnet to autofill)\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_mpls", (PyCFunction)context_build_mpls, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 3032 Multi-Protocol Label Switching (MPLS) header.\n"
			"\nParameters:\n\n"
			"experimental - 3-bit reserved field\n"
			"bos - 1-bit bottom of stack identifier\n"
			"ttl - time to live\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ntp", (PyCFunction)context_build_ntp, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 958 Network Time Protocol (NTP) header.\n"
			"\nParameters:\n\n"
			"version - NTP protocol version\n"
			"mode - NTP mode\n"
			"stratum - stratum\n"
			"poll - polling interval\n"
			"precision - precision\n"
			"delay_interval - delay interval\n"
			"delay_frac - delay fraction\n"
			"dispersion_int - dispersion interval\n"
			"dispersion_frac - dispersion fraction\n"
			"reference_id - reference id\n"
			"ref_ts_int - reference timestamp integer\n"
			"ref_ts_frac - reference timestamp fraction\n"
			"orig_ts_int - original timestamp integer\n"
			"orig_ts_frac - original timestamp fraction\n"
			"rec_ts_int - receiver timestamp integer\n"
			"rec_ts_frac - reciever timestamp fraction\n"
			"xmt_ts_int - transmit timestamp integer\n"
			"xmt_ts_frac - transmit timestamp integer\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2", (PyCFunction)context_build_ospfv2, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2_hello", (PyCFunction)context_build_ospfv2_hello, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2_dbd", (PyCFunction)context_build_ospfv2_dbd, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2_lsr", (PyCFunction)context_build_ospfv2_lsr, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2_lsu", (PyCFunction)context_build_ospfv2_lsu, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2_lsa", (PyCFunction)context_build_ospfv2_lsa, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2_lsa_rtr", (PyCFunction)context_build_ospfv2_lsa_rtr, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2_lsa_net", (PyCFunction)context_build_ospfv2_lsa_net, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2_lsa_sum", (PyCFunction)context_build_ospfv2_lsa_sum, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_ospfv2_lsa_as", (PyCFunction)context_build_ospfv2_lsa_as, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_data", (PyCFunction)context_build_data, METH_VARARGS | METH_KEYWORDS,
		"Builds a generic libnet protocol header. This is useful for including an\n"
			"optional payload to a packet that might need to change repeatedly inside\n"
			"of a loop.\n"
			"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_dhcpv4", (PyCFunction)context_build_dhcpv4, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"opcode - operation code\n"
			"htype - hardware address type\n"
			"hlen - hardware address length\n"
			"hopcount - hop count\n"
			"xid - transaction ID\n"
			"secs - number of seconds elapsed\n"
			"flags - broadcast and reserved flags\n"
			"cip - network byte-order client IPv4 address\n"
			"yip - network byte-order your IPv4 address\n"
			"sip - network byte-order server IPv4 address\n"
			"gip - network byte-order gateway IPv4 address\n"
			"chaddr - client hardware address\n"
			"sname - server name\n"
			"file - file option for BOOTP\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_bootpv4", (PyCFunction)context_build_bootpv4, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"opcode - operation code\n"
			"htype - hardware address type\n"
			"hlen - hardware address length\n"
			"hopcount - hop count\n"
			"xid - transaction ID\n"
			"secs - number of seconds elapsed\n"
			"flags - broadcast and reserved flags\n"
			"cip - network byte-order client IPv4 address\n"
			"yip - network byte-order your IPv4 address\n"
			"sip - network byte-order server IPv4 address\n"
			"gip - network byte-order gateway IPv4 address\n"
			"chaddr - client hardware address\n"
			"sname - server name\n"
			"file - file option for BOOTP\n"
			"payload - optional payload or None\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"getgre_length", (PyCFunction)context_getgre_length, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_gre", (PyCFunction)context_build_gre, METH_VARARGS | METH_KEYWORDS,
		"Generic Routing Encapsulation (GRE - RFC 1701) is used to encapsulate any\n"
			"protocol. Hence, the IP part of the packet is usually referred as \"delivery\n"
			"header\". It is then followed by the GRE header and finally the encapsulated\n"
			"packet (IP or whatever).\n"
			"As GRE is very modular, the first GRE header describes the structure of the\n"
			"header, using bits and flag to specify which fields will be present in the\n"
			"header.\n"
			"\nParameters:\n\n"
			"fv - the 16 0 to 7: which fields are included in the header (checksum, seq. number, key, ...), bits 8 to 12: flag, bits 13 to 15: version.\n"
			"payload - optional payload or None\n"
			"type - which protocol is encapsulated (PPP, IP, ...)\n"
			"sum - checksum (0 for libnet to autofill).\n"
			"offset - byte offset from the start of the routing field to the first byte of the SRE\n"
			"key - inserted by the encapsulator to authenticate the source\n"
			"seq - sequence number used by the receiver to sort the packets\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_egre", (PyCFunction)context_build_egre, METH_VARARGS | METH_KEYWORDS,
		"Generic Routing Encapsulation (GRE - RFC 1701) is used to encapsulate any\n"
			"protocol. Hence, the IP part of the packet is usually referred as \"delivery\n"
			"header\". It is then followed by the GRE header and finally the encapsulated\n"
			"packet (IP or whatever).\n"
			"As GRE is very modular, the first GRE header describes the structure of the\n"
			"header, using bits and flag to specify which fields will be present in the\n"
			"header.\n"
			"\nParameters:\n\n"
			"fv - the 16 0 to 7: which fields are included in the header (checksum, seq. number, key, ...), bits 8 to 12: flag, bits 13 to 15: version.\n"
			"payload - optional payload or None\n"
			"type - which protocol is encapsulated (PPP, IP, ...)\n"
			"sum - checksum (0 for libnet to autofill).\n"
			"offset - byte offset from the start of the routing field to the first byte of the SRE\n"
			"key - inserted by the encapsulator to authenticate the source\n"
			"seq - sequence number used by the receiver to sort the packets\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_gre_sre", (PyCFunction)context_build_gre_sre, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_gre_last_sre", (PyCFunction)context_build_gre_last_sre, METH_VARARGS | METH_KEYWORDS,
		"\nParameters:\n\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_bgp4_header", (PyCFunction)context_build_bgp4_header, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 1771 Border Gateway Protocol 4 (BGP-4) header. The primary\n"
			"function of a BGP speaking system is to exchange network reachability\n"
			"information with other BGP systems. This network reachability information\n"
			"includes information on the list of  Autonomous Systems (ASs) that\n"
			"reachability information traverses.  This information is sufficient to\n"
			"construct a graph of AS connectivity from which routing loops may be pruned\n"
			"and some policy decisions at the AS level may be enforced.\n"
			"This function builds the base BGP header which is used as a preamble before\n"
			"any other BGP header. For example, a BGP KEEPALIVE message may be built with\n"
			"only this function, while an error notification requires a subsequent call\n"
			"to build_bgp4_notification.\n"
			"\nParameters:\n\n"
			"marker - a value the receiver can predict (if the message type is not BGP OPEN, or no authentication is used, these 16 bytes are normally set as all ones)\n"
			"type - type code of the message (OPEN, UPDATE, NOTIFICATION or KEEPALIVE)\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_bgp4_open", (PyCFunction)context_build_bgp4_open, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 1771 Border Gateway Protocol 4 (BGP-4) OPEN header. This is\n"
			"the first message sent by each side of a BGP connection. The optional\n"
			"parameters options should be constructed using the payload interface (see\n"
			"RFC 1771 for the options structures).\n"
			"\nParameters:\n\n"
			"version - protocol version (should be set to 4)\n"
			"src_as - Autonomous System of the sender\n"
			"hold_time - used to compute the maximum allowed time between the receipt of KEEPALIVE, and/or UPDATE messages by the sender\n"
			"bgp_id - BGP identifier of the sender\n"
			"opt_len - total length of the  optional parameters field in bytes\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_bgp4_update", (PyCFunction)context_build_bgp4_update, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 1771 Border Gateway Protocol 4 (BGP-4) update header. Update\n"
			"messages are used to transfer routing information between BGP peers.\n"
			"\nParameters:\n\n"
			"unfeasible_rt_len - indicates the length of the (next) \"withdrawn routes\" field in bytes\n"
			"withdrawn_rt - list of IP addresses prefixes for the routes that are being withdrawn; each IP address prefix is built as a 2-tuple <length (1 byte), prefix (variable)>\n"
			"total_path_attr_len - indicates the length of the (next) \"path attributes\" field in bytes\n"
			"path_attributes - each attribute is a 3-tuple <type (2 bytes), length, value>\n"
			"info_len - indicates the length of the (next) \"network layer reachability information\" field in bytes (needed for internal memory size calculation)\n"
			"reachability_info - 2-tuples <length (1 byte), prefix (variable)>.\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_bgp4_notification", (PyCFunction)context_build_bgp4_notification, METH_VARARGS | METH_KEYWORDS,
		"Builds an RFC 1771 Border Gateway Protocol 4 (BGP-4) notification header.\n"
			"A NOTIFICATION message is sent when an error condition is detected. Specific\n"
			"error information may be passed through the payload interface.\n"
			"\nParameters:\n\n"
			"err_code - type of notification\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"build_sebek", (PyCFunction)context_build_sebek, METH_VARARGS | METH_KEYWORDS,
		"Builds a Sebek header. The Sebek protocol was designed by the Honeynet\n"
			"Project as a transport mechanism for post-intrusion forensic data. More\n"
			"information may be found here: http://www.honeynet.org/papers/sebek.pdf.\n"
			"\nParameters:\n\n"
			"magic - identify packets that should be hidden \n"
			"version - protocol version, currently 1 \n"
			"type - type of record (read data is type 0, write data is type 1) \n"
			"counter - PDU counter used to identify when packet are lost \n"
			"time_usec - residual microseconds \n"
			"pid - PID \n"
			"uid - UID \n"
			"fd - FD \n"
			"cmd[SEBEK_CMD_LENGTH] - 12 first characters of the command \n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},/*
	{
		"build_link", (PyCFunction)context_build_link, METH_VARARGS | METH_KEYWORDS,
		"Builds a link layer header for an initialized l. The function\n"
			"determines the proper link layer header format from how l was initialized.\n"
			"The function current supports Ethernet and Token Ring link layers.\n"
			"\nParameters:\n\n"
			"dst - the destination MAC address\n"
			"src - the source MAC address\n"
			"oui - Organizationally Unique Identifier (unused for Ethernet)\n"
			"type - the upper layer protocol type\n"
			"payload - optional payload or None\n"
			"ptag - protocol tag to modify an existing header, 0 to build a new one\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},
	{
		"autobuild_link", (PyCFunction)context_autobuild_link, METH_VARARGS | METH_KEYWORDS,
		"Automatically builds a link layer header for an initialized l. The function\n"
			"determines the proper link layer header format from how l was initialized.\n"
			"The function current supports Ethernet and Token Ring link layers.\n"
			"\nParameters:\n\n"
			"dst - the destination MAC address\n"
			"oui - Organizationally Unique Identifier (unused for Ethernet)\n"
			"type - the upper layer protocol type\n"
			"\nReturns: protocol tag value on success, -1 on error"
	},*/
	{
		"write", (PyCFunction)context_write, METH_VARARGS | METH_KEYWORDS,
		"Writes a prebuilt packet to the network. The function assumes that l was\n"
			"previously initialized (via a call to init()) and that a \n"
			"previously constructed packet has been built inside this context (via one or\n"
			"more calls to the build* family of functions) and is ready to go.\n"
			"Depending on how libnet was initialized, the function will write the packet\n"
			"to the wire either via the raw or link layer interface. The function will\n"
			"also bump up the internal libnet stat counters which are retrievable via\n"
			"stats().\n"
			"\nParameters:\n\n"
			"\nReturns: the number of bytes written, -1 on error"
	},
	{
		"get_ipaddr4", (PyCFunction)context_get_ipaddr4, METH_NOARGS,
		"Returns the IP address for the device libnet was initialized with. If\n"
			"libnet was initialized without a device (in raw socket mode) the function\n"
			"will attempt to find one. If the function fails and returns -1 a call to \n"
			"geterrror() will tell you why.\n"
			"\nReturns: a big endian IP address suitable for use in a build function or -1"
	},
	{
		"get_ipaddr6", (PyCFunction)context_get_ipaddr6, METH_NOARGS,
		"This function is not yet implemented under IPv6.\n"
			"\nReturns: well, nothing yet"
	},
	{
		"get_hwaddr", (PyCFunction)context_get_hwaddr, METH_NOARGS,
		"Returns the MAC address for the device libnet was initialized with. If\n"
			"libnet was initialized without a device the function will attempt to find\n"
			"one. If the function fails and returns None a call to geterror() will\n"
			"tell you why.\n"
			"\nReturns: a pointer to the MAC address or None"
	},
	{
		"hex_aton", (PyCFunction)context_hex_aton, METH_VARARGS | METH_KEYWORDS,
		"Takes a colon separated hexidecimal address (from the command line) and\n"
			"returns a bytestring suitable for use in a build function. Note this\n"
			"function performs an implicit malloc and the return value should be freed\n"
			"after its use.\n"
			"\nParameters:\n\n"
			"s - the string to be parsed\n"
			"\nReturns: a byte string or None on failure"
	},/*
	{
		"adv_cull_packet", (PyCFunction)context_adv_cull_packet, METH_VARARGS | METH_KEYWORDS,
		"[Advanced Interface]\n"
			"Yanks a prebuilt, wire-ready packet from the given libnet context. If\n"
			"libnet was configured to do so (which it is by default) the packet will have\n"
			"all checksums written in. This function is part of the advanced interface\n"
			"and is only available when libnet is initialized in advanced mode. It is\n"
			"important to note that the function performs an implicit malloc() and a\n"
			"corresponding call to adv_free_packet() should be made to free the\n"
			"memory packet occupies. If the function fails geterror() can tell you\n"
			"why.\n"
			"\nParameters:\n\n"
			"packet - will contain the wire-ready packet\n"
			"\nReturns: 1 on success, -1 on failure  "
	},
	{
		"adv_cull_header", (PyCFunction)context_adv_cull_header, METH_VARARGS | METH_KEYWORDS,
		"[Advanced Interface] \n"
			"Pulls the header from the specified ptag from the given libnet context. This\n"
			"function is part of the advanced interface and is only available when libnet\n"
			"is initialized in advanced mode. If the function fails geterror() can\n"
			"tell you why.\n"
			"\nParameters:\n\n"
			"ptag - the ptag referencing the header to pull\n"
			"header - will contain the header\n"
			"\nReturns: 1 on success, -1 on failure"
	},
	{
		"adv_write_link", (PyCFunction)context_adv_write_link, METH_VARARGS | METH_KEYWORDS,
		"[Advanced Interface] \n"
			"Writes a packet the network at the link layer. This function is useful to\n"
			"write a packet that has been constructed by hand by the application\n"
			"programmer or, more commonly, to write a packet that has been returned by\n"
			"a call to adv_cull_packet(). This function is part of the advanced\n"
			"interface and is only available when libnet is initialized in advanced mode.\n"
			"If the function fails geterror() can tell you why.\n"
			"\nParameters:\n\n"
			"packet - a pointer to the packet to inject\n"
			"\nReturns: the number of bytes written, or -1 on failure"
	},
	{
		"adv_free_packet", (PyCFunction)context_adv_free_packet, METH_VARARGS | METH_KEYWORDS,
		"[Advanced Interface] \n"
			"Frees the memory allocated when adv_cull_packet() is called.\n"
			"\nParameters:\n\n"
			"packet - a pointer to the packet to free\n"
			"\nReturns: the number of bytes written, or -1 on failure"
	},
	{
		"cq_add", (PyCFunction)context_cq_add, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Adds a new context to the libnet context queue. If no queue exists, this\n"
			"function will create the queue and add the specified libnet context as the\n"
			"first entry on the list. The functions checks to ensure niether l nor label\n"
			"are None, and that label doesn't refer to an existing context already in the\n"
			"queue. Additionally, l should refer to a libnet context previously\n"
			"initialized with a call to init(). If the context queue in write\n"
			"locked, this function will fail.\n"
			"\nParameters:\n\n"
			"\nReturns: 1 on success, -1 on failure"
	},
	{
		"cq_remove", (PyCFunction)context_cq_remove, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Removes a specified context from the libnet context queue by specifying the\n"
			"libnet context pointer. Note the function will remove the specified context\n"
			"from the context queue and cleanup internal memory from the queue, it is up\n"
			"to the application programmer to free the returned libnet context with a\n"
			"call to destroy(). Also, as it is not necessary to keep the libnet\n"
			"context pointer when initially adding it to the context queue, most\n"
			"application programmers will prefer to refer to entries on the context\n"
			"queue by canonical name and would use cq_remove_by_label(). If the\n"
			"context queue is write locked, this function will fail.\n"
			"\nParameters:\n\n"
			"\nReturns: the pointer to the removed libnet context, None on failure"
	},
	{
		"cq_remove_by_label", (PyCFunction)context_cq_remove_by_label, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Removes a specified context from the libnet context queue by specifying the\n"
			"canonical name. Note the function will remove the specified context from\n"
			"the context queue and cleanup internal memory from the queue, it is up to \n"
			"the application programmer to free the returned libnet context with a call\n"
			"to destroy(). If the context queue is write locked, this function\n"
			"will fail.\n"
			"\nParameters:\n\n"
			"\nReturns: the pointer to the removed libnet context, None on failure"
	},
	{
		"cq_getlabel", (PyCFunction)context_cq_getlabel, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Returns the canonical label associated with the context.\n"
			"\nParameters:\n\n"
			"\nReturns: pointer to the libnet context's label"
	},
	{
		"cq_find_by_label", (PyCFunction)context_cq_find_by_label, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Locates a libnet context from the queue, indexed by a canonical label.\n"
			"\nParameters:\n\n"
			"\nReturns: the expected libnet context, None on failure"
	},
	{
		"cq_destroy", (PyCFunction)context_cq_destroy, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Destroys the entire context queue, calling destroy() on each\n"
			"member context.\n"
			"\nParameters:\n\n"
			"\nReturns: the expected libnet context, NULL on failure"
	},
	{
		"cq_head", (PyCFunction)context_cq_head, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Intiailizes the interator interface and set a write lock on the entire\n"
			"queue. This function is intended to be called just prior to interating\n"
			"through the entire list of contexts (with the probable intent of inject a\n"
			"series of packets in rapid succession). This function is often used as\n"
			"per the following:\n"
			"for (l = cq_head(); cq_last(); l = cq_next())\n"
			"{\n"
			"...\n"
			"}\n"
			"Much of the time, the application programmer will use the iterator as it is\n"
			"written above; as such, libnet provides a macro to do exactly that,\n"
			"for_each_context_in_cq(l). Warning: do not call the iterator more than once\n"
			"in a single loop.\n"
			"\nParameters:\n\n"
			"\nReturns: the head of the context queue"
	},
	{
		"cq_last", (PyCFunction)context_cq_last, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Check whether the iterator is at the last context in the queue.\n"
			"\nParameters:\n\n"
			"\nReturns: 1 if at the end of the context queue, 0 otherwise"
	},
	{
		"cq_next", (PyCFunction)context_cq_next, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Get next context from the context queue.\n"
			"\nParameters:\n\n"
			"\nReturns: 1 if at the end of the context queue, 0 otherwise"
	},
	{
		"cq_size", (PyCFunction)context_cq_size, METH_VARARGS | METH_KEYWORDS,
		"[Context Queue] \n"
			"Function returns the number of libnet contexts that are in the queue.\n"
			"\nParameters:\n\n"
			"\nReturns: the number of libnet contexts currently in the queue"
	},
	{
		"diag_dump_context", (PyCFunction)context_diag_dump_context, METH_VARARGS | METH_KEYWORDS,
		"[Diagnostic] \n"
			"Prints the contents of the given context.\n"
			"\nParameters:\n\n"
			"\nReturns: the number of libnet contexts currently in the queue"
	},
	{
		"diag_dump_pblock", (PyCFunction)context_diag_dump_pblock, METH_VARARGS | METH_KEYWORDS,
		"[Diagnostic] \n"
			"Prints the contents of every pblock.\n"
			"\nParameters:\n\n"
			"\nReturns: the number of libnet contexts currently in the queue"
	},
	{
		"diag_dump_pblock_type", (PyCFunction)context_diag_dump_pblock_type, METH_VARARGS | METH_KEYWORDS,
		"[Diagnostic] \n"
			"Returns the canonical name of the pblock type.\n"
			"\nParameters:\n\n"
			"type - pblock type\n"
			"\nReturns: a string representing the pblock type type or \"unknown\" for an unknown value"
	},
	{
		"diag_dump_hex", (PyCFunction)context_diag_dump_hex, METH_VARARGS | METH_KEYWORDS,
		"[Diagnostic] \n"
			"Function prints the contents of the supplied buffer to the supplied\n"
			"stream pointer. Will swap endianness based disposition of mode variable.\n"
			"Useful to be used in conjunction with the advanced interface and a culled\n"
			"packet.\n"
			"\nParameters:\n\n"
			"packet - the packet to print\n"
			"swap - 1 to swap byte order, 0 to not\n"
			"stream - a stream pointer to print to\n"
			"\nReturns: a string representing the pblock type type or \"unknown\" for an unknown value"
	},*/
	{
		"getheader", (PyCFunction)context_getheader, METH_VARARGS | METH_KEYWORDS,
		"Returns a user-friendly description of the packet header\n"
		"\nParameters:\n\n"
		"ptag - packet tag\n"
		"\nReturns: a dictionary of packet header fields and values."
	},
	{
		"getheader_raw", (PyCFunction)context_getheader_raw, METH_VARARGS | METH_KEYWORDS,
		"Returns a string representing the packet header.\n"
		"\nParameters:\n\n"
		"ptag - packet tag\n"
		"\nReturns: a string representing the packet header."
	},
	{
	 	"getpacket", (PyCFunction)context_getpacket, METH_NOARGS,
		"Returns a user-friendly description of the packet header\n\n"
		"Returns: a user-friendly description of the packet header\n"
	},
	{
	 	"getpacket_raw", (PyCFunction)context_getpacket_raw, METH_NOARGS,
		"Returns a string representing the complete packet.\n\n"
		"Returns: a string representing the complete packet.\n"
	},
	{NULL}  /* Sentinel */
};

static PyTypeObject context_Type = {
		PyObject_HEAD_INIT(NULL)
			0,                         /*ob_size*/
		"libnet.context",             /*tp_name*/
		sizeof(context),             /*tp_basicsize*/
		0,                         /*tp_itemsize*/
		(destructor)context_dealloc, /*tp_dealloc*/
		0,                         /*tp_print*/
		0,                         /*tp_getattr*/
		0,                         /*tp_setattr*/
		0,                         /*tp_compare*/
		0,                         /*tp_repr*/
		0,                         /*tp_as_number*/
		0,                         /*tp_as_sequence*/
		0,                         /*tp_as_mapping*/
		0,                         /*tp_hash */
		0,                         /*tp_call*/
		0,                         /*tp_str*/
		0,                         /*tp_getattro*/
		0,                         /*tp_setattro*/
		0,                         /*tp_as_buffer*/
		Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
		context_doc,           /* tp_doc */
		0,		               /* tp_traverse */
		0,		               /* tp_clear */
		0,		               /* tp_richcompare */
		0,		               /* tp_weaklistoffset */
		0,		               /* tp_iter */
		0,		               /* tp_iternext */
		context_methods,             /* tp_methods */
		context_members,             /* tp_members */
		0,                         /* tp_getset */
		0,                         /* tp_base */
		0,                         /* tp_dict */
		0,                         /* tp_descr_get */
		0,                         /* tp_descr_set */
		0,                         /* tp_dictoffset */
		(initproc)context_init,      /* tp_init */
		0,                         /* tp_alloc */
		context_new,                 /* tp_new */
};
