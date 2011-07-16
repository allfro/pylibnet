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

#include "parsers.c"

static PyObject *
context_diag_dump_context(context *self)
{
	libnet_diag_dump_context(self->l);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
context_diag_dump_pblock(context *self)
{
	libnet_diag_dump_pblock(self->l);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
context_diag_dump_hex(context *self, PyObject *args, PyObject *kwargs)
{

	FILE *fd = NULL;
	char *file = "pylibnet.out";
	u_int8_t *packet = NULL;
	int packet_len = 0;
	int swap = 0;

	static char *kwlist[] = {"packet", "swap", "file", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "t#|is", kwlist, &packet, &packet_len, &swap, &file)) 
		return NULL;
	
	if ((fd = fopen(file, "w")) == NULL) {
		strerror(errno);
		return NULL;
	}

	libnet_diag_dump_hex(packet, packet_len, swap, fd);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
context_clear_packet(context *self)
{

	if (self->l->total_size)
		libnet_clear_packet(self->l);

	Py_INCREF(Py_None);
	return Py_None;

}

static PyObject *
context_stats(context *self)
{

	struct libnet_stats ls;

	libnet_stats(self->l, &ls);

	return Py_BuildValue("{s:L,s:L,s:L}", 
	"packets_sent", ls.packets_sent, 
	"packet_errors", ls.packet_errors, 
	"bytes_written", ls.bytes_written);
	
}


static PyObject *
context_getfd(context *self)
{

	return Py_BuildValue("i", libnet_getfd(self->l));

}


static PyObject *
context_getdevice(context *self)
{

	return Py_BuildValue("s", libnet_getdevice(self->l));

}


static PyObject *
context_getpbuf(context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	u_int8_t *pbuf;

	static char *kwlist[] = {"ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i", kwlist, &ptag)) 
		return NULL;

	pbuf = libnet_getpbuf(self->l, ptag);

	if (pbuf == NULL) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("s#", (char *)pbuf, libnet_getpbuf_size(self->l, ptag));
	
}

static PyObject *
context_getpacket(context *self, PyObject *args, PyObject *kwargs)
{
	
	int ptag;
	PyObject *l = NULL;
	PyObject *o = NULL, *next_cycle = NULL;
	libnet_pblock_t *pblock = NULL;

	
	if ((l = PyList_New(0)) == NULL)
		return NULL;
	
	for (ptag = self->l->ptag_state; pblock != self->l->protocol_blocks; ptag--) {

		printf("%d\n", ptag);
		o = pylibnet_getheader(self, ptag);
		PYLIBNET_ERROR_LIBNET((pblock = libnet_pblock_find (self->l, ptag)) == NULL);

		if (pblock->type == LIBNET_PBLOCK_IPDATA || pblock->type == LIBNET_PBLOCK_TCPDATA) {

			next_cycle = o;
			continue;

		}

		if (PyList_Append(l, o) == -1)
			return NULL;

		if (next_cycle != NULL) {
			
			if (PyList_Append(l, next_cycle) == -1)
				return NULL;

			next_cycle = NULL;

		}

	}

	return l;

}

static PyObject *
context_getpacket_raw(context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *packet = NULL;
	u_int32_t size = 0;

	if (self->l->total_size > 0) {
		PYLIBNET_ERROR_LIBNET(libnet_pblock_coalesce(self->l, &packet, &size) < 0);
	} else {
		PyErr_SetString(PyErr_LibnetError, "Packet is empty!");
		return NULL;
	}
	
	return Py_BuildValue("s#", (char *)packet, size);

}

static PyObject *
context_getheader(context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i", kwlist, &ptag))
		return NULL;
	
	if (ptag == 0) {
		PyErr_SetString(PyErr_LibnetError, "Expected a ptag.");
		return NULL;
	}

	return pylibnet_getheader(self, ptag);

}

static PyObject *
context_getheader_raw(context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	libnet_pblock_t *pblock = NULL;

	static char *kwlist[] = {"ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i", kwlist, &ptag))
		return NULL;
	
	if (ptag == 0) {
		PyErr_SetString(PyErr_LibnetError, "Expected a ptag.");
		return NULL;
	}

	pblock = libnet_pblock_find(self->l, ptag);

	if (pblock == NULL) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("s#", (char *)pblock->buf, pblock->b_len);

}

static PyObject *
context_getpbuf_size(context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	u_int32_t pbuf_size = 0;

	static char *kwlist[] = {"ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i", kwlist, &ptag))
		return NULL;

	pbuf_size = libnet_getpbuf_size(self->l, ptag);

	return Py_BuildValue("i", pbuf_size);

}


static PyObject *
context_geterror(context *self)
{
	return Py_BuildValue("s", libnet_geterror(self->l));
}


static PyObject *
context_getheader_size(context *self)
{
	return Py_BuildValue("i", libnet_getpacket_size(self->l));
}


static PyObject *
context_seed_prand(context *self)
{
	
	if (libnet_seed_prand(self->l) == -1) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;

}


static PyObject *
context_get_prand(context *self, PyObject *args, PyObject *kwargs)
{

	int mod = LIBNET_PRu32;

	static char *kwlist[] = {"mod", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i", kwlist, &mod))
		return NULL;

	u_int32_t i = libnet_get_prand(mod);

	if (i == -1) {
		PyErr_SetString(PyErr_LibnetError, "libnet_get_prand(): an unknown error has occured.");
		return NULL;
	}

	return Py_BuildValue("i", i);

}


static PyObject *
context_toggle_checksum(context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag=0;
	int mode=LIBNET_ON;

	static char *kwlist[] = {"ptag", "mode", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|ii", kwlist, &ptag, &mode))
		return NULL;

	if (libnet_toggle_checksum(self->l, ptag, mode) == -1) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;

}


static PyObject *
context_addr2name4(context *self, PyObject *args, PyObject *kwargs)
{

	char *inaddr = NULL;
	int inaddr_len = 0;
	u_int32_t use_name = LIBNET_RESOLVE;
	char *name = NULL;

	static char *kwlist[] = {"inaddr", "use_name", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#i", kwlist, &inaddr, &inaddr_len, &use_name))
		return NULL;

	if (inaddr == NULL || inaddr_len != 4) {
		PyErr_SetString(PyErr_LibnetError, "Expected an IP address.");
		return NULL;
	}

	name = libnet_addr2name4(*((u_int32_t *)inaddr), use_name);

	if (name == NULL) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("s", name);

}


static PyObject *
context_name2addr4(context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t inaddr;
	char *host_name = NULL;
	u_int32_t use_name = 1;

	static char *kwlist[] = {"host_name", "use_name", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|si", kwlist, &host_name, &use_name))
		return NULL;

	if (host_name == NULL) {
		PyErr_SetString(PyErr_LibnetError, "Expected a hostname.");
		return NULL;
	}

	inaddr = libnet_name2addr4(self->l, host_name, use_name);

	return Py_BuildValue("s#", (char *)&inaddr, 4);

}


static PyObject *
context_name2addr6(context *self, PyObject *args, PyObject *kwargs)
{

	struct libnet_in6_addr in6addr;
	char *host_name = NULL;
	u_int32_t use_name = 1;

	static char *kwlist[] = {"host_name", "use_name", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|si", kwlist, &host_name, &use_name))
		return NULL;

	if (host_name == NULL) {
		PyErr_SetString(PyErr_LibnetError, "Expected a hostname.");
		return NULL;
	}

	in6addr = libnet_name2addr6(self->l, host_name, use_name);

	if (memcmp(&in6addr, &in6addr_error, sizeof(struct libnet_in6_addr)) == 0) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("s#", (char *)&in6addr, 16);

}


static PyObject *
context_addr2name6_r(context *self, PyObject *args, PyObject *kwargs)
{

#define HOST_NAME_LEN 1024
	char *in6addr;
	int in6addr_len;
	u_int32_t use_name = 1;
	char host_name[HOST_NAME_LEN];

	static char *kwlist[] = {"in", "use_name", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#i", kwlist, &in6addr, &in6addr_len, &use_name))
		return NULL;

	if (in6addr == NULL || in6addr_len != 16) {
		PyErr_SetString(PyErr_LibnetError, "Expected an IPV6 address.");
		return NULL;
	}

	libnet_addr2name6_r(*((struct libnet_in6_addr *)in6addr), use_name, host_name, HOST_NAME_LEN);

	if (host_name[0] == '\0') {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("s", host_name);

}


static PyObject *
context_write(context *self)
{

	if (libnet_getpacket_size(self->l) != 0 && libnet_write(self->l) == -1) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;

}


static PyObject *
context_get_ipaddr4(context *self) 
{
	
	u_int32_t ipaddr4;

	ipaddr4 = libnet_get_ipaddr4(self->l);

	if (ipaddr4 == 0xFFFFFFFF) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("s#", (char *)&ipaddr4, sizeof(u_int32_t));

}


static PyObject *
context_get_ipaddr6(context *self)
{

	struct libnet_in6_addr ipaddr6;
	
	ipaddr6 = libnet_get_ipaddr6(self->l);

	if (memcmp(&ipaddr6, &in6addr_error, sizeof(struct libnet_in6_addr)) == 0) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("s#", (char *)&ipaddr6, sizeof(struct libnet_in6_addr));

}


static PyObject *
context_get_hwaddr(context *self) 
{
	
	struct libnet_ether_addr *lea;
	
	lea = libnet_get_hwaddr(self->l);

	if (lea == NULL) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("s#", (char *)lea, sizeof(struct libnet_ether_addr));

}


static PyObject *
context_hex_aton(context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *s;
	int len;

	static char *kwlist[] = {"s", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", kwlist, &s))
		return NULL;

#if LIBNET_RELEASE <= 2
	s = libnet_hex_aton((int8_t *)s, &len);
#elif LIBNET_RELEASE >= 3
	s = libnet_hex_aton((char *)s, &len);
#endif

	if (s == NULL) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("s#", s, len);

}
