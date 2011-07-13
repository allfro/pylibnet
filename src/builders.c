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

#define PYLIBNET_HWA "hardware address"
#define PYLIBNET_IP4 "IPv4 address"
#define PYLIBNET_IP6 "IPv6 address"
#define PYLIBNET_OUI "3 byte OUI"

#define PYLIBNET_ERRTYPE(x, y, z) PYLIBNET_ERROR_TYPE(x##_len != y, #x, z)

#define PYLIBNET_ERRPTAG PYLIBNET_ERROR_LIBNET(ptag == -1)
#define PYLIBNET_ERRHWASRC PYLIBNET_ERROR_TYPE(src_len != 6, "src", PYLIBNET_HWA)
#define PYLIBNET_ERRHWADST PYLIBNET_ERROR_TYPE(dst_len != 6, "dst", PYLIBNET_HWA)
#define PYLIBNET_ERRIP4SRC PYLIBNET_ERROR_TYPE1(src_len != 4, "src", PYLIBNET_IP4)
#define PYLIBNET_ERRIP4DST PYLIBNET_ERROR_TYPE1(dst_len != 4, "dst", PYLIBNET_IP4)
#define PYLIBNET_ERRIP6SRC PYLIBNET_ERROR_TYPE1(src_len != 16, "src", PYLIBNET_IP6)
#define PYLIBNET_ERRIP6DST PYLIBNET_ERROR_TYPE1(dst_len != 16, "dst", PYLIBNET_IP6)

#define PYLIBNET_ERRCHADDR(x) PYLIBNET_ERROR_TYPE(x##_len > 16, #x, PYLIBNET_HWA)

#define PYLIBNET_ERRHWA(x) PYLIBNET_ERROR_TYPE(x##_len != 6, #x, PYLIBNET_HWA)
#define PYLIBNET_ERRIP4(x) PYLIBNET_ERROR_TYPE1(x##_len != 4, #x, PYLIBNET_IP4)
#define PYLIBNET_ERRIP6(x) PYLIBNET_ERROR_TYPE1(x##_len != 16, #x, PYLIBNET_IP6)

#define PYLIBNET_ERRHWA1(x, y) PYLIBNET_ERROR_TYPE(x##_len != 6, y, PYLIBNET_HWA)
#define PYLIBNET_ERRIP41(x, y) PYLIBNET_ERROR_TYPE1(x##_len != 4, y, PYLIBNET_IP4)
#define PYLIBNET_ERRIP61(x, y) PYLIBNET_ERROR_TYPE1(x##_len != 16, y, PYLIBNET_IP6)

#define PYLIBNET_ERRHWA2(x, y) PYLIBNET_ERROR_TYPE(x, y, PYLIBNET_HWA)
#define PYLIBNET_ERRIP42(x, y) PYLIBNET_ERROR_TYPE1(x, y, PYLIBNET_IP4)
#define PYLIBNET_ERRIP62(x, y) PYLIBNET_ERROR_TYPE1(x, y, PYLIBNET_IP6)

#define PYLIBNET_ERROUI PYLIBNET_ERROR_TYPE1(oui_len != 3, "oui", PYLIBNET_OUI)
#define PYLIBNET_ERROUI1(x) PYLIBNET_ERROR_TYPE1(x##_len != 3, #x, PYLIBNET_OUI)
#define PYLIBNET_ERROUI2(x, y) PYLIBNET_ERROR_TYPE1(x, y, PYLIBNET_OUI)

#define AUTOSIZE(x) if (!len) len = pylibnet_auto_length(self->l, ptag)+x+payload_s
#define AUTOSIZE1(x,y) if (!x) x = pylibnet_auto_length(self->l, ptag)+y+payload_s

#define AUTOSIZE_NOPAYLOAD(x) if (!len) len = pylibnet_auto_length(self->l, ptag)+x


static int 
pylibnet_auto_length(libnet_t *l, int ptag) {
	
	int i = 0;
	int len = 0;

	if (ptag <= l->ptag_state && ptag >= 0) {

		for (i = (ptag)?--ptag:l->ptag_state; i; i--) {
			len += libnet_getpbuf_size(l, i);
			printf("%d: %d\n", i, len);
		}

	}

	return len;

}

static PyObject *
context_build_802_1q (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *dst = PYLIBNET_BROADCAST_MAC;
	int dst_len = 6;
	u_int8_t *src = self->hwaddr;
	int src_len = 6;
	u_int32_t tpi = 0x8100;
	u_int32_t priority = 0;
	u_int32_t cfi = 0;
	u_int32_t vlan_id = 0;
	u_int32_t len_proto = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"dst", "src", "tpi", "priority", "cfi", "vlan_id", "len_proto", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#t#IIIIIz#i", kwlist, &dst, &dst_len, &src, &src_len, &tpi, &priority, &cfi, &vlan_id, &len_proto, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRHWADST;
	PYLIBNET_ERRHWASRC;
	
	AUTOSIZE1(len_proto, LIBNET_802_1Q_H);

	ptag = libnet_build_802_1q(dst, src, tpi, priority, cfi, vlan_id, len_proto, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_802_1x (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t eap_ver = 1;
	u_int32_t eap_type = LIBNET_802_1X_PACKET;
	u_int32_t length = 0;  
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"eap_ver", "eap_type", "length", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIz#i", kwlist, &eap_ver, &eap_type, &length, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE1(length, LIBNET_802_1X_H);

	ptag = libnet_build_802_1x(eap_ver, eap_type, length, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_802_2 (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t dsap = LIBNET_SAP_SNAP;
	u_int32_t ssap = LIBNET_SAP_SNAP;
	u_int32_t control = 3;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"dsap", "ssap", "control", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIz#i", kwlist, &dsap, &ssap, &control, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_802_2 (dsap, ssap, control, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_802_2snap (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t dsap = LIBNET_SAP_SNAP;
	u_int32_t ssap = LIBNET_SAP_SNAP;
	u_int32_t control = 3;
	u_int8_t *oui = (u_int8_t *)"\x00\x00\x00";
	int oui_len = 3;
	u_int32_t type = 0x800;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"dsap", "ssap", "control", "oui", "type", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIt#Iz#i", kwlist, &dsap, &ssap, &control, &oui, &oui_len, &type, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERROUI;

	ptag = libnet_build_802_2snap (dsap, ssap, control, oui, type, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_802_3 (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *dst = PYLIBNET_BROADCAST_MAC;
	int dst_len = 6;
	u_int8_t *src = self->hwaddr;
	int src_len = 6;
	u_int32_t len = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"dst", "src", "len", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#t#Iz#i", kwlist, &dst, &dst_len, &src, &src_len, &len, &payload, &payload_s, &ptag))
		return NULL;


	PYLIBNET_ERRHWADST;
	PYLIBNET_ERRHWASRC;
	
	AUTOSIZE(LIBNET_802_3_H);

	ptag = libnet_build_802_3 (dst, src, len, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ethernet (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *dst = PYLIBNET_BROADCAST_MAC;
	int dst_len = 6;
	u_int8_t *src = self->hwaddr;
	int src_len = 6;
	u_int32_t type = ETHERTYPE_IP;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"dst", "src", "type", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#t#Iz#i", kwlist, &dst, &dst_len, &src, &src_len, &type, &payload, &payload_s, &ptag))
		return NULL;


	PYLIBNET_ERRHWADST;
	PYLIBNET_ERRHWASRC;

	ptag = libnet_build_ethernet (dst, src, type, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_autobuild_ethernet (context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	u_int8_t *dst = PYLIBNET_BROADCAST_MAC; 
	int dst_len = 6;
	u_int32_t type = ETHERTYPE_IP;

	static char *kwlist[] = {"dst", "type", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#I", kwlist, &dst, &dst_len, &type))
		return NULL;

	PYLIBNET_ERRHWADST;

	ptag = libnet_autobuild_ethernet (dst, type, self->l);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_fddi (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t fc = LIBNET_FDDI_48BIT_ADDR;
	u_int8_t *dst = PYLIBNET_BROADCAST_MAC;
	int dst_len = 6;
	u_int8_t *src = self->hwaddr;
	int src_len = 6;
	u_int32_t dsap = LIBNET_SAP_SNAP;
	u_int32_t ssap = LIBNET_SAP_SNAP;
	u_int32_t cf = 0;
	u_int8_t *org = (u_int8_t *)"\x00\x00\x00";
	int org_len = 3;
	u_int32_t type = FDDI_TYPE_IP;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"fc", "dst", "src", "dsap", "ssap", "cf", "org", "type", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|It#t#IIIt#Iz#i", kwlist, &fc, &dst, &dst_len, &src, &src_len, &dsap, &ssap, &cf, &org, &org_len, &type, &payload, &payload_s))
		return NULL;


	PYLIBNET_ERRHWADST;
	PYLIBNET_ERRHWASRC;
	PYLIBNET_ERROUI1(org);

	ptag = libnet_build_fddi (fc, dst, src, dsap, ssap, cf, org, type, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_autobuild_fddi (context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	u_int32_t fc = LIBNET_FDDI_48BIT_ADDR;
	u_int8_t *dst = PYLIBNET_BROADCAST_MAC;
	int dst_len = 6;
	u_int32_t dsap = LIBNET_SAP_SNAP; 
	u_int32_t ssap = LIBNET_SAP_SNAP;
	u_int32_t cf = 0;
	u_int8_t *org = (u_int8_t *)"\x00\x00\x00";
	int org_len = 3;
	u_int32_t type = FDDI_TYPE_IP;

	static char *kwlist[] = {"fc", "dst", "dsap", "ssap", "cf", "org", "type", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|It#IIIt#i", kwlist, &fc, &dst, &dst_len, &dsap, &ssap, &cf, &org, &org_len, &type))
		return NULL;

	PYLIBNET_ERRHWADST;
	PYLIBNET_ERROUI1(org);

	ptag = libnet_autobuild_fddi (fc, dst, dsap, ssap, cf, org, type, self->l);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_arp (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t hrd = ARPHRD_ETHER;
	u_int32_t pro = ETHERTYPE_IP;
	u_int32_t hln = 6;
	u_int32_t pln = 4;
	u_int32_t op = ARPOP_REQUEST;
	u_int8_t *sha = self->hwaddr;
	int sha_len = 6;
	u_int8_t *spa = self->ipaddr4;
	int spa_len = 4;
	u_int8_t *tha = PYLIBNET_BROADCAST_MAC;
	int tha_len = 6;
	u_int8_t *tpa = PYLIBNET_BROADCAST_IPV4;
	int tpa_len = 4;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"hrd", "pro", "hln", "pln", "op", "sha", "spa", "tha", "tpa", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIt#t#t#t#z#i", kwlist, &hrd, &pro, &hln, &pln, &op, &sha, &sha_len, &spa, &spa_len, &tha, &tha_len, &tpa, &tpa_len, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRHWA2(hln != sha_len, "sha");
	PYLIBNET_ERRHWA2(hln != tha_len, "tha");
	PYLIBNET_ERRIP42(pln != spa_len, "spa");
	PYLIBNET_ERRIP42(pln != tpa_len, "tpa");

	ptag = libnet_build_arp (hrd, pro, hln, pln, op, sha, spa, tha, tpa, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_autobuild_arp (context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	u_int32_t op = ARPOP_REQUEST;
	u_int8_t *sha = self->hwaddr;
	int sha_len = 6;
	u_int8_t *spa = self->ipaddr4; 
	int spa_len = 4;
	u_int8_t *tha = PYLIBNET_BROADCAST_MAC;
	int tha_len = 6;
	u_int8_t *tpa = PYLIBNET_BROADCAST_IPV4;
	int tpa_len = 4;

	static char *kwlist[] = {"op", "sha", "spa", "tha", "tpa", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|It#t#t#t#", kwlist, &op, &sha, &sha_len, &spa, &spa_len, &tha, &tha_len, &tpa, &tpa_len))
		return NULL;
/*
	PYLIBNET_ERRHWA(sha);
	PYLIBNET_ERRHWA(tha);
	PYLIBNET_ERRIP4(spa);
	PYLIBNET_ERRIP4(tpa);
*/
	ptag = libnet_autobuild_arp (op, sha, spa, tha, tpa, self->l);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_tcp (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t sp = PYLIBNET_RANDOM_U16;
	u_int32_t dp = PYLIBNET_RANDOM_U16;
	u_int32_t seq = PYLIBNET_RANDOM_U32;
	u_int32_t ack = PYLIBNET_RANDOM_U32;
	u_int32_t control = TH_SYN;
	u_int32_t win = PYLIBNET_RANDOM_U16;
	u_int32_t sum = 0;
	u_int32_t urg = 0;
	u_int32_t len = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"sp", "dp", "seq", "ack", "control", "win", "sum", "urg", "len", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIIIz#i", kwlist, &sp, &dp, &seq, &ack, &control, &win, &sum, &urg, &len, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE(LIBNET_TCP_H);

	ptag = libnet_build_tcp (sp, dp, seq, ack, control, win, sum, urg, len, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_tcp_options (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *options = NULL;
	u_int32_t options_s = 0;
	libnet_ptag_t ptag = 0;
	static char *kwlist[] = {"options", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#i", kwlist, &options, &options_s, &ptag))
		return NULL;

	ptag = libnet_build_tcp_options (options, options_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_udp (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t sp = PYLIBNET_RANDOM_U16;
	u_int32_t dp = PYLIBNET_RANDOM_U16;
	u_int32_t len = 0; 
	u_int32_t sum = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"sp", "dp", "len", "sum", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIz#i", kwlist, &sp, &dp, &len, &sum, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE(LIBNET_UDP_H);

	ptag = libnet_build_udp (sp, dp, len, sum, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_cdp (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t version = 1;
	u_int32_t ttl = PYLIBNET_RANDOM_U8;
	u_int32_t sum = 0;
	u_int32_t type = LIBNET_CDP_DEVID;
	u_int32_t len = 0;
	u_int8_t *value = NULL;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"version", "ttl", "sum", "type", "len", "value", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIsz#i", kwlist, &version, &ttl, &sum, &type, &len, &value, &payload, &payload_s, &ptag))
		return NULL;

	if (value == NULL) {
		PyErr_SetString(PyErr_LibnetError, "Expected a device ID, address, port ID, capabilities spec, version, platform, or IP prefix.");
		return NULL;
	}

	AUTOSIZE(LIBNET_CDP_H);

	ptag = libnet_build_cdp (version, ttl, sum, type, len, value, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_icmpv4_echo (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t type = ICMP_ECHO;
	u_int32_t code = 0;
	u_int32_t sum = 0;
	u_int32_t id = PYLIBNET_RANDOM_U16;
	u_int32_t seq = PYLIBNET_RANDOM_U16;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"type", "code", "sum", "id", "seq", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIz#i", kwlist, &type, &code, &sum, &id, &seq, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_icmpv4_echo (type, code, sum, id, seq, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_icmpv4_mask (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t type = ICMP_MASKREQ;
	u_int32_t code = 0;
	u_int32_t sum = 0;
	u_int32_t id = PYLIBNET_RANDOM_U16;
	u_int32_t seq = PYLIBNET_RANDOM_U16;
	u_int32_t mask = PYLIBNET_RANDOM_U16;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"type", "code", "sum", "id", "seq", "mask", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIz#i", kwlist, &type, &code, &sum, &id, &seq, &mask, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_icmpv4_mask (type, code, sum, id, seq, mask, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_icmpv4_unreach (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t type = ICMP_UNREACH;
	u_int32_t code = ICMP_UNREACH_NET;
	u_int32_t sum = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"type", "code", "sum", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIz#i", kwlist, &type, &code, &sum, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_icmpv4_unreach (type, code, sum, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_icmpv4_redirect (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t type = ICMP_REDIRECT;
	u_int32_t code = ICMP_REDIRECT_NET;
	u_int32_t sum = 0;
	u_int8_t *gateway = PYLIBNET_BROADCAST_IPV4;
	int gateway_len = 4;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"type", "code", "sum", "gateway", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIt#z#i", kwlist, &type, &code, &sum, &gateway, &gateway_len, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(gateway); 

	ptag = libnet_build_icmpv4_redirect (type, code, sum, U_INT32_TP(gateway), payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_icmpv4_timeexceed (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t type = ICMP_TIMXCEED;
	u_int32_t code = ICMP_TIMXCEED_INTRANS;
	u_int32_t sum = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"type", "code", "sum", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIz#i", kwlist, &type, &code, &sum, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_icmpv4_timeexceed (type, code, sum, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_icmpv4_timestamp (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t type = ICMP_TSTAMP;
	u_int32_t code = 0;
	u_int32_t sum = 0;
	u_int32_t id = PYLIBNET_RANDOM_U16;
	u_int32_t seq = PYLIBNET_RANDOM_U16;
	n_time otime = PYLIBNET_RANDOM_U32;
	n_time rtime = PYLIBNET_RANDOM_U32;
	n_time ttime = PYLIBNET_RANDOM_U32;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"type", "code", "sum", "id", "seq", "otime", "rtime", "ttime", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIIz#i", kwlist, &type, &code, &sum, &id, &seq, &otime, &rtime, &ttime, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_icmpv4_timestamp (type, code, sum, id, seq, otime, rtime, ttime, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_igmp (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t type = IGMP_MEMBERSHIP_QUERY;
	u_int32_t code = 0;
	u_int32_t sum = 0;
	u_int8_t *ip = self->ipaddr4;
	int ip_len = 4;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"type", "code", "sum", "ip", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIt#z#i", kwlist, &type, &code, &sum, &ip, &ip_len, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(ip);

	ptag = libnet_build_igmp (type, code, sum, U_INT32_TP(ip), payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ipv4 (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t len = 0;
	u_int32_t tos = 0;
	u_int32_t id = PYLIBNET_RANDOM_U16;
	u_int32_t frag = 0;
	u_int32_t ttl = 255;
	u_int32_t prot = IPPROTO_IPIP;
	u_int32_t sum = 0;
	u_int8_t *src = self->ipaddr4;
	int src_len = 4;
	u_int8_t *dst = PYLIBNET_BROADCAST_IPV4;
	int dst_len = 4;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"len", "tos", "id", "frag", "ttl", "prot", "sum", "src", "dst", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIt#t#z#i", kwlist, &len, &tos, &id, &frag, &ttl, &prot, &sum, &src, &src_len, &dst, &dst_len, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4SRC;
	PYLIBNET_ERRIP4DST;
	
	AUTOSIZE(LIBNET_IPV4_H);

	ptag = libnet_build_ipv4 (len, tos, id, frag, ttl, prot, sum, U_INT32_TP(src), U_INT32_TP(dst), payload, payload_s, self->l, ptag);
	
	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ipv4_options (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *options = NULL;
	u_int32_t options_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"options", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#i", kwlist, &options, &options_s, &ptag))
		return NULL;

	ptag = libnet_build_ipv4_options (options, options_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_autobuild_ipv4 (context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	u_int32_t len = 0;
	u_int32_t prot = IPPROTO_IPIP;
	u_int8_t *dst = PYLIBNET_BROADCAST_IPV4;
	int dst_len = 4;

	static char *kwlist[] = {"len", "prot", "dst", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIz#", kwlist, &len, &prot, &dst, &dst_len))
		return NULL;

	PYLIBNET_ERRIP4DST;

	AUTOSIZE_NOPAYLOAD(LIBNET_IPV4_H);

	ptag = libnet_autobuild_ipv4 (len, prot, U_INT32_TP(dst), self->l);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ipv6 (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t tc = 0;
	u_int32_t fl = 0;
	u_int32_t len = 0;
	u_int32_t nh = 0;
	u_int32_t hl = PYLIBNET_RANDOM_U8;
	u_int8_t *src = self->ipaddr6;
	int src_len = 16;
	u_int8_t *dst = PYLIBNET_BROADCAST_IPV6;
	int dst_len = 16;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"tc", "fl", "len", "nh", "hl", "src", "dst", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIt#t#z#i", kwlist, &tc, &fl, &len, &nh, &hl, &src, &src_len, &dst, &dst_len, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP6SRC;
	PYLIBNET_ERRIP6DST;

	AUTOSIZE(LIBNET_IPV6_H);

	ptag = libnet_build_ipv6 (tc, fl, len, nh, hl, *((struct libnet_in6_addr *)src), *((struct libnet_in6_addr *)dst), payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ipv6_frag (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t nh = 0;
	u_int32_t reserved = 0;
	u_int32_t frag = PYLIBNET_RANDOM_U16;
	u_int32_t id = PYLIBNET_RANDOM_U32;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"nh", "reserved", "frag", "id", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIz#i", kwlist, &nh, &reserved, &frag, &id, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_ipv6_frag (nh, reserved, frag, id, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ipv6_routing (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t nh = 0;
	u_int32_t len = 0;
	u_int32_t rtype = 0;
	u_int32_t segments = PYLIBNET_RANDOM_U8;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"nh", "len", "rtype", "segments", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIz#i", kwlist, &nh, &len, &rtype, &segments, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE(LIBNET_IPV6_ROUTING_H);

	ptag = libnet_build_ipv6_routing (nh, len, rtype, segments, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ipv6_destopts (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t nh = 0;
	u_int32_t len = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"nh", "len", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIz#i", kwlist, &nh, &len, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE(LIBNET_IPV6_DESTOPTS_H);

	ptag = libnet_build_ipv6_destopts (nh, len, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ipv6_hbhopts (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t nh = 0;
	u_int32_t len = 0; 
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"nh", "len", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIz#i", kwlist, &nh, &len, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE(LIBNET_IPV6_HBHOPTS_H);

	ptag = libnet_build_ipv6_hbhopts (nh, len, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_autobuild_ipv6 (context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	u_int32_t len = 0;
	u_int32_t nh = 0;
	u_int8_t *dst = PYLIBNET_BROADCAST_IPV6;
	int dst_len = 16;

	static char *kwlist[] = {"len", "nh", "dst", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIt#", kwlist, &len, &nh, &dst, &dst_len))
		return NULL;

	PYLIBNET_ERRIP6DST;

	AUTOSIZE_NOPAYLOAD(LIBNET_IPV6_H);

#if LIBNET_RELEASE <= 2
	ptag = libnet_autobuild_ipv6 (len, nh, *((struct libnet_in6_addr *)dst), self->l);
#elif LIBNET_RELEASE >= 3
	ptag = libnet_autobuild_ipv6 (len, nh, *((struct libnet_in6_addr *)dst), self->l, ptag);
#endif

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_isl (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *dhost = (u_int8_t *)"\x01\x00\x0c\x00\x00";
	int dhost_len = 5;
	u_int32_t type = 0;
	u_int32_t user = 0;
	u_int8_t *shost = self->hwaddr;
	int shost_len = 6;
	u_int32_t len = 0;
	u_int8_t *snap = (u_int8_t *)"\xaa\xaa\x03";
	int snap_len = 3;
	u_int32_t vid = 0;
	u_int32_t index = PYLIBNET_RANDOM_U16;
	u_int32_t reserved = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"dhost", "type", "user", "shost", "len", "snap", "vid", "index", "reserved", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#IIt#It#IIIz#i", kwlist, &dhost, &dhost_len, &type, &user, &shost, &shost_len, &len, &snap, &snap_len, &vid, &index, &reserved, &payload, &payload_s, &ptag))
		return NULL;

	if (dhost == NULL || dhost_len != 5) {
		PyErr_SetString(PyErr_LibnetError, "Expected a 5-byte destination address."); 
		return NULL;
	}

	PYLIBNET_ERRHWA(shost);

	if (snap == NULL || snap_len != 3) {
		PyErr_SetString(PyErr_LibnetError, "Expected a SNAP or LLC field."); 
		return NULL;
	}

	AUTOSIZE(LIBNET_ISL_H);

	ptag = libnet_build_isl (dhost, type, user, shost, len, snap, vid, index, reserved, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ipsec_esp_hdr (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t spi = PYLIBNET_RANDOM_U32;
	u_int32_t seq = PYLIBNET_RANDOM_U32;
	u_int32_t iv = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;
	
	static char *kwlist[] = {"spi", "seq", "iv", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIz#i", kwlist, &spi, &seq, &iv, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_ipsec_esp_hdr (spi, seq, iv, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}



static PyObject *
context_build_ipsec_esp_ftr (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t len = 0;
	u_int32_t nh = 0;
	int8_t *auth = NULL;
	int auth_len = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"len", "nh", "auth", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIt#z#i", kwlist, &len, &nh, &auth, &auth_len, &payload, &payload_s, &ptag))
		return NULL;
	
	AUTOSIZE(LIBNET_IPSEC_ESP_FTR_H);

	ptag = libnet_build_ipsec_esp_ftr (len, nh, auth, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ipsec_ah (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t nh = 0;
	u_int32_t len = 0;
	u_int32_t res = 0;
	u_int32_t spi = PYLIBNET_RANDOM_U32;
	u_int32_t seq = PYLIBNET_RANDOM_U32;
	u_int32_t auth = PYLIBNET_RANDOM_U32;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"nh", "len", "res", "spi", "seq", "auth", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "IIIIIIIz#i", kwlist, &nh, &len, &res, &spi, &seq, &auth, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE(LIBNET_IPSEC_AH_H);

	ptag = libnet_build_ipsec_ah (nh, len, res, spi, seq, auth, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_dnsv4 (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t h_len = 0;
	u_int32_t id = PYLIBNET_RANDOM_U16;
	u_int32_t flags = 0;
	u_int32_t num_q = 0;
	u_int32_t num_anws_rr = 0;
	u_int32_t num_auth_rr = 0;
	u_int32_t num_addi_rr = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"h_len", "id", "flags", "num_q", "num_anws_rr", "num_auth_rr", "num_addi_rr", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIz#i", kwlist, &h_len, &id, &flags, &num_q, &num_anws_rr, &num_auth_rr, &num_addi_rr, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE1(h_len, LIBNET_TCP_DNSV4_H);

	ptag = libnet_build_dnsv4 (h_len, id, flags, num_q, num_anws_rr, num_auth_rr, num_addi_rr, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}

static PyObject *
context_build_rip (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t cmd = RIPCMD_REQUEST;
	u_int32_t version = RIPVER_1;
	u_int32_t rd = 0;
	u_int32_t af = AF_INET;
	u_int32_t rt = 0;
	u_int8_t *addr = self->ipaddr4;
	int addr_len = 4;
	u_int8_t *mask = (u_int8_t *)"\x00\x00\x00\x00";
	int mask_len = 4;
	u_int8_t *next_hop = (u_int8_t *)"\x00\x00\x00\x00";
	int next_hop_len = 4;
	u_int32_t metric = PYLIBNET_RANDOM_U32;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"cmd", "version", "rd", "af", "rt", "addr", "mask", "next_hop", "metric", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIt#t#t#Iz#i", kwlist, &cmd, &version, &rd, &af, &rt, &addr, &addr_len, &mask, &mask_len, &next_hop, &next_hop_len, &metric, &payload, &payload_s, &ptag))
		return NULL;


	PYLIBNET_ERRIP4(addr);
	PYLIBNET_ERRIP4(mask);
	PYLIBNET_ERRIP4(next_hop);
	
	ptag = libnet_build_rip (cmd, version, rd, af, rt, U_INT32_TP(addr), U_INT32_TP(mask), U_INT32_TP(next_hop), metric, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_rpc_call (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t rm = 0;
	u_int32_t xid = 0;
	u_int32_t prog_num = 0;
	u_int32_t prog_vers = 0;
	u_int32_t procedure = 0;
	u_int32_t cflavor = 0;
	u_int32_t clength = 0;
	u_int8_t *cdata = NULL;
	u_int32_t vflavor = 0;
	u_int32_t vlength = 0;
	u_int8_t *vdata = NULL;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"rm", "xid", "prog_num", "prog_vers", "procedure", "cflavor", "cdata", "vflavor", "vdata", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIt#It#z#i", kwlist, &rm, &xid, &prog_num, &prog_vers, &procedure, &cflavor, &cdata, &clength, &vflavor, &vdata, &vlength, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_rpc_call (rm, xid, prog_num, prog_vers, procedure, cflavor, clength, cdata, vflavor, vlength, vdata, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_stp_conf (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t id = 0;
	u_int32_t version = 0;
	u_int32_t bpdu_type = 0;
	u_int32_t flags = 0;
	u_int8_t *root_id = (u_int8_t *)"\x00\x00\xff\xff\xff\xff\xff\xff";
	int root_id_len = 8;
	u_int32_t root_pc = 0;
	u_int8_t *bridge_id = root_id;
	int bridge_id_len = 8;
	u_int32_t port_id = 0x8001;
	u_int32_t message_age = PYLIBNET_RANDOM_U16;
	u_int32_t max_age = PYLIBNET_RANDOM_U16;
	u_int32_t hello_time = PYLIBNET_RANDOM_U16;
	u_int32_t f_delay = PYLIBNET_RANDOM_U16;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"id", "version", "bpdu_type", "flags", "root_id", "root_pc", "bridge_id", "port_id", "message_age", "max_age", "hello_time", "f_delay", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIt#It#IIIIIz#i", kwlist, &id, &version, &bpdu_type, &flags, &root_id, &root_id_len, &root_pc, &bridge_id_len, &port_id, &message_age, &max_age, &hello_time, &f_delay, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRTYPE(root_id, 8, "bridge ID");
	PYLIBNET_ERRTYPE(bridge_id, 8, "bridge ID");

	ptag = libnet_build_stp_conf (id, version, bpdu_type, flags, root_id, root_pc, bridge_id, port_id, message_age, max_age, hello_time, f_delay, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_stp_tcn (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t id = PYLIBNET_RANDOM_U16;
	u_int32_t version = 0;
	u_int32_t bpdu_type = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"id", "version", "bpdu_type", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIz#i", kwlist, &id, &version, &bpdu_type, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_stp_tcn (id, version, bpdu_type, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_token_ring (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t ac = LIBNET_TOKEN_RING_FRAME;
	u_int32_t fc = LIBNET_TOKEN_RING_LLC_FRAME;
	u_int8_t *dst = PYLIBNET_BROADCAST_MAC;
	int dst_len = TOKEN_RING_ADDR_LEN;
	u_int8_t *src = self->hwaddr;
	int src_len = TOKEN_RING_ADDR_LEN;
	u_int32_t dsap = 0;
	u_int32_t ssap = 0;
	u_int32_t cf = 0;
	u_int8_t *org = (u_int8_t *) "\x00\x00\x00";
	int org_len = LIBNET_ORG_CODE_SIZE;
	u_int32_t type = TOKEN_RING_TYPE_IP;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"ac", "fc", "dst", "src", "dsap", "ssap", "cf", "org", "type", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIt#t#IIIt#Iz#i", kwlist, &ac, &fc, &dst, &dst_len, &src, &src_len, &dsap, &ssap, &cf, &org, &org_len, &type, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRHWADST;
	PYLIBNET_ERRHWASRC;
	PYLIBNET_ERROUI1(org);

	ptag = libnet_build_token_ring (ac, fc, dst, src, dsap, ssap, cf, org, type, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_autobuild_token_ring (context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	u_int32_t ac = LIBNET_TOKEN_RING_FRAME;
	u_int32_t fc = LIBNET_TOKEN_RING_LLC_FRAME;
	u_int8_t *dst = PYLIBNET_BROADCAST_MAC;
	int dst_len = TOKEN_RING_ADDR_LEN;
	u_int32_t dsap = 0;
	u_int32_t ssap = 0;
	u_int32_t cf = 0;
	u_int8_t *org = (u_int8_t *) "\x00\x00\x00";
	int org_len = LIBNET_ORG_CODE_SIZE;
	u_int32_t type = TOKEN_RING_TYPE_IP;

	static char *kwlist[] = {"ac", "fc", "dst", "dsap", "ssap", "cf", "org", "type", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIt#IIIt#i", kwlist, &ac, &fc, &dst, &dst_len, &dsap, &ssap, &cf, &org, &org_len, &type))
		return NULL;

	PYLIBNET_ERRHWADST;
	PYLIBNET_ERROUI1(org);

	ptag = libnet_autobuild_token_ring (ac, fc, dst, dsap, ssap, cf, org, type, self->l);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_vrrp (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t version = LIBNET_VRRP_VERSION_01;
	u_int32_t type = LIBNET_VRRP_TYPE_ADVERT;
	u_int32_t vrouter_id = PYLIBNET_RANDOM_U8;
	u_int32_t priority = 0;
	u_int32_t ip_count = PYLIBNET_RANDOM_U8;
	u_int32_t auth_type = LIBNET_VRRP_AUTH_NONE;
	u_int32_t advert_int = PYLIBNET_RANDOM_U8;
	u_int32_t sum = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"version", "type", "vrouter_id", "priority", "ip_count", "auth_type", "advert_int", "sum", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIIz#i", kwlist, &version, &type, &vrouter_id, &priority, &ip_count, &auth_type, &advert_int, &sum, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_vrrp (version, type, vrouter_id, priority, ip_count, auth_type, advert_int, sum, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_mpls (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t label = PYLIBNET_RANDOM_U32;
	u_int32_t experimental = 0;
	u_int32_t bos = LIBNET_MPLS_BOS_OFF;
	u_int32_t ttl = PYLIBNET_RANDOM_U8;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"label", "experimental", "bos", "ttl", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIz#i", kwlist, &label, &experimental, &bos, &ttl, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_mpls (label, experimental, bos, ttl, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ntp (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t leap_indicator = PYLIBNET_RANDOM_U8;
	u_int32_t version = LIBNET_NTP_VN_2;
	u_int32_t mode = LIBNET_NTP_LI_NW;
	u_int32_t stratum = LIBNET_NTP_STRATUM_PRIMARY;
	u_int32_t poll = PYLIBNET_RANDOM_U8;
	u_int32_t precision = PYLIBNET_RANDOM_U8;
	u_int32_t delay_int = PYLIBNET_RANDOM_U16;
	u_int32_t delay_frac = PYLIBNET_RANDOM_U16;
	u_int32_t dispersion_int = PYLIBNET_RANDOM_U16;
	u_int32_t dispersion_frac = PYLIBNET_RANDOM_U16;
	u_int32_t reference_id = LIBNET_NTP_REF_LOCAL;
	u_int32_t ref_ts_int = PYLIBNET_RANDOM_U32;
	u_int32_t ref_ts_frac = PYLIBNET_RANDOM_U32;
	u_int32_t orig_ts_int = PYLIBNET_RANDOM_U32;
	u_int32_t orig_ts_frac = PYLIBNET_RANDOM_U32;
	u_int32_t rec_ts_int = PYLIBNET_RANDOM_U32;
	u_int32_t rec_ts_frac = PYLIBNET_RANDOM_U32;
	u_int32_t xmt_ts_int = PYLIBNET_RANDOM_U32;
	u_int32_t xmt_ts_frac = PYLIBNET_RANDOM_U32;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"leap_indicator", "version", "mode", "stratum", "poll", "precision", "delay_int", "delay_frac", "dispersion_int", "dispersion_frac", "reference_id", "ref_ts_int", "ref_ts_frac", "orig_ts_int", "orig_ts_frac", "rec_ts_int", "rec_ts_frac", "xmt_ts_int", "xmt_ts_frac", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIIIIIIIIIIIIIz#i", kwlist, &leap_indicator, &version, &mode, &stratum, &poll, &precision, &delay_int, &delay_frac, &dispersion_int, &dispersion_frac, &reference_id, &ref_ts_int, &ref_ts_frac, &orig_ts_int, &orig_ts_frac, &ref_ts_int, &ref_ts_frac, &xmt_ts_int, &xmt_ts_frac, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_ntp (leap_indicator, version, mode, stratum, poll, precision, delay_int, delay_frac, dispersion_int, dispersion_frac, reference_id, ref_ts_int, ref_ts_frac, orig_ts_int, orig_ts_frac, rec_ts_int, rec_ts_frac, xmt_ts_int, xmt_ts_frac, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2 (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t len = 0;
	u_int32_t type = LIBNET_OSPF_UMD;
	u_int8_t *rtr_id = self->ipaddr4;
	int rtr_id_len = 4;
	u_int8_t *area_id = PYLIBNET_BROADCAST_IPV4;
	int area_id_len = 4;
	u_int32_t sum = 0;
	u_int32_t autype = LIBNET_OSPF_AUTH_NULL;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"len", "type", "rtr_id", "area_id", "sum", "autype", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIt#t#IIz#i", kwlist, &len, &type, &rtr_id, &rtr_id_len, &area_id, &area_id_len, &sum, &autype, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(area_id);
	PYLIBNET_ERRIP4(rtr_id);
	
	AUTOSIZE(LIBNET_OSPF_H);
	
	ptag = libnet_build_ospfv2 (len, type, U_INT32_TP(rtr_id), U_INT32_TP(area_id), sum, autype, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2_hello (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *netmask = PYLIBNET_BROADCAST_IPV4;
	int netmask_len = 4;
	u_int32_t interval = PYLIBNET_RANDOM_U16;
	u_int32_t opts = 0;
	u_int32_t priority = 0;
	u_int32_t dead_int = PYLIBNET_RANDOM_U16;
	u_int8_t *des_rtr = PYLIBNET_BROADCAST_IPV4;
	int des_rtr_len = 4;
	u_int8_t *bkup_rtr = PYLIBNET_BROADCAST_IPV4;
	int bkup_rtr_len = 4;
	u_int8_t *neighbor = self->ipaddr4;
	int neighbor_len = 4;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"netmask", "interval", "opts", "priority", "dead_int", "des_rtr", "bkup_rtr", "neighbor", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#IIIIt#t#t#z#i", kwlist, &netmask, &netmask_len, &opts, &priority, &dead_int, &des_rtr, &des_rtr_len, &bkup_rtr, &bkup_rtr_len, &neighbor, &neighbor_len, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(des_rtr);
	PYLIBNET_ERRIP4(des_rtr);
	PYLIBNET_ERRIP4(bkup_rtr);
	PYLIBNET_ERRIP4(neighbor);

#if LIBNET_RELEASE <= 2
	ptag = libnet_build_ospfv2_hello (U_INT32_TP(netmask), interval, opts, priority, dead_int, U_INT32_TP(des_rtr), U_INT32_TP(bkup_rtr), U_INT32_TP(neighbor), payload, payload_s, self->l, ptag);
#elif LIBNET_RELEASE >= 3
	ptag = libnet_build_ospfv2_hello (U_INT32_TP(netmask), interval, opts, priority, dead_int, U_INT32_TP(des_rtr), U_INT32_TP(bkup_rtr), payload, payload_s, self->l, ptag);
#endif

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2_dbd (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t dgram_len = 0;
	u_int32_t opts = 0;
	u_int32_t type = LIBNET_DBD_IBI;
	u_int32_t seqnum = PYLIBNET_RANDOM_U32;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"dgram_len", "opts", "type", "seqnum", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIz#i", kwlist, &dgram_len, &opts, &type, &seqnum, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE1(dgram_len, LIBNET_OSPF_DBD_H);

	ptag = libnet_build_ospfv2_dbd (dgram_len, opts, type, seqnum, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2_lsr (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t type = 0;
	u_int32_t lsid = PYLIBNET_RANDOM_U32;
	u_int8_t *advrtr = self->ipaddr4;
	int advrtr_len = 4;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"type", "lsid", "advrtr", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIt#z#i", kwlist, &type, &lsid, &advrtr, &advrtr_len, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(advrtr);                                   

	ptag = libnet_build_ospfv2_lsr (type, lsid, U_INT32_TP(advrtr), payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2_lsu (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t num = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"num", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|Iz#i", kwlist, &num, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_ospfv2_lsu (num, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2_lsa (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t age = PYLIBNET_RANDOM_U16;
	u_int32_t opts = 0;
	u_int32_t type = 0;
	u_int32_t lsid = PYLIBNET_RANDOM_U32;
	u_int8_t *advrtr = self->ipaddr4;
	u_int32_t advrtr_len = 4;
	u_int32_t seqnum = PYLIBNET_RANDOM_U32;
	u_int32_t sum = 0;
	u_int32_t len = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"age", "opts", "type", "lsid", "advrtr", "seqnum", "sum", "len", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIt#IIIz#i", kwlist, &age, &opts, &type, &lsid, &advrtr, &advrtr_len, &seqnum, &sum, &len, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(advrtr);

	AUTOSIZE(LIBNET_OSPF_LSA_H);

	ptag = libnet_build_ospfv2_lsa (age, opts, type, lsid, U_INT32_TP(advrtr), seqnum, sum, len, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2_lsa_rtr (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t flags = LIBNET_RTR_FLAGS_W;
	u_int32_t num = 0;
	u_int32_t id = LIBNET_LINK_ID_NBR_ID;
	u_int8_t *data = self->ipaddr4;
	int data_len = 4;
	u_int32_t type = LIBNET_RTR_TYPE_PTP;
	u_int32_t tos = 0;
	u_int32_t metric = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"flags", "num", "id", "data", "type", "tos", "metric", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIt#IIIz#i", kwlist, &flags, &num, &id, &data, &data_len, &type, &tos, &metric, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(data);

	ptag = libnet_build_ospfv2_lsa_rtr (flags, num, id, U_INT32_TP(data), type, tos, metric, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2_lsa_net (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *nmask = PYLIBNET_BROADCAST_IPV4;
	int nmask_len = 4;
	u_int8_t *rtrid = self->ipaddr4;
	int rtrid_len = 4;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"nmask", "rtrid", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#t#z#i", kwlist, &nmask, &nmask_len, &rtrid, &rtrid_len, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(nmask);
	PYLIBNET_ERRIP4(rtrid);

	ptag = libnet_build_ospfv2_lsa_net (U_INT32_TP(nmask), U_INT32_TP(rtrid), payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2_lsa_sum (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *nmask = PYLIBNET_BROADCAST_IPV4;
	u_int32_t nmask_len = 4;
	u_int32_t metric = PYLIBNET_RANDOM_U32;
	u_int32_t tos = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"nmask", "metric", "tos", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#IIz#i", kwlist, &nmask, &nmask_len, &metric, &tos, &payload, &payload_s, &ptag))
		return NULL;
	
	PYLIBNET_ERRIP4(nmask);

	ptag = libnet_build_ospfv2_lsa_sum (U_INT32_TP(nmask), metric, tos, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_ospfv2_lsa_as (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *nmask = PYLIBNET_BROADCAST_IPV4;
	int nmask_len = 4;
	u_int32_t metric = PYLIBNET_RANDOM_U32;
	u_int8_t *fwdaddr = self->ipaddr4;
	int fwdaddr_len = 4;
	u_int32_t tag = PYLIBNET_RANDOM_U32;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"nmask", "metric", "fwdaddr", "tag", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#It#Iz#i", kwlist, &nmask, &nmask_len, &metric, &fwdaddr, &fwdaddr_len, &tag, &payload, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(nmask);
	PYLIBNET_ERRIP4(fwdaddr); 

	ptag = libnet_build_ospfv2_lsa_as (U_INT32_TP(nmask), metric, U_INT32_TP(fwdaddr), tag, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_data (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;
	static char *kwlist[] = {"payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#i", kwlist, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_data (payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_dhcpv4 (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t opcode = LIBNET_DHCP_REQUEST;
	u_int32_t htype = 1;
	u_int32_t hlen = ETHER_ADDR_LEN;
	u_int32_t hopcount = PYLIBNET_RANDOM_U8;
	u_int32_t xid = PYLIBNET_RANDOM_U32;
	u_int32_t secs = PYLIBNET_RANDOM_U16;
	u_int32_t flags = 1;
	u_int8_t *cip = (u_int8_t *)"\x00\x00\x00\x00";
	int cip_len = 4;
	u_int8_t *yip = cip;
	int yip_len = 4;
	u_int8_t *sip = cip;
	int sip_len = 4;
	u_int8_t *gip = cip;
	int gip_len = 4;
	u_int8_t *chaddr = self->hwaddr;
	int chaddr_len = 6;
	u_int8_t *sname = NULL;
	u_int8_t *file = NULL;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"opcode", "htype", "hlen", "hopcount", "xid", "secs", "flags", "cip", "yip", "sip", "gip", "chaddr", "sname", "file", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIt#t#t#t#t#ssz#i", kwlist, &opcode, &htype, &hlen, &hopcount, &xid, &secs, &flags, &cip, &cip_len, &yip, &yip_len, &sip, &sip_len, &gip, &gip_len, &chaddr, &chaddr_len, &sname, &file, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(cip);
	PYLIBNET_ERRIP4(yip);
	PYLIBNET_ERRIP4(sip);
	PYLIBNET_ERRIP4(gip);
	PYLIBNET_ERRCHADDR(chaddr);

	ptag = libnet_build_dhcpv4 (opcode, htype, hlen, hopcount, xid, secs, flags, U_INT32_TP(cip), U_INT32_TP(yip), U_INT32_TP(sip), U_INT32_TP(gip), chaddr, sname, file, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_bootpv4 (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t opcode = LIBNET_DHCP_REQUEST;
	u_int32_t htype = 1;
	u_int32_t hlen = 0;
	u_int32_t hopcount = PYLIBNET_RANDOM_U8;
	u_int32_t xid = PYLIBNET_RANDOM_U32;
	u_int32_t secs = PYLIBNET_RANDOM_U16;
	u_int32_t flags = 1;
	u_int8_t *cip = (u_int8_t *)"\x00\x00\x00\x00";
	int cip_len = 4;
	u_int8_t *yip = cip;
	int yip_len = 4;
	u_int8_t *sip = cip;
	int sip_len = 4;
	u_int8_t *gip = cip;
	int gip_len = 4;
	u_int8_t *chaddr = self->hwaddr;
	int chaddr_len = 6;
	u_int8_t *sname = NULL;
	u_int8_t *file = NULL;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"opcode", "htype", "hlen", "hopcount", "xid", "secs", "flags", "cip", "yip", "sip", "gip", "chaddr", "sname", "file", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIt#t#t#t#t#ssz#i", kwlist, &opcode, &htype, &hlen, &hopcount, &xid, &secs, &flags, &cip, &cip_len, &yip, &yip_len, &sip, &sip_len, &gip, &gip_len, &chaddr, &chaddr_len, &sname, &file, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRIP4(cip);
	PYLIBNET_ERRIP4(yip);
	PYLIBNET_ERRIP4(sip);
	PYLIBNET_ERRIP4(gip);
	PYLIBNET_ERRIP4(chaddr);

	AUTOSIZE1(hlen, LIBNET_DHCPV4_H);

	ptag = libnet_build_bootpv4 (opcode, htype, hlen, hopcount, xid, secs, flags, U_INT32_TP(cip), U_INT32_TP(yip), U_INT32_TP(sip), U_INT32_TP(gip), chaddr, sname, file, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_getgre_length (context *self, PyObject *args, PyObject *kwargs)
{

	int len = 0;
	u_int32_t fv = 0;
	static char *kwlist[] = {"fv", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i", kwlist, &fv))
		return NULL;

	len = libnet_getgre_length (fv);

	if (len == -1) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("i", len);

}


static PyObject *
context_build_gre (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t fv = 0;
	u_int32_t type = GRE_IP;
	u_int32_t sum = 0;
	u_int32_t offset = 0;
	u_int32_t key = 0;
	u_int32_t seq = 0;
	u_int32_t len = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"fv", "type", "sum", "offset", "key", "seq", "len", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIz#i", kwlist, &fv, &type, &sum, &offset, &key, &seq, &len, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE(LIBNET_GRE_H);

	ptag = libnet_build_gre (fv, type, sum, offset, key, seq, len, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_egre (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t fv = 0;
	u_int32_t type = GRE_IP;
	u_int32_t sum = 0;
	u_int32_t offset = 0;
	u_int32_t key = 0;
	u_int32_t seq = 0;
	u_int32_t len = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"fv", "type", "sum", "offset", "key", "seq", "len", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIz#i", kwlist, &fv, &type, &sum, &offset, &key, &seq, &len, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE(LIBNET_GRE_H);

	ptag = libnet_build_egre (fv, type, sum, offset, key, seq, len, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_gre_sre (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t af = AF_INET;
	u_int32_t offset = 0;
	u_int32_t length = 0;
	u_int8_t *routing = NULL;
	int routing_len = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"af", "offset", "length", "routing", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIt#z#i", kwlist, &af, &offset, &length, &routing, &routing_len, &payload, &payload_s, &ptag))
		return NULL;

	AUTOSIZE1(length, LIBNET_GRE_SRE_H);

	ptag = libnet_build_gre_sre (af, offset, length, routing, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_gre_last_sre (context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	static char *kwlist[] = {"ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i", kwlist, &ptag))
		return NULL;

	if (ptag == 0) {
		PyErr_SetString(PyErr_LibnetError, "Expected a ptag.");
		return NULL;
	}

	ptag = libnet_build_gre_last_sre (self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_bgp4_header (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *marker = NULL;
	int marker_len = 0;
	u_int32_t len = 0;
	u_int32_t type = LIBNET_BGP4_OPEN;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"marker", "len", "type", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#IIz#i", kwlist, &marker, &marker_len, &len, &type, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRTYPE(marker, LIBNET_BGP4_MARKER_SIZE, "BPG4 marker");

	AUTOSIZE(LIBNET_BGP4_HEADER_H);

	ptag = libnet_build_bgp4_header (marker, len, type, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_bgp4_open (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t version = 0;
	u_int32_t src_as = PYLIBNET_RANDOM_U16;
	u_int32_t hold_time = PYLIBNET_RANDOM_U16;
	u_int32_t bgp_id = PYLIBNET_RANDOM_U32;
	u_int32_t opt_len = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"version", "src_as", "hold_time", "bgp_id", "opt_len", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIz#i", kwlist, &version, &src_as, &hold_time, &bgp_id, &opt_len, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_bgp4_open (version, src_as, hold_time, bgp_id, opt_len, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_bgp4_update (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t unfeasible_rt_len = 0;
	u_int8_t *withdrawn_rt = NULL;
	u_int32_t total_path_attr_len = 0;
	u_int8_t *path_attributes = NULL;
	u_int32_t info_len = 0;
	u_int8_t *reachability_info = NULL;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"withdrawn_rt", "path_attributes", "reachability_info", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#t#t#z#i", kwlist, &withdrawn_rt, &unfeasible_rt_len, &path_attributes, &total_path_attr_len, &reachability_info, &info_len, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_bgp4_update (unfeasible_rt_len, withdrawn_rt, total_path_attr_len, path_attributes, info_len, reachability_info, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_bgp4_notification (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t err_code = 0;
	u_int32_t err_subcode = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"err_code", "err_subcode", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIz#i", kwlist, &err_code, &err_subcode, &payload, &payload_s, &ptag))
		return NULL;

	ptag = libnet_build_bgp4_notification (err_code, err_subcode, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_build_sebek (context *self, PyObject *args, PyObject *kwargs)
{

	u_int32_t magic = 0;
	u_int32_t version = SEBEK_PROTO_VERSION;
	u_int32_t type = SEBEK_TYPE_READ;
	u_int32_t counter = PYLIBNET_RANDOM_U32;
	u_int32_t time_sec = PYLIBNET_RANDOM_U32;
	u_int32_t time_usec = PYLIBNET_RANDOM_U32;
	u_int32_t pid = 0;
	u_int32_t uid = 0;
	u_int32_t fd = 0;
	u_int8_t *cmd = NULL;
	int cmd_len = 0;
	u_int32_t length = 0;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"magic", "version", "type", "counter", "time_sec", "time_usec", "pid", "uid", "fd", "cmd", "length", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IIIIIIIIIt#iz#i", kwlist, &magic, &version, &type, &counter, &time_sec, &time_usec, &pid, &uid, &fd, &cmd, &cmd_len, &length, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERRTYPE(cmd, SEBEK_CMD_LENGTH, "Sebek command");

	AUTOSIZE1(length, LIBNET_SEBEK_H);

	ptag = libnet_build_sebek (magic, version, type, counter, time_sec, time_usec, pid, uid, fd, cmd, length, payload, payload_s, self->l, ptag);

	PYLIBNET_ERRPTAG;

	return Py_BuildValue("i", ptag);

}

/*
static PyObject *
context_build_link (context *self, PyObject *args, PyObject *kwargs)
{

	u_int8_t *dst = PYLIBNET_BROADCAST_MAC;
	int dst_len = 6;
	u_int8_t *src = self->hwaddr;
	int src_len = 6;
	u_int8_t *oui = (u_int8_t *)"\x00\x00\x00"; 
	int oui_len = 3;
	u_int32_t type = ETHERTYPE_IP;
	u_int8_t *payload = NULL;
	u_int32_t payload_s = 0;
	libnet_ptag_t ptag = 0;

	static char *kwlist[] = {"dst", "src", "oui", "type", "payload", "ptag", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#t#t#iz#i", kwlist, &dst, &dst_len, &src, &src_len, &oui, &oui_len, &type, &payload, &payload_s, &ptag))
		return NULL;

	PYLIBNET_ERROR_STR(dst, dst_len, 6, "Expected a destination hardware address.");
	PYLIBNET_ERROR_STR(src, src_len, 6, "Expected a source hardware address.");
	PYLIBNET_ERROR_STR(oui, oui_len, 3, "Expected an organization unique identifier.");

	ptag = libnet_build_link (dst, src, oui, type, payload, payload_s, self->l, ptag);

	if (ptag == -1) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("i", ptag);

}


static PyObject *
context_autobuild_link (context *self, PyObject *args, PyObject *kwargs)
{

	libnet_ptag_t ptag = 0;
	u_int8_t *dst = PYLIBNET_BROADCAST_MAC;
	int dst_len = 6;
	u_int8_t *oui = (u_int8_t *)"\x00\x00\x00";
	int oui_len = 3;
	u_int16_t type = ETHERTYPE_IP;
	static char *kwlist[] = {"dst", "oui", "type", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|t#t#i", kwlist, &dst, &dst_len, &oui, &oui_len, &type))
		return NULL;

	PYLIBNET_ERROR_STR(dst, dst_len, 6, "Expected a destination hardware address.");
	PYLIBNET_ERROR_STR(oui, oui_len, 3, "Expected an organization unique identifier.");

	ptag = libnet_autobuild_link (dst, oui, type, self->l);

	if (ptag == -1) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	return Py_BuildValue("i", ptag);

}
*/