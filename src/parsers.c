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

#define PYLIBNET_POINT_HDR(x) struct x *hdr = (struct x *)buf
#define PYLIBNET_KEYPAIR(x) #x, hdr->x
#define PYLIBNET_KEYPAIR_HS(x) #x, ntohs(hdr->x)
#define PYLIBNET_KEYPAIR_HL(x) #x, ntohl(hdr->x)
#define PYLIBNET_KEYPAIR_INADDR4(x) #x, libnet_addr2name4(*((u_int32_t *)&hdr->x), LIBNET_DONT_RESOLVE)
#define PYLIBNET_KEYPAIR_INADDR41(x) #x, libnet_addr2name4(x, LIBNET_DONT_RESOLVE)
#define PYLIBNET_KEYPAIR_INADDR42(x, y) x, libnet_addr2name4(y, LIBNET_DONT_RESOLVE)
#define PYLIBNET_KEYPAIR_INADDR6(x) #x, pylibnet_addr2name6(hdr->x)
#define PYLIBNET_KEYPAIR_HWADDR(x) #x, pylibnet_hex_ntoa(hdr->x, 6)
#define PYLIBNET_KEYPAIR_HWADDR1(x) #x, pylibnet_hex_ntoa(x, 6)
#define PYLIBNET_KEYPAIR_HWADDR2(x,y) x, pylibnet_hex_ntoa(y, 6)
#define PYLIBNET_KEYPAIR_HEX(x,y) #x, pylibnet_hex_ntoa(hdr->x, y)
#define PYLIBNET_KEYPAIR_OUI(x) #x, Py_BuildValue("s#", hdr->x, 3)
#define PYLIBNET_RESERVED 0

PyObject *pylibnet_addr2name6(struct libnet_in6_addr ip6) {

	char hostname[64];

	libnet_addr2name6_r(ip6, 1, hostname, 64);

	return Py_BuildValue("s", hostname);

}

PyObject *pylibnet_hex_ntoa(u_int8_t *buf, int len) {

	PyObject *Str;
	int i, str_len = (len * 3);
	char *str = malloc(sizeof(char) * str_len);
	char curr[4];

	memset(str, '\0', sizeof(char) * str_len);
	memset(curr, '\0', sizeof(char) * 4);

	for (i = 0; i < len; i++) {
		snprintf(curr, 3, "%02x", buf[i]);
		curr[2] = (i+1 < len)?':':'\0';
		strcat(str, curr);
	}
	
	Str = Py_BuildValue("s", str);
	free(str);

	return Str;

}

static PyObject *
pylibnet_parse_reserved(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{ Py_INCREF(Py_None); return Py_None; }

static PyObject *
pylibnet_parse_arp_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_arp_hdr);

	u_int8_t *sha = (buf + sizeof(struct libnet_arp_hdr));
	u_int32_t *spa = (u_int32_t *)(sha + sizeof(struct libnet_ether_addr));
	u_int8_t *tha = ((u_int8_t *)spa + sizeof(u_int32_t));
	u_int32_t *tpa = (u_int32_t *)(tha + sizeof(struct libnet_ether_addr));

	return Py_BuildValue("{s:H,s:H,s:B,s:B,s:H,s:S,s:s,s:S,s:s}",
		PYLIBNET_KEYPAIR_HS(ar_hrd),
		PYLIBNET_KEYPAIR_HS(ar_pro),
		PYLIBNET_KEYPAIR(ar_hln),
		PYLIBNET_KEYPAIR(ar_pln),
		PYLIBNET_KEYPAIR_HS(ar_op),
		PYLIBNET_KEYPAIR_HWADDR1(sha),
		PYLIBNET_KEYPAIR_INADDR42("spa", *spa),
		PYLIBNET_KEYPAIR_HWADDR1(tha),
		PYLIBNET_KEYPAIR_INADDR42("tpa", *tpa));
}

static PyObject *
pylibnet_parse_dhcpv4_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_dhcpv4_hdr);

	return Py_BuildValue("{s:B,s:B,s:B,s:B,s:I,s:H,s:H,s:s,s:s,s:s,s:s,s:S,s:s,s:s,s:I}",
		PYLIBNET_KEYPAIR(dhcp_opcode),
		PYLIBNET_KEYPAIR(dhcp_htype),
		PYLIBNET_KEYPAIR(dhcp_hlen),
		PYLIBNET_KEYPAIR(dhcp_hopcount),
		PYLIBNET_KEYPAIR_HL(dhcp_xid),
		PYLIBNET_KEYPAIR_HS(dhcp_secs),
		PYLIBNET_KEYPAIR_HS(dhcp_flags),
		PYLIBNET_KEYPAIR_INADDR4(dhcp_cip),
		PYLIBNET_KEYPAIR_INADDR4(dhcp_yip),
		PYLIBNET_KEYPAIR_INADDR4(dhcp_sip),
		PYLIBNET_KEYPAIR_INADDR4(dhcp_gip),
		PYLIBNET_KEYPAIR_HEX(dhcp_chaddr, hdr->dhcp_hlen),
		PYLIBNET_KEYPAIR(dhcp_sname),
		PYLIBNET_KEYPAIR(dhcp_file),
		PYLIBNET_KEYPAIR_HL(dhcp_magic));
}

static PyObject *
pylibnet_parse_dnsv4_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len) {

	if (h_len == LIBNET_UDP_DNSV4_H) {

		PYLIBNET_POINT_HDR(libnet_dnsv4udp_hdr);

		return Py_BuildValue("{s:H,s:H,s:H,s:H,s:H,s:H}",
			PYLIBNET_KEYPAIR_HS(id),
			PYLIBNET_KEYPAIR_HS(flags),
			PYLIBNET_KEYPAIR_HS(num_q),
			PYLIBNET_KEYPAIR_HS(num_answ_rr),
			PYLIBNET_KEYPAIR_HS(num_auth_rr),
			PYLIBNET_KEYPAIR_HS(num_addi_rr));
	}

	PYLIBNET_POINT_HDR(libnet_dnsv4_hdr);

	return Py_BuildValue("{s:H,s:H,s:H,s:H,s:H,s:H,s:H}",
		PYLIBNET_KEYPAIR_HS(h_len),
		PYLIBNET_KEYPAIR_HS(id),
		PYLIBNET_KEYPAIR_HS(flags),
		PYLIBNET_KEYPAIR_HS(num_q),
		PYLIBNET_KEYPAIR_HS(num_answ_rr),
		PYLIBNET_KEYPAIR_HS(num_auth_rr),
		PYLIBNET_KEYPAIR_HS(num_addi_rr));

}

static PyObject *
pylibnet_parse_eth_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len) 
{
	PYLIBNET_POINT_HDR(libnet_ethernet_hdr);

	return Py_BuildValue("{s:S,s:S,s:H}",
		PYLIBNET_KEYPAIR_HWADDR(ether_dhost),
		PYLIBNET_KEYPAIR_HWADDR(ether_shost),
		PYLIBNET_KEYPAIR_HS(ether_type));
}

static PyObject *
pylibnet_parse_icmpv4_echo_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_icmpv4_hdr);

	return Py_BuildValue("{s:B,s:B,s:H,s:H,s:H}",
		PYLIBNET_KEYPAIR(icmp_type),
		PYLIBNET_KEYPAIR(icmp_code),
		PYLIBNET_KEYPAIR_HS(icmp_sum),
		PYLIBNET_KEYPAIR_HS(icmp_id),
		PYLIBNET_KEYPAIR_HS(icmp_seq));
}

static PyObject *
pylibnet_parse_icmpv4_mask_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_icmpv4_hdr);

	return Py_BuildValue("{s:B,s:B,s:H,s:H,s:H,s:s}",
		PYLIBNET_KEYPAIR(icmp_type),
		PYLIBNET_KEYPAIR(icmp_code),
		PYLIBNET_KEYPAIR_HS(icmp_sum),
		PYLIBNET_KEYPAIR_HS(icmp_id),
		PYLIBNET_KEYPAIR_HS(icmp_seq),
		PYLIBNET_KEYPAIR_INADDR4(icmp_mask));
}

static PyObject *
pylibnet_parse_icmpv4_unreach_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_icmpv4_hdr);

#define icmp_pad hun.frag.pad
#define icmp_mtu hun.frag.mtu 

	return Py_BuildValue("{s:B,s:B,s:H,s:H,s:H}",
		PYLIBNET_KEYPAIR(icmp_type),
		PYLIBNET_KEYPAIR(icmp_code),
		PYLIBNET_KEYPAIR_HS(icmp_sum),
		PYLIBNET_KEYPAIR_HS(icmp_pad),
		PYLIBNET_KEYPAIR_HS(icmp_mtu));
}

static PyObject *
pylibnet_parse_icmpv4_timxceed_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_icmpv4_hdr);

	return Py_BuildValue("{s:B,s:B,s:H,s:H,s:H}",
		PYLIBNET_KEYPAIR(icmp_type),
		PYLIBNET_KEYPAIR(icmp_code),
		PYLIBNET_KEYPAIR_HS(icmp_sum),
		PYLIBNET_KEYPAIR_HS(icmp_id),
		PYLIBNET_KEYPAIR_HS(icmp_seq));
}

static PyObject *
pylibnet_parse_icmpv4_redirect_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_icmpv4_hdr);

#define icmp_gateway hun.gateway

	return Py_BuildValue("{s:B,s:B,s:B,s:s}",
		PYLIBNET_KEYPAIR(icmp_type),
		PYLIBNET_KEYPAIR(icmp_code),
		PYLIBNET_KEYPAIR_HS(icmp_sum),
		PYLIBNET_KEYPAIR_INADDR4(icmp_gateway));
}

static PyObject *
pylibnet_parse_icmpv4_ts_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_icmpv4_hdr);

	return Py_BuildValue("{s:B,s:B,s:H,s:H,s:H,s:I}",
		PYLIBNET_KEYPAIR(icmp_type),
		PYLIBNET_KEYPAIR(icmp_code),
		PYLIBNET_KEYPAIR_HS(icmp_sum),
		PYLIBNET_KEYPAIR_HS(icmp_id),
		PYLIBNET_KEYPAIR_HS(icmp_seq),
		PYLIBNET_KEYPAIR_HL(icmp_otime));
}

static PyObject *
pylibnet_parse_icmpv4_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	
	PYLIBNET_POINT_HDR(libnet_icmpv4_hdr);

	switch (hdr->icmp_type) {
		case ICMP_TSTAMP:
		case ICMP_TSTAMPREPLY:
			return pylibnet_parse_icmpv4_ts_h(buf, h_len, b_len);
		case ICMP_MASKREQ:
		case ICMP_MASKREPLY:
			return pylibnet_parse_icmpv4_mask_h(buf, h_len, b_len);
		case ICMP_UNREACH:
			return pylibnet_parse_icmpv4_unreach_h(buf, h_len, b_len);
		case ICMP_TIMXCEED:
			return pylibnet_parse_icmpv4_timxceed_h(buf, h_len, b_len);
		case ICMP_REDIRECT:
			return pylibnet_parse_icmpv4_redirect_h(buf, h_len, b_len);
		case ICMP_IREQ:
		case ICMP_ECHOREPLY:
		case ICMP_ECHO:
			return pylibnet_parse_icmpv4_echo_h(buf, h_len, b_len);
		case ICMP_SOURCEQUENCH:
		case ICMP_ROUTERADVERT:
		case ICMP_ROUTERSOLICIT:
		case ICMP_PARAMPROB:
		default:
			break;
	}

	return Py_BuildValue("{s:B,s:B,s:H}",
		PYLIBNET_KEYPAIR(icmp_type),
		PYLIBNET_KEYPAIR(icmp_code),
		PYLIBNET_KEYPAIR_HS(icmp_sum));

}

static PyObject *
pylibnet_parse_igmp_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_igmp_hdr);
	return Py_BuildValue("{s:B,s:B,s:H,s:s}",
		PYLIBNET_KEYPAIR(igmp_type),
		PYLIBNET_KEYPAIR(igmp_code),
		PYLIBNET_KEYPAIR_HS(igmp_sum),
		PYLIBNET_KEYPAIR_INADDR4(igmp_group));
}

static PyObject *
pylibnet_parse_ipv4_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	
	PYLIBNET_POINT_HDR(libnet_ipv4_hdr);
	return Py_BuildValue("{s:B,s:B,s:B,s:H,s:H,s:H,s:B,s:B,s:H,s:s,s:s}",
			PYLIBNET_KEYPAIR(ip_hl), 
			PYLIBNET_KEYPAIR(ip_v), 
			PYLIBNET_KEYPAIR(ip_tos), 
			PYLIBNET_KEYPAIR_HS(ip_len),
			PYLIBNET_KEYPAIR_HS(ip_id), 
			PYLIBNET_KEYPAIR_HS(ip_off), 
			PYLIBNET_KEYPAIR(ip_ttl), 
			PYLIBNET_KEYPAIR(ip_p),
			PYLIBNET_KEYPAIR_HS(ip_sum), 
			PYLIBNET_KEYPAIR_INADDR4(ip_src), 
			PYLIBNET_KEYPAIR_INADDR4(ip_dst));
}

static PyObject *
pylibnet_parse_ipo_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	return (b_len > 1)?Py_BuildValue("{s:B,s:B,s:B,s:s#}",
		"ipo_copy", buf[0] >> 7,
		"ipo_class", (buf[0] >> 5) & 3,
		"ipo_option", buf[0] & 0x1F,
		"ipo_data", buf+1, b_len-1)
		:Py_BuildValue("{s:B,s:B,s:B}",
		"ipo_copy", buf[0] >> 7,
		"ipo_class", (buf[0] >> 5) & 3,
		"ipo_option", buf[0] & 0x1F);
}

static PyObject *
pylibnet_parse_ipdata(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	return Py_BuildValue("{s:s#}", "ipdata", buf, b_len);
}

static PyObject *
pylibnet_parse_ospf_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_ospf_hdr);
	
	return Py_BuildValue("{s:B,s:B,s:H,s:s,s:s,s:H,s:H}",
			PYLIBNET_KEYPAIR(ospf_v),
			PYLIBNET_KEYPAIR(ospf_type),
			PYLIBNET_KEYPAIR_HS(ospf_len),
			PYLIBNET_KEYPAIR_INADDR4(ospf_rtr_id),
			PYLIBNET_KEYPAIR_INADDR4(ospf_area_id),
			PYLIBNET_KEYPAIR_HS(ospf_sum),
			PYLIBNET_KEYPAIR_HS(ospf_auth_type));
}
static PyObject *
pylibnet_parse_ospf_hello_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_ospf_hello_hdr);
	
	return Py_BuildValue("{s:s,s:H,s:B,s:B,s:I,s:s,s:s,s:s}",
			PYLIBNET_KEYPAIR_INADDR4(hello_nmask),
			PYLIBNET_KEYPAIR_HS(hello_intrvl),
			PYLIBNET_KEYPAIR(hello_opts),
			PYLIBNET_KEYPAIR(hello_rtr_pri),
			PYLIBNET_KEYPAIR_HL(hello_dead_intvl),
			PYLIBNET_KEYPAIR_INADDR4(hello_des_rtr),
			PYLIBNET_KEYPAIR_INADDR4(hello_bkup_rtr),
			PYLIBNET_KEYPAIR_INADDR4(hello_nbr));
}

static PyObject *
pylibnet_parse_ospf_dbd_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_dbd_hdr);

	return Py_BuildValue("{s:H,s:B,s:B,s:I}",
			PYLIBNET_KEYPAIR_HS(dbd_mtu_len),
			PYLIBNET_KEYPAIR(dbd_opts),
			PYLIBNET_KEYPAIR(dbd_type),
			PYLIBNET_KEYPAIR_HL(dbd_seq));
}

static PyObject *
pylibnet_parse_ospf_lsr_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_lsr_hdr);
	return Py_BuildValue("{s:I,s:I,s:s}",
			PYLIBNET_KEYPAIR_HL(lsr_type),
			PYLIBNET_KEYPAIR_HL(lsr_lsid),
			PYLIBNET_KEYPAIR_INADDR4(lsr_adrtr));
}

static PyObject *
pylibnet_parse_ospf_lsu_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_lsu_hdr);
	return Py_BuildValue("{s:I}",
			PYLIBNET_KEYPAIR_HL(lsu_num));
}

static PyObject *
pylibnet_parse_ospf_lsa_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_lsa_hdr);
	return Py_BuildValue("{s:H,s:B,s:B,s:I,s:s,s:I,s:H,s:H}",
			PYLIBNET_KEYPAIR_HS(lsa_age),
			PYLIBNET_KEYPAIR(lsa_opts),
			PYLIBNET_KEYPAIR(lsa_type),
			PYLIBNET_KEYPAIR_HL(lsa_id),
			PYLIBNET_KEYPAIR_INADDR4(lsa_adv),
			PYLIBNET_KEYPAIR_HL(lsa_seq),
			PYLIBNET_KEYPAIR_HS(lsa_sum),
			PYLIBNET_KEYPAIR_HS(lsa_len));
}

static PyObject *
pylibnet_parse_ospf_auth_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_auth_hdr);
	return Py_BuildValue("{s:H,s:B,s:B,s:I}",
			PYLIBNET_KEYPAIR_HS(ospf_auth_null),
			PYLIBNET_KEYPAIR(ospf_auth_keyid),
			PYLIBNET_KEYPAIR(ospf_auth_len),
			PYLIBNET_KEYPAIR_HL(ospf_auth_seq));
}

static PyObject *
pylibnet_parse_ospf_cksum(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{ PyErr_SetString(PyErr_LibnetError, "Packet parser not yet implemented."); return NULL; }

	static PyObject *
pylibnet_parse_ls_rtr_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_rtr_lsa_hdr);
	return Py_BuildValue("{s:H,s:H,s:I,s:I,s:B,s:B,s:B}",
			PYLIBNET_KEYPAIR_HS(rtr_flags),
			PYLIBNET_KEYPAIR_HS(rtr_num),
			PYLIBNET_KEYPAIR_HL(rtr_link_id),
			PYLIBNET_KEYPAIR_HL(rtr_link_data),
			PYLIBNET_KEYPAIR(rtr_type),
			PYLIBNET_KEYPAIR(rtr_tos_num),
			PYLIBNET_KEYPAIR(rtr_metric));
}

static PyObject *
pylibnet_parse_ls_net_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_net_lsa_hdr);
	return Py_BuildValue("{s:s,s:I}",
			PYLIBNET_KEYPAIR_INADDR4(net_nmask),
			PYLIBNET_KEYPAIR_HL(net_rtr_id));
}

static PyObject *
pylibnet_parse_ls_sum_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_sum_lsa_hdr);
	return Py_BuildValue("{s:s,s:I,s:I}",
			PYLIBNET_KEYPAIR_INADDR4(sum_nmask),
			PYLIBNET_KEYPAIR_HL(sum_metric),
			PYLIBNET_KEYPAIR_HL(sum_tos_metric));
}

static PyObject *
pylibnet_parse_ls_as_ext_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_as_lsa_hdr);
	return Py_BuildValue("{s:s,s:I,s:s,s:I}",
		PYLIBNET_KEYPAIR_INADDR4(as_nmask),
		PYLIBNET_KEYPAIR_HL(as_metric),
		PYLIBNET_KEYPAIR_INADDR4(as_fwd_addr),
		PYLIBNET_KEYPAIR_HL(as_rte_tag));
}

static PyObject *
pylibnet_parse_ntp_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_ntp_hdr);

#define TS_TO_HF(x) (1.0/ntohs(hdr->x.fraction)) + (ntohs(hdr->x.integer))
#define TS_TO_HD(x) (1.0/ntohl(hdr->x.fraction)) + (ntohl(hdr->x.integer))
	float ntp_delay = TS_TO_HF(ntp_delay);
	float ntp_dispersion = TS_TO_HF(ntp_dispersion);

	double ntp_ref_ts = TS_TO_HD(ntp_ref_ts);
	double ntp_orig_ts = TS_TO_HD(ntp_orig_ts);
	double ntp_rec_ts = TS_TO_HD(ntp_rec_ts);
	double ntp_xmt_ts = TS_TO_HD(ntp_xmt_ts);

	return Py_BuildValue("{s:B,s:B,s:B,s:B,s:f,s:f,s:d,s:d,s:d,s:d,s:I}",
		PYLIBNET_KEYPAIR(ntp_li_vn_mode),
		PYLIBNET_KEYPAIR(ntp_stratum),
		PYLIBNET_KEYPAIR(ntp_poll),
		PYLIBNET_KEYPAIR(ntp_precision),
		"ntp_delay", ntp_delay,
		"ntp_dispersion", ntp_dispersion,
		"ntp_ref_ts", ntp_ref_ts,
		"ntp_orig_ts", ntp_orig_ts,
		"ntp_rec_ts", ntp_rec_ts,
		"ntp_xmt_ts", ntp_xmt_ts,
		PYLIBNET_KEYPAIR_HL(ntp_reference_id));
}

static PyObject *
pylibnet_parse_rip_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_rip_hdr);

	return Py_BuildValue("{s:B,s:B,s:H,s:H,s:H,s:s,s:s,s:s,s:s}",
		PYLIBNET_KEYPAIR(rip_cmd),
		PYLIBNET_KEYPAIR(rip_ver),
		PYLIBNET_KEYPAIR_HS(rip_rd),
		PYLIBNET_KEYPAIR_HS(rip_af),
		PYLIBNET_KEYPAIR_HS(rip_rt),
		PYLIBNET_KEYPAIR_INADDR4(rip_addr),
		PYLIBNET_KEYPAIR_INADDR4(rip_mask),
		PYLIBNET_KEYPAIR_INADDR4(rip_next_hop),
		PYLIBNET_KEYPAIR_INADDR4(rip_metric));
}

static PyObject *
pylibnet_parse_tcp_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_tcp_hdr);
	return Py_BuildValue("{s:H,s:H,s:I,s:I,s:B,s:B,s:B,s:B,s:B,s:B,s:B,s:B,s:B,s:B,s:H,s:H,s:H}", 
		PYLIBNET_KEYPAIR_HS(th_sport), 
		PYLIBNET_KEYPAIR_HS(th_dport), 
		PYLIBNET_KEYPAIR_HL(th_seq), 
		PYLIBNET_KEYPAIR_HL(th_ack),
		PYLIBNET_KEYPAIR(th_x2), 
		PYLIBNET_KEYPAIR(th_off), 
		"th_fin", hdr->th_flags & TH_FIN, 
		"th_syn", (hdr->th_flags & TH_SYN) >> 1, 
		"th_rst", (hdr->th_flags & TH_RST) >> 2, 
		"th_push", (hdr->th_flags & TH_PUSH) >> 3,
		"th_ack", (hdr->th_flags & TH_ACK) >> 4, 
		"th_urg", (hdr->th_flags & TH_URG) >> 5,
		"th_ece", (hdr->th_flags & TH_ECE) >> 6, 
		"th_cwr", (hdr->th_flags & TH_CWR) >> 7,
		PYLIBNET_KEYPAIR_HS(th_win), 
		PYLIBNET_KEYPAIR_HS(th_sum), 
		PYLIBNET_KEYPAIR_HS(th_urp));
}

static PyObject *
pylibnet_parse_tcpo_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{ PyErr_SetString(PyErr_LibnetError, "Packet parser not yet implemented."); return NULL; }

static PyObject *
pylibnet_parse_tcpdata(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	return Py_BuildValue("{s:s#}", "tcpdata", buf, b_len);
}

static PyObject *
pylibnet_parse_udp_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_udp_hdr);
	return Py_BuildValue("{s:H,s:H,s:H,s:H}",
		PYLIBNET_KEYPAIR_HS(uh_sport),
		PYLIBNET_KEYPAIR_HS(uh_dport),
		PYLIBNET_KEYPAIR_HS(uh_ulen),
		PYLIBNET_KEYPAIR_HS(uh_sum));

}

static PyObject *
pylibnet_parse_vrrp_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_vrrp_hdr);

	return Py_BuildValue("{s:B,s:B,s:B,s:B,s:B,s:B,s:B,s:H}",
		PYLIBNET_KEYPAIR(vrrp_v),
		PYLIBNET_KEYPAIR(vrrp_t),
		PYLIBNET_KEYPAIR(vrrp_vrouter_id),
		PYLIBNET_KEYPAIR(vrrp_priority),
		PYLIBNET_KEYPAIR(vrrp_ip_count),
		PYLIBNET_KEYPAIR(vrrp_auth_type),
		PYLIBNET_KEYPAIR(vrrp_advert_int),
		PYLIBNET_KEYPAIR_HS(vrrp_sum));
}

static PyObject *
pylibnet_parse_data_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	return Py_BuildValue("{s:s#}", "data", buf, b_len);
}

static PyObject *
pylibnet_parse_cdp_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_cdp_hdr);
	return Py_BuildValue("{s:B,s:B,s:H,s:H,s:H}",
		PYLIBNET_KEYPAIR(cdp_version),
		PYLIBNET_KEYPAIR(cdp_ttl),
		PYLIBNET_KEYPAIR_HS(cdp_sum),
		PYLIBNET_KEYPAIR_HS(cdp_type),
		PYLIBNET_KEYPAIR_HS(cdp_len));
}

static PyObject *
pylibnet_parse_ipsec_esp_hdr_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_esp_hdr);
	return Py_BuildValue("{s:I,s:I,s:I}",
		PYLIBNET_KEYPAIR_HL(esp_spi),
		PYLIBNET_KEYPAIR_HL(esp_seq),
		PYLIBNET_KEYPAIR_HL(esp_iv));
}

static PyObject *
pylibnet_parse_ipsec_esp_ftr_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_esp_ftr);
	return Py_BuildValue("{s:B,s:B,s:s}",
		PYLIBNET_KEYPAIR(esp_pad_len),
		PYLIBNET_KEYPAIR(esp_nh),
		PYLIBNET_KEYPAIR(esp_auth));
}

static PyObject *
pylibnet_parse_ipsec_ah_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_ah_hdr);
	return Py_BuildValue("{s:B,s:B,s:H,s:I,s:I,s:I}",
		PYLIBNET_KEYPAIR(ah_nh),
		PYLIBNET_KEYPAIR(ah_len),
		PYLIBNET_KEYPAIR_HS(ah_res),
		PYLIBNET_KEYPAIR_HL(ah_spi),
		PYLIBNET_KEYPAIR_HL(ah_seq),
		PYLIBNET_KEYPAIR_HL(ah_auth));

}

static PyObject *
pylibnet_parse_802_1q_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_802_1q_hdr);
	return Py_BuildValue("{s:S,s:S,s:H,s:H,s:H}",
		PYLIBNET_KEYPAIR_HWADDR(vlan_dhost),
		PYLIBNET_KEYPAIR_HWADDR(vlan_shost),
		PYLIBNET_KEYPAIR_HS(vlan_tpi),
		PYLIBNET_KEYPAIR_HS(vlan_priority_c_vid),
		PYLIBNET_KEYPAIR_HS(vlan_len));
}

static PyObject *
pylibnet_parse_802_2_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_802_2_hdr);
	return Py_BuildValue("{s:B,s:B,s:B}",
		PYLIBNET_KEYPAIR(llc_dsap),
		PYLIBNET_KEYPAIR(llc_ssap),
		PYLIBNET_KEYPAIR(llc_control));
}

static PyObject *
pylibnet_parse_802_2snap_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_802_2snap_hdr);
	return Py_BuildValue("{s:B,s:B,s:B,s:S,s:H}",
		PYLIBNET_KEYPAIR(snap_dsap),
		PYLIBNET_KEYPAIR(snap_ssap),
		PYLIBNET_KEYPAIR(snap_control),
		PYLIBNET_KEYPAIR_OUI(snap_oui),
		PYLIBNET_KEYPAIR_HS(snap_type));
}

static PyObject *
pylibnet_parse_802_3_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_802_3_hdr);
	return Py_BuildValue("{s:S,s:S,s:H}",
		PYLIBNET_KEYPAIR_HWADDR(_802_3_dhost),
		PYLIBNET_KEYPAIR_HWADDR(_802_3_shost),
		PYLIBNET_KEYPAIR_HS(_802_3_len));
}

static PyObject *
pylibnet_parse_stp_conf_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_stp_conf_hdr);
	return Py_BuildValue("{s:H,s:B,s:B,s:B,s:S,s:I,s:S,s:H,s:H,s:H,s:H,s:H}",
		PYLIBNET_KEYPAIR_HS(stp_id),
		PYLIBNET_KEYPAIR(stp_version),
		PYLIBNET_KEYPAIR(stp_bpdu_type),
		PYLIBNET_KEYPAIR(stp_flags),
		PYLIBNET_KEYPAIR_HEX(stp_rootid, 8),
		PYLIBNET_KEYPAIR_HL(stp_rootpc),
		PYLIBNET_KEYPAIR_HEX(stp_bridgeid, 8),
		PYLIBNET_KEYPAIR_HS(stp_portid),
		PYLIBNET_KEYPAIR_HS(stp_mage),
		PYLIBNET_KEYPAIR_HS(stp_maxage),
		PYLIBNET_KEYPAIR_HS(stp_hellot),
		PYLIBNET_KEYPAIR_HS(stp_fdelay));

}

static PyObject *
pylibnet_parse_stp_tcn_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_stp_tcn_hdr);
	return Py_BuildValue("{s:H,s:B,s:B}",
		PYLIBNET_KEYPAIR_HS(stp_id),
		PYLIBNET_KEYPAIR(stp_version),
		PYLIBNET_KEYPAIR(stp_bpdu_type));
}

static PyObject *
pylibnet_parse_isl_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_isl_hdr);
	return Py_BuildValue("{s:S,s:B,s:B,s:S,s:H,s:S,s:H,s:H,s:H}",
		PYLIBNET_KEYPAIR_HEX(isl_dhost, 5),
		PYLIBNET_KEYPAIR(isl_user),
		PYLIBNET_KEYPAIR(isl_type),
		PYLIBNET_KEYPAIR_HWADDR(isl_shost),
		PYLIBNET_KEYPAIR_HS(isl_len),
		PYLIBNET_KEYPAIR_HWADDR(isl_snap),
		PYLIBNET_KEYPAIR_HS(isl_vid),
		PYLIBNET_KEYPAIR_HS(isl_index),
		PYLIBNET_KEYPAIR_HS(isl_reserved));
}

static PyObject *
pylibnet_parse_ipv6_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_ipv6_hdr);
	u_int32_t ip_flags = ntohl(*((u_int32_t *)hdr->ip_flags));
	return Py_BuildValue("{s:B,s:B,s:B,s:H,s:B,s:B,s:S,s:S}",
		"ip_ver", (ip_flags >> 28) & 0xf,
		"ip_tc", (ip_flags >> 20) & 0xff,
		"ip_fl", ip_flags & 0xfffff,
		PYLIBNET_KEYPAIR_HS(ip_len),
		PYLIBNET_KEYPAIR(ip_nh),
		PYLIBNET_KEYPAIR(ip_hl),
		PYLIBNET_KEYPAIR_INADDR6(ip_src),
		PYLIBNET_KEYPAIR_INADDR6(ip_dst));

}

static PyObject *
pylibnet_parse_802_1x_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_802_1x_hdr);
	return Py_BuildValue("{s:B,s:B,s:B}",
		PYLIBNET_KEYPAIR(dot1x_version),
		PYLIBNET_KEYPAIR(dot1x_type),
		PYLIBNET_KEYPAIR(dot1x_length));
}

static PyObject *
pylibnet_parse_rpc_call_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{

	PYLIBNET_POINT_HDR(libnet_rpc_call_tcp_hdr);

#define rpc_xid rpc_common.rpc_xid
#define rpc_type rpc_common.rpc_type
#define rpc_credentials_flavor rpc_common.rpc_call.rpc_credentials.rpc_auth_flavor
#define rpc_credentials_length rpc_common.rpc_call.rpc_credentials.rpc_auth_length
#define rpc_verifier_flavor rpc_common.rpc_call.rpc_verifier.rpc_auth_flavor
#define rpc_verifier_length rpc_common.rpc_call.rpc_verifier.rpc_auth_length
#define rpc_rpcvers rpc_common.rpc_call.rpc_rpcvers
#define rpc_prognum rpc_common.rpc_call.rpc_prognum
#define rpc_vers rpc_common.rpc_call.rpc_vers
#define rpc_procedure rpc_common.rpc_call.rpc_procedure
	
	return Py_BuildValue("{s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:I}",
		PYLIBNET_KEYPAIR_HL(rpc_record_marking),
		PYLIBNET_KEYPAIR_HL(rpc_xid),
		PYLIBNET_KEYPAIR_HL(rpc_type),
		PYLIBNET_KEYPAIR_HL(rpc_rpcvers),
		PYLIBNET_KEYPAIR_HL(rpc_prognum),
		PYLIBNET_KEYPAIR_HL(rpc_vers),
		PYLIBNET_KEYPAIR_HL(rpc_procedure),
		PYLIBNET_KEYPAIR_HL(rpc_credentials_flavor),
		PYLIBNET_KEYPAIR_HL(rpc_credentials_length),
		PYLIBNET_KEYPAIR_HL(rpc_verifier_flavor),
		PYLIBNET_KEYPAIR_HL(rpc_verifier_length));
}

static PyObject *
pylibnet_parse_mpls_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_mpls_hdr);
	return Py_BuildValue("{s:I}",
		PYLIBNET_KEYPAIR_HL(mpls_les));
}

static PyObject *
pylibnet_parse_fddi_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_fddi_hdr);

	return Py_BuildValue("{s:B,s:S,s:S,s:B,s:B,s:B,s:S,s:B,s:B}",
		PYLIBNET_KEYPAIR(fddi_frame_control),
		PYLIBNET_KEYPAIR_HEX(fddi_dhost, FDDI_ADDR_LEN),
		PYLIBNET_KEYPAIR_HEX(fddi_shost, FDDI_ADDR_LEN),
		PYLIBNET_KEYPAIR(fddi_llc_dsap),
		PYLIBNET_KEYPAIR(fddi_llc_ssap),
		PYLIBNET_KEYPAIR(fddi_llc_control_field),
		PYLIBNET_KEYPAIR_HEX(fddi_llc_org_code, LIBNET_ORG_CODE_SIZE),
		PYLIBNET_KEYPAIR(fddi_type),
		PYLIBNET_KEYPAIR(fddi_type1));

}

static PyObject *
pylibnet_parse_token_ring_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_token_ring_hdr);

	return Py_BuildValue("{s:B,s:B,s:S,s:S,s:B,s:B,s:B,s:S,s:H}",
		PYLIBNET_KEYPAIR(token_ring_access_control),
		PYLIBNET_KEYPAIR(token_ring_frame_control),
		PYLIBNET_KEYPAIR_HEX(token_ring_dhost, TOKEN_RING_ADDR_LEN),
		PYLIBNET_KEYPAIR_HEX(token_ring_shost, TOKEN_RING_ADDR_LEN),
		PYLIBNET_KEYPAIR(token_ring_llc_dsap),
		PYLIBNET_KEYPAIR(token_ring_llc_ssap),
		PYLIBNET_KEYPAIR(token_ring_llc_control_field),
		PYLIBNET_KEYPAIR_HEX(token_ring_llc_org_code, LIBNET_ORG_CODE_SIZE),
		PYLIBNET_KEYPAIR_HS(token_ring_type));
}

static PyObject *
pylibnet_parse_bgp4_header_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_bgp4_header_hdr);
	return Py_BuildValue("{s:s#,s:H,s:B}",
		PYLIBNET_KEYPAIR(marker), LIBNET_BGP4_MARKER_SIZE,
		PYLIBNET_KEYPAIR_HS(len),
		PYLIBNET_KEYPAIR(type));
}

static PyObject *
pylibnet_parse_bgp4_open_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_bgp4_open_hdr);
	return Py_BuildValue("{s:B,s:H,s:H,s:I,s:B}",
		PYLIBNET_KEYPAIR(version),
		PYLIBNET_KEYPAIR_HS(src_as),
		PYLIBNET_KEYPAIR_HS(hold_time),
		PYLIBNET_KEYPAIR_HL(bgp_id),
		PYLIBNET_KEYPAIR(opt_len));
}

static PyObject *
pylibnet_parse_bgp4_update_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{ PyErr_SetString(PyErr_LibnetError, "Packet parser not yet implemented."); return NULL; }

static PyObject *
pylibnet_parse_bgp4_notification_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_bgp4_notification_hdr);
	return Py_BuildValue("{s:B,s:B}",
		PYLIBNET_KEYPAIR(err_code),
		PYLIBNET_KEYPAIR(err_subcode));
}

static PyObject *
pylibnet_parse_gre_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_gre_hdr);
	return (hdr->flags_ver & GRE_VERSION_1)?Py_BuildValue("{s:H,s:H,s:H,s:H,s:I,s:I}",
		PYLIBNET_KEYPAIR_HS(flags_ver),
		PYLIBNET_KEYPAIR_HS(type),
		PYLIBNET_KEYPAIR_HS(egre_payload_s),
		PYLIBNET_KEYPAIR_HS(egre_callID),
		PYLIBNET_KEYPAIR_HL(egre_seq),
		PYLIBNET_KEYPAIR_HL(egre_ack))
		:Py_BuildValue("{s:H,s:H,s:H,s:H,s:I,s:I}", 
		PYLIBNET_KEYPAIR_HS(flags_ver),
		PYLIBNET_KEYPAIR_HS(type),
		PYLIBNET_KEYPAIR_HS(gre_sum),
		PYLIBNET_KEYPAIR_HS(gre_offset),
		PYLIBNET_KEYPAIR_HL(gre_key),
		PYLIBNET_KEYPAIR_HL(gre_seq));

}

static PyObject *
pylibnet_parse_gre_sre_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_gre_sre_hdr);
	return Py_BuildValue("{s:H,s:B,s:B,s:s#}",
		PYLIBNET_KEYPAIR_HS(af),
		PYLIBNET_KEYPAIR(sre_offset),
		PYLIBNET_KEYPAIR(sre_length),
		PYLIBNET_KEYPAIR(routing), b_len-3);
};

static PyObject *
pylibnet_parse_ipv6_routing_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_ipv6_routing_hdr);
	return Py_BuildValue("{s:B,s:B,s:B,s:B}",
		PYLIBNET_KEYPAIR(ip_nh),
		PYLIBNET_KEYPAIR(ip_len),
		PYLIBNET_KEYPAIR(ip_rtype),
		PYLIBNET_KEYPAIR(ip_segments));
}

static PyObject *
pylibnet_parse_ipv6_frag_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_ipv6_frag_hdr);
	return Py_BuildValue("{s:B,s:B,s:H,s:I}",
		PYLIBNET_KEYPAIR(ip_nh),
		PYLIBNET_KEYPAIR(ip_reserved),
		PYLIBNET_KEYPAIR_HS(ip_frag),
		PYLIBNET_KEYPAIR_HL(ip_id));
}

static PyObject *
pylibnet_parse_ipv6_destopts_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_ipv6_destopts_hdr);
	return Py_BuildValue("{s:B,s:B}",
		PYLIBNET_KEYPAIR(ip_nh),
		PYLIBNET_KEYPAIR(ip_len));
}

static PyObject *
pylibnet_parse_ipv6_hbhopts_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_ipv6_hbhopts_hdr);
	return Py_BuildValue("{s:B,s:B}",
		PYLIBNET_KEYPAIR(ip_nh),
		PYLIBNET_KEYPAIR(ip_len));
}

static PyObject *
pylibnet_parse_sebek_h(u_int8_t *buf, u_int32_t h_len, u_int32_t b_len)
{
	PYLIBNET_POINT_HDR(libnet_sebek_hdr);
	return Py_BuildValue("{s:I,s:H,s:H,s:I,s:I,s:I,s:I,s:I,s:I,s:s#,s:I}",
		PYLIBNET_KEYPAIR_HL(magic),
		PYLIBNET_KEYPAIR_HS(version),
		PYLIBNET_KEYPAIR_HS(type),
		PYLIBNET_KEYPAIR_HL(counter),
		PYLIBNET_KEYPAIR_HL(time_sec),
		PYLIBNET_KEYPAIR_HL(time_usec),
		PYLIBNET_KEYPAIR_HL(pid),
		PYLIBNET_KEYPAIR_HL(uid),
		PYLIBNET_KEYPAIR_HL(fd),
		PYLIBNET_KEYPAIR(cmd), SEBEK_CMD_LENGTH,
		PYLIBNET_KEYPAIR_HL(length));
}

typedef PyObject *(*PyLibnetParseFunction)(u_int8_t *, u_int32_t, u_int32_t);

static struct {
	u_int8_t type;
	PyLibnetParseFunction func;
} pylibnet_parsers[] = {
	{PYLIBNET_RESERVED, (PyLibnetParseFunction)pylibnet_parse_reserved},
	{LIBNET_PBLOCK_ARP_H, (PyLibnetParseFunction)pylibnet_parse_arp_h},
	{LIBNET_PBLOCK_DHCPV4_H, (PyLibnetParseFunction)pylibnet_parse_dhcpv4_h},
	{LIBNET_PBLOCK_DNSV4_H, (PyLibnetParseFunction)pylibnet_parse_dnsv4_h},
	{LIBNET_PBLOCK_ETH_H, (PyLibnetParseFunction)pylibnet_parse_eth_h},
	{LIBNET_PBLOCK_ICMPV4_H, (PyLibnetParseFunction)pylibnet_parse_icmpv4_h},
	{LIBNET_PBLOCK_ICMPV4_ECHO_H, (PyLibnetParseFunction)pylibnet_parse_icmpv4_echo_h},
	{LIBNET_PBLOCK_ICMPV4_MASK_H, (PyLibnetParseFunction)pylibnet_parse_icmpv4_mask_h},
	{LIBNET_PBLOCK_ICMPV4_UNREACH_H, (PyLibnetParseFunction)pylibnet_parse_icmpv4_unreach_h},
	{LIBNET_PBLOCK_ICMPV4_TIMXCEED_H, (PyLibnetParseFunction)pylibnet_parse_icmpv4_timxceed_h},
	{LIBNET_PBLOCK_ICMPV4_REDIRECT_H, (PyLibnetParseFunction)pylibnet_parse_icmpv4_redirect_h},
	{LIBNET_PBLOCK_ICMPV4_TS_H, (PyLibnetParseFunction)pylibnet_parse_icmpv4_ts_h},
	{LIBNET_PBLOCK_IGMP_H, (PyLibnetParseFunction)pylibnet_parse_igmp_h},
	{LIBNET_PBLOCK_IPV4_H, (PyLibnetParseFunction)pylibnet_parse_ipv4_h},
	{LIBNET_PBLOCK_IPO_H, (PyLibnetParseFunction)pylibnet_parse_ipo_h},
	{LIBNET_PBLOCK_IPDATA, (PyLibnetParseFunction)pylibnet_parse_ipdata},
	{LIBNET_PBLOCK_OSPF_H, (PyLibnetParseFunction)pylibnet_parse_ospf_h},
	{LIBNET_PBLOCK_OSPF_HELLO_H, (PyLibnetParseFunction)pylibnet_parse_ospf_hello_h},
	{LIBNET_PBLOCK_OSPF_DBD_H, (PyLibnetParseFunction)pylibnet_parse_ospf_dbd_h},
	{LIBNET_PBLOCK_OSPF_LSR_H, (PyLibnetParseFunction)pylibnet_parse_ospf_lsr_h},
	{LIBNET_PBLOCK_OSPF_LSU_H, (PyLibnetParseFunction)pylibnet_parse_ospf_lsu_h},
	{LIBNET_PBLOCK_OSPF_LSA_H, (PyLibnetParseFunction)pylibnet_parse_ospf_lsa_h},
	{LIBNET_PBLOCK_OSPF_AUTH_H, (PyLibnetParseFunction)pylibnet_parse_ospf_auth_h},
	{LIBNET_PBLOCK_OSPF_CKSUM, (PyLibnetParseFunction)pylibnet_parse_ospf_cksum},
	{LIBNET_PBLOCK_LS_RTR_H, (PyLibnetParseFunction)pylibnet_parse_ls_rtr_h},
	{LIBNET_PBLOCK_LS_NET_H, (PyLibnetParseFunction)pylibnet_parse_ls_net_h},
	{LIBNET_PBLOCK_LS_SUM_H, (PyLibnetParseFunction)pylibnet_parse_ls_sum_h},
	{LIBNET_PBLOCK_LS_AS_EXT_H, (PyLibnetParseFunction)pylibnet_parse_ls_as_ext_h},
	{LIBNET_PBLOCK_NTP_H, (PyLibnetParseFunction)pylibnet_parse_ntp_h},
	{LIBNET_PBLOCK_RIP_H, (PyLibnetParseFunction)pylibnet_parse_rip_h},
	{LIBNET_PBLOCK_TCP_H, (PyLibnetParseFunction)pylibnet_parse_tcp_h},
	{LIBNET_PBLOCK_TCPO_H, (PyLibnetParseFunction)pylibnet_parse_tcpo_h},
	{LIBNET_PBLOCK_TCPDATA, (PyLibnetParseFunction)pylibnet_parse_tcpdata},
	{LIBNET_PBLOCK_UDP_H, (PyLibnetParseFunction)pylibnet_parse_udp_h},
	{LIBNET_PBLOCK_VRRP_H, (PyLibnetParseFunction)pylibnet_parse_vrrp_h},
	{LIBNET_PBLOCK_DATA_H, (PyLibnetParseFunction)pylibnet_parse_data_h},
	{LIBNET_PBLOCK_CDP_H, (PyLibnetParseFunction)pylibnet_parse_cdp_h},
	{LIBNET_PBLOCK_IPSEC_ESP_HDR_H, (PyLibnetParseFunction)pylibnet_parse_ipsec_esp_hdr_h},
	{LIBNET_PBLOCK_IPSEC_ESP_FTR_H, (PyLibnetParseFunction)pylibnet_parse_ipsec_esp_ftr_h},
	{LIBNET_PBLOCK_IPSEC_AH_H, (PyLibnetParseFunction)pylibnet_parse_ipsec_ah_h},
	{LIBNET_PBLOCK_802_1Q_H, (PyLibnetParseFunction)pylibnet_parse_802_1q_h},
	{LIBNET_PBLOCK_802_2_H, (PyLibnetParseFunction)pylibnet_parse_802_2_h},
	{LIBNET_PBLOCK_802_2SNAP_H, (PyLibnetParseFunction)pylibnet_parse_802_2snap_h},
	{LIBNET_PBLOCK_802_3_H, (PyLibnetParseFunction)pylibnet_parse_802_3_h},
	{LIBNET_PBLOCK_STP_CONF_H, (PyLibnetParseFunction)pylibnet_parse_stp_conf_h},
	{LIBNET_PBLOCK_STP_TCN_H, (PyLibnetParseFunction)pylibnet_parse_stp_tcn_h},
	{LIBNET_PBLOCK_ISL_H, (PyLibnetParseFunction)pylibnet_parse_isl_h},
	{LIBNET_PBLOCK_IPV6_H, (PyLibnetParseFunction)pylibnet_parse_ipv6_h},
	{LIBNET_PBLOCK_802_1X_H, (PyLibnetParseFunction)pylibnet_parse_802_1x_h},
	{LIBNET_PBLOCK_RPC_CALL_H, (PyLibnetParseFunction)pylibnet_parse_rpc_call_h},
	{LIBNET_PBLOCK_MPLS_H, (PyLibnetParseFunction)pylibnet_parse_mpls_h},
	{LIBNET_PBLOCK_FDDI_H, (PyLibnetParseFunction)pylibnet_parse_fddi_h},
	{LIBNET_PBLOCK_TOKEN_RING_H, (PyLibnetParseFunction)pylibnet_parse_token_ring_h},
	{LIBNET_PBLOCK_BGP4_HEADER_H, (PyLibnetParseFunction)pylibnet_parse_bgp4_header_h},
	{LIBNET_PBLOCK_BGP4_OPEN_H, (PyLibnetParseFunction)pylibnet_parse_bgp4_open_h},
	{LIBNET_PBLOCK_BGP4_UPDATE_H, (PyLibnetParseFunction)pylibnet_parse_bgp4_update_h},
	{LIBNET_PBLOCK_BGP4_NOTIFICATION_H, (PyLibnetParseFunction)pylibnet_parse_bgp4_notification_h},
	{LIBNET_PBLOCK_GRE_H, (PyLibnetParseFunction)pylibnet_parse_gre_h},
	{LIBNET_PBLOCK_GRE_SRE_H, (PyLibnetParseFunction)pylibnet_parse_gre_sre_h},
	{LIBNET_PBLOCK_IPV6_FRAG_H, (PyLibnetParseFunction)pylibnet_parse_ipv6_frag_h},
	{LIBNET_PBLOCK_IPV6_ROUTING_H, (PyLibnetParseFunction)pylibnet_parse_ipv6_routing_h},
	{LIBNET_PBLOCK_IPV6_DESTOPTS_H, (PyLibnetParseFunction)pylibnet_parse_ipv6_destopts_h},
	{LIBNET_PBLOCK_IPV6_HBHOPTS_H, (PyLibnetParseFunction)pylibnet_parse_ipv6_hbhopts_h},
	{LIBNET_PBLOCK_SEBEK_H, (PyLibnetParseFunction)pylibnet_parse_sebek_h},
	{0, NULL}
};

#define PYLIBNET_NUM_DESCRIPTORS LIBNET_PBLOCK_SEBEK_H

static PyObject *
pylibnet_getheader(context *self, libnet_ptag_t ptag)
{

	int i = 0;
	libnet_pblock_t *pblock = NULL;

	pblock = libnet_pblock_find(self->l, ptag);

	if (pblock == NULL) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(self->l));
		return NULL;
	}

	if (pylibnet_parsers[pblock->type].type > PYLIBNET_NUM_DESCRIPTORS) {
		PyErr_SetString(PyErr_LibnetError, "getheader(): invalid packet type specified.");
		return NULL;
	}

	if (pylibnet_parsers[pblock->type].type != pblock->type) {
		while(pylibnet_parsers[i].func != NULL) {
			if (pylibnet_parsers[i].type == pblock->type)
				return pylibnet_parsers[i].func(pblock->buf, pblock->h_len, pblock->b_len);
			i++;
		}

		PyErr_SetString(PyErr_LibnetError, "getheader(): invalid packet type specified.");
		return NULL;
	}

	return pylibnet_parsers[pblock->type].func(pblock->buf, pblock->h_len, pblock->b_len);

}
