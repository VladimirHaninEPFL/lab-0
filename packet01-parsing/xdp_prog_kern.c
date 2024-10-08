/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define MAX_VLAN_HEADERS 2

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* this is a vlan header */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline 
int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline 
int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	struct vlan_hdr *vlh = NULL;
	__u16 h_proto; // this is the return code

	if (eth + 1 > data_end)
		return -1;

	nh->pos += sizeof(*eth);
	*ethhdr = eth;

	vlh = nh->pos;
	h_proto = eth->h_proto;

	#pragma unroll
	for (int i = 0; i < MAX_VLAN_HEADERS; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline
int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *ip = nh->pos;

	if (ip + 1 > data_end)
		return -1;

	int hdrsize = ip->ihl * 4;
	if(hdrsize < sizeof(*ip))
		return -1;

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = ip;

	return ip->protocol;
}

/* Assignment 2: Implement and use this */
static __always_inline 
int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip = nh->pos;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (ip + 1 > data_end)
		return -1;

	nh->pos += sizeof(*ip);
	*ip6hdr = ip;

	return ip->nexthdr; /* network-byte-order */
}

/* Assignment 3: Implement and use this */
static __always_inline
int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr* icmp = nh->pos;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (icmp + 1 > data_end)
		return -1;

	nh->pos += sizeof(*icmp);
	*icmp6hdr = icmp;

	return icmp->icmp6_type; /* network-byte-order */
}

static __always_inline
int parse_icmphdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;

	if (icmph + 1 > data_end)
		return -1;

	nh->pos  = icmph + 1;
	*icmphdr = icmph;

	return icmph->type;
}


SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {

		struct ipv6hdr *ip;
		struct icmp6hdr *icmp;

		nh_type = parse_ip6hdr(&nh, data_end, &ip);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		// this is an application layer header (of the ICMP protocol)
		nh_type = parse_icmp6hdr(&nh, data_end, &icmp);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		int sequence_number = bpf_ntohs(icmp->icmp6_sequence);
		if (sequence_number % 2 == 0) {
			action = XDP_DROP;
		} else {
			action = XDP_PASS;
		}

	}
	else if (nh_type == bpf_htons(ETH_P_IP)) {

		struct iphdr *ip;
		struct icmphdr *icmp;

		nh_type = parse_iphdr(&nh, data_end, &ip);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmp);
		if (nh_type != ICMP_ECHO)
			goto out;

		int sequence_number = bpf_ntohs(icmp->un.echo.sequence);
		if (sequence_number % 2 == 0) {
			action = XDP_DROP;
		} else {
			action = XDP_PASS;
		}

	} else {
		goto out;
	}

	/* Assignment additions go below here */



out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
