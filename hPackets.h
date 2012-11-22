#ifndef HPACKETS_H
#define HPACKETS_H

#include <windows.h>

#define	ETHER_ADDR_LEN		6
#define	ETHER_TYPE_LEN		2
#define	ETHER_CRC_LEN		4
#define	ETHER_HDR_LEN		(ETHER_ADDR_LEN*2+ETHER_TYPE_LEN)
#define	ETHER_MIN_LEN		64
#define	ETHER_MAX_LEN		1518
#define	ETHER_IS_VALID_LEN(foo)	\
	((foo) >= ETHER_MIN_LEN && (foo) <= ETHER_MAX_LEN)

struct	ETHER_HEADER {
	u_char	ether_dhost[ETHER_ADDR_LEN];
	u_char	ether_shost[ETHER_ADDR_LEN];
	u_short	ether_type;
};

struct	ETHER_ADDR {
	u_char octet[ETHER_ADDR_LEN];
};

#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define	ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define	ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#define	ETHERTYPE_VLAN		0x8100	/* IEEE 802.1Q VLAN tagging */
#define	ETHERTYPE_IPV6		0x86dd	/* IPv6 */
#define	ETHERTYPE_LOOPBACK	0x9000	/* used to test interfaces */
#define	ETHERTYPE_TRAIL		0x1000		/* Trailer packet */
#define	ETHERTYPE_NTRAILER	16

#define	ETHERMTU	(ETHER_MAX_LEN-ETHER_HDR_LEN-ETHER_CRC_LEN)
#define	ETHERMIN	(ETHER_MIN_LEN-ETHER_HDR_LEN-ETHER_CRC_LEN)

struct IP_HEADER
{
	unsigned char  ip_header_len:4;  // 4-bit header length (in 32-bit words)
	unsigned char  ip_version   :4;  // 4-bit IPv4 version
	unsigned char  ip_tos;           // IP type of service
	unsigned short ip_total_length;  // Total length
	unsigned short ip_id;            // Unique identifier
	unsigned char  ip_frag_offset   :5; // Fragment offset field
	unsigned char  ip_more_fragment :1;
	unsigned char  ip_dont_fragment :1;
	unsigned char  ip_reserved_zero :1;
	unsigned char  ip_frag_offset1;    //fragment offset
	unsigned char  ip_ttl;           // Time to live
	unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
	unsigned short ip_checksum;      // IP checksum
	unsigned int   ip_srcaddr;       // Source address
	unsigned int   ip_destaddr;      // Source address
};

#define TCP_PACKET	6
#define UDP_PACKET	17

struct TCP_HEADER
{
	unsigned short source_port;  // source port
	unsigned short dest_port;    // destination port
	unsigned int   sequence;     // sequence number - 32 bits
	unsigned int   acknowledge;  // acknowledgement number - 32 bits
	unsigned char  ns   :1;          //Nonce Sum Flag Added in RFC 3540.
	unsigned char  reserved_part1:3; //according to rfc
	unsigned char  data_offset:4;    //number of dwords in the TCP header.
	unsigned char  fin  :1;      //Finish Flag
	unsigned char  syn  :1;      //Synchronise Flag
	unsigned char  rst  :1;      //Reset Flag
	unsigned char  psh  :1;      //Push Flag
	unsigned char  ack  :1;      //Acknowledgement Flag
	unsigned char  urg  :1;      //Urgent Flag
	unsigned char  ecn  :1;      //ECN-Echo Flag
	unsigned char  cwr  :1;      //Congestion Window Reduced Flag
	unsigned short window;          // window
	unsigned short checksum;        // checksum
	unsigned short urgent_pointer;  // urgent pointer
};

struct	ARP_HEADER
{
	u_short	ar_hrd;		/* format of hardware address */

#define ARPHRD_ETHER 	1	/* ethernet hardware format */
#define ARPHRD_IEEE802	6	/* token-ring hardware format */
#define ARPHRD_FRELAY 	15	/* frame relay hardware format */

	u_short	ar_pro;		/* format of protocol address */
	u_char	ar_hln;		/* length of hardware address */
	u_char	ar_pln;		/* length of protocol address */
	u_short	ar_op;		/* one of: */

#define	ARPOP_REQUEST	1	/* request to resolve address */
#define	ARPOP_REPLY	2	/* response to previous request */
#define	ARPOP_REVREQUEST 3	/* request protocol address given hardware */
#define	ARPOP_REVREPLY	4	/* response giving protocol address */
#define ARPOP_INVREQUEST 8 	/* request to identify peer */
#define ARPOP_INVREPLY	9	/* response identifying peer */

#ifdef COMMENT_ONLY
	u_char	ar_sha[];	/* sender hardware address */
	u_char	ar_spa[];	/* sender protocol address */
	u_char	ar_tha[];	/* target hardware address */
	u_char	ar_tpa[];	/* target protocol address */
#endif
};

struct UDP_HEADER
{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
};

#endif
