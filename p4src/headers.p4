/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8>  IP_PROTO_TCP   = 6;
const bit<8>  IP_PROTO_UDP   = 17;
const bit<16> TCP_PORT_HTTPS = 443;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4> dataofs;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> chksum;
    bit<16> urgptr; 
}

header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum; 
}

/***********************  I N G R E S S  H E A D E R S  ************************/
struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    tcp_h        tcp;
    udp_h        udp;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {
    bit<1>  is_tcp;    // set in ingress if packet is TCP
    bit<1>  is_https;  // subset of TCP: port 443
    bit<16> flow_idx;  // CRC16 bucket index
    bit<16> pkt_len;   // copy of packet length (ingress)
}



/***********************  E G R E S S  H E A D E R S  ***************************/
/* We don't re-parse user headers in egress, so this can stay empty. */
struct my_egress_headers_t {

}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    bit<1>  is_tcp;
    bit<1>  is_https;
    bit<16> flow_idx;
    bit<16> pkt_len;
}
