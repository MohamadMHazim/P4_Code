/***********************  P A R S E R  **************************/

parser IngressParser(
    packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.sel_protocol = hdr.ipv4.protocol;
        meta.pkt_len = hdr.ipv4.total_len;
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }
    
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        meta.sel_protocol = hdr.ipv6.next_header;
        meta.pkt_len = hdr.ipv6.payload_len;
        transition select(hdr.ipv6.next_header) {
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.sel_src_port = hdr.tcp.sport;
        meta.sel_dst_port = hdr.tcp.dport;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.sel_src_port = hdr.udp.sport;
        meta.sel_dst_port = hdr.udp.dport;
        transition accept;
    }
}
