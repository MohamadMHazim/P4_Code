/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

const bit<32> FLOW_BUCKETS = 65536; // match CRC16 space

control Ingress(
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_hasher;

    /**********************  Registers (32-bit for SALU)  **********************/
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_flow_pkts;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_flow_bytes;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_https_flow_pkts;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_https_flow_bytes;

    /*********************  RegisterActions (no branches)  *********************/
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_flow_pkts) flow_pkts_add = {
        void apply(inout bit<32> register_data) {
            register_data = register_data + 32w1;
        }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_flow_bytes) flow_bytes_add = {
        void apply(inout bit<32> register_data) {
            register_data = register_data + (bit<32>) meta.pkt_len;
        }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_https_flow_pkts) https_flow_pkts_add = {
        void apply(inout bit<32> register_data) {
            register_data = register_data + 32w1;
        }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_https_flow_bytes) https_flow_bytes_add = {
        void apply(inout bit<32> register_data) {
            register_data = register_data + (bit<32>) meta.pkt_len;
        }
    };

    /**************************  Basic forwarding actions  *********************/
    action send_using_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress     = 0;
    }
    action drop() {
        ig_tm_md.ucast_egress_port = 0;
        ig_dprsr_md.drop_ctl       = 3w1;
        ig_tm_md.bypass_egress     = 1w1;
    }

    /*******************  Actions (no conditionals inside)  ********************/
    action mark_non_tcp() {
        meta.is_tcp   = 0;
        meta.is_https = 0;
        // pkt_len is computed by compute_pkt_len table
    }

    // Computes hash and base counters; no pkt_len branching here.
    action mark_tcp_and_hash() {
        meta.is_tcp   = 1;
        meta.is_https = 0;  // may be set to 1 by classify_https table

        bit<16> hval = crc16_hasher.get({
            hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
            hdr.tcp.sport,     hdr.tcp.dport,
            hdr.ipv4.protocol
        });
        meta.flow_idx = hval;

        // Base per-flow stats (always)
        flow_pkts_add.execute(meta.flow_idx);
        flow_bytes_add.execute(meta.flow_idx);
    }

    // HTTPS counters live in their own action (no conditionals)
    action set_https_and_count() {
        meta.is_https = 1;
        https_flow_pkts_add.execute(meta.flow_idx);
        https_flow_bytes_add.execute(meta.flow_idx);
    }
    action clear_https_flag() {
        meta.is_https = 0;
    }

    /******************  Tables (move conditions out of actions)  **************/

    // Compute packet length based on IPv4 validity (no if inside actions)
    action set_pkt_len_ipv4() { meta.pkt_len = (bit<16>)(hdr.ipv4.total_len + 16w14); }
    action set_pkt_len_zero() { meta.pkt_len = 16w0; }

    table compute_pkt_len {
        key = { hdr.ipv4.isValid() : exact; }
        actions = { set_pkt_len_ipv4; set_pkt_len_zero; }
        const default_action = set_pkt_len_zero();
        size = 2;
    }

    // Classify TCP vs non-TCP, and trigger base counters
    table tcp_classify {
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.ipv4.protocol  : exact;
            hdr.tcp.isValid()  : exact;
        }
        actions = { mark_tcp_and_hash; mark_non_tcp; }
        const default_action = mark_non_tcp();
        size = 4;
    }

    // Decide HTTPS via ports (443 on either side) and update HTTPS counters
    table classify_https {
        key = {
            hdr.tcp.isValid() : exact;
            hdr.tcp.sport     : ternary;
            hdr.tcp.dport     : ternary;
        }
        actions = { set_https_and_count; clear_https_flag; }
        const default_action = clear_https_flag();
        size = 3;

        const entries = {
            (true, 16w443 &&& 16w0xFFFF, 16w0   &&& 16w0)       : set_https_and_count();
            (true, 16w0   &&& 16w0,      16w443 &&& 16w0xFFFF)  : set_https_and_count();
        }
    }

    // Port-based forwarding (unchanged)
    table forwarding {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { send_using_port; drop; }
        size = 256;
    }

    /*********************************  Apply  *********************************/
    apply {
        compute_pkt_len.apply();
        tcp_classify.apply();
        classify_https.apply();
        forwarding.apply();
    }
}
