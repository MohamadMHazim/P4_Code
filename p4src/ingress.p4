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

    /***************************  Utility actions  ****************************/
    action nop() { }

    /*******************  Actions (no conditionals inside)  ********************/
    action mark_non_tcp() {
        meta.is_tcp   = 0;
        meta.is_https = 0;
        meta.flow_idx = 0;
        // pkt_len is computed by compute_pkt_len table
    }

    // Computes hash + sets flags ONLY (no register ops here)
    action mark_tcp_and_hash() {
        meta.is_tcp   = 1;
        meta.is_https = 0;  // may be set later by classify_https

        bit<16> hval = crc16_hasher.get({
            hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
            hdr.tcp.sport,     hdr.tcp.dport,
            hdr.ipv4.protocol
        });
        meta.flow_idx = hval;
    }

    /*****************  Counter update actions (ONE register each)  ************/
    action do_flow_pkts()  { flow_pkts_add.execute(meta.flow_idx); }
    action do_flow_bytes() { flow_bytes_add.execute(meta.flow_idx); }

    action do_https_pkts()  { https_flow_pkts_add.execute(meta.flow_idx); }
    action do_https_bytes() { https_flow_bytes_add.execute(meta.flow_idx); }

    /******************  Tables (move conditions out of actions)  **************/

    // Compute packet length based on IPv4 validity (no if inside actions)
action set_pkt_len_ipv4() { meta.pkt_len = (bit<16>)(hdr.ipv4.total_len + 16w14); }
action set_pkt_len_zero() { meta.pkt_len = 16w0; }

table compute_pkt_len {
    key = { hdr.ipv4.isValid() : exact; }
    actions = { set_pkt_len_ipv4; set_pkt_len_zero; }
    const default_action = set_pkt_len_zero();
    size = 2;

    const entries = {
        (true)  : set_pkt_len_ipv4();
        (false) : set_pkt_len_zero();
    }
}

// Classify TCP vs non-TCP and compute hash/flags
table tcp_classify {
    key = {
        hdr.ipv4.isValid() : exact;
        hdr.ipv4.protocol  : exact;
        hdr.tcp.isValid()  : exact;
    }
    actions = { mark_tcp_and_hash; mark_non_tcp; }
    const default_action = mark_non_tcp();
    size = 4;

    const entries = {
        // IPv4 + TCP + tcp header valid => compute hash + set meta.is_tcp=1
        (true,  8w6,  true)  : mark_tcp_and_hash();

        // Anything else => non-tcp
        (true,  8w6,  false) : mark_non_tcp();
        (true,  8w0,  true)  : mark_non_tcp();
        (false, 8w0,  false) : mark_non_tcp();
    }
}


    // Update base per-flow TCP counters (each table touches ONE register)
    table flow_pkts_update {
        key = { meta.is_tcp : exact; }
        actions = { do_flow_pkts; nop; }
        const default_action = nop();
        size = 2;

        const entries = {
            (1w1) : do_flow_pkts();
        }
    }

    table flow_bytes_update {
        key = { meta.is_tcp : exact; }
        actions = { do_flow_bytes; nop; }
        const default_action = nop();
        size = 2;

        const entries = {
            (1w1) : do_flow_bytes();
        }
    }

    // Decide HTTPS via ports (443 on either side) - ONLY sets flag here
    action set_https_flag()   { meta.is_https = 1; }
    action clear_https_flag() { meta.is_https = 0; }

    table classify_https {
        key = {
            hdr.tcp.isValid() : exact;
            hdr.tcp.sport     : ternary;
            hdr.tcp.dport     : ternary;
        }
        actions = { set_https_flag; clear_https_flag; }
        const default_action = clear_https_flag();
        size = 3;

        const entries = {
            (true, 16w443 &&& 16w0xFFFF, 16w0   &&& 16w0)       : set_https_flag();
            (true, 16w0   &&& 16w0,      16w443 &&& 16w0xFFFF)  : set_https_flag();
        }
    }

    // Update HTTPS counters (each table touches ONE register)
    table https_pkts_update {
        key = { meta.is_https : exact; }
        actions = { do_https_pkts; nop; }
        const default_action = nop();
        size = 2;

        const entries = {
            (1w1) : do_https_pkts();
        }
    }

    table https_bytes_update {
        key = { meta.is_https : exact; }
        actions = { do_https_bytes; nop; }
        const default_action = nop();
        size = 2;

        const entries = {
            (1w1) : do_https_bytes();
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

        // base TCP counters (1 register per table)
        flow_pkts_update.apply();
        flow_bytes_update.apply();

        classify_https.apply();

        // HTTPS counters (1 register per table)
        https_pkts_update.apply();
        https_bytes_update.apply();

        forwarding.apply();
    }
}
