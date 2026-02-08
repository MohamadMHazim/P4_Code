/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

const bit<32> BUCKETS = 65536; // CRC16 space

control Ingress(
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_hasher;

    /**********************  Advisor bucket registers  ************************/
    Register<bit<32>, bit<16>>(BUCKETS) reg_bucket_pkts;
    Register<bit<32>, bit<16>>(BUCKETS) reg_bucket_bytes;

    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_bucket_pkts) bucket_pkts_add = {
        void apply(inout bit<32> register_data) { register_data = register_data + 32w1; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_bucket_bytes) bucket_bytes_add = {
        void apply(inout bit<32> register_data) { register_data = register_data + (bit<32>) meta.pkt_len; }
    };

    /**************************  Forwarding actions  **************************/
    action send_using_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress     = 0;
    }
    action drop() {
        ig_tm_md.ucast_egress_port = 0;
        ig_dprsr_md.drop_ctl       = 3w1;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action nop() { }

    /**********************  Packet length (for bytes)  ************************/
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

    /**********************  Direction (OUT/IN)  ********************************
     * Define outgoing/incoming using ingress_port.
     * EDIT the entries to match your topology.
     ***************************************************************************/
    action set_outgoing() { meta.is_outgoing = 1w1; }
    action set_incoming() { meta.is_outgoing = 1w0; }

    table set_direction {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_outgoing; set_incoming; }
        const default_action = set_incoming();
        size = 256;
        const entries = {
            (0) : set_outgoing();
        }
    }

    /**********************  Select port (sport vs dport)  *********************/
    action sel_port_zero()    { meta.sel_port = 16w0; }

    action sel_tcp_out()      { meta.sel_port = hdr.tcp.sport; }
    action sel_tcp_in()       { meta.sel_port = hdr.tcp.dport; }

    action sel_udp_out()      { meta.sel_port = hdr.udp.sport; }
    action sel_udp_in()       { meta.sel_port = hdr.udp.dport; }

    // First reset sel_port to 0 for each packet
    table init_sel_port {
        key = { hdr.ipv4.isValid() : exact; }
        actions = { sel_port_zero; nop; }
        const default_action = nop();
        size = 2;
        const entries = { (true) : sel_port_zero(); }
    }

    table select_tcp_port {
        key = {
            hdr.tcp.isValid()  : exact;
            meta.is_outgoing   : exact;
        }
        actions = { sel_tcp_out; sel_tcp_in; nop; }
        const default_action = nop();
        size = 4;

        const entries = {
            (true,  1w1) : sel_tcp_out();
            (true,  1w0) : sel_tcp_in();
        }
    }

    table select_udp_port {
        key = {
            hdr.udp.isValid()  : exact;
            meta.is_outgoing   : exact;
        }
        actions = { sel_udp_out; sel_udp_in; nop; }
        const default_action = nop();
        size = 4;

        const entries = {
            (true,  1w1) : sel_udp_out();
            (true,  1w0) : sel_udp_in();
        }
    }

    /**********************  Compute bucket hash index  ************************/
    action compute_bucket_idx() {
        // CRC16( EtherType || IPv4.protocol || selected_port )
        meta.bucket_idx = crc16_hasher.get({
            hdr.ethernet.ether_type,
            hdr.ipv4.protocol,
            meta.sel_port
        });
    }

    /**********************  Update bucket registers  **************************/
    action do_bucket_pkts()  { bucket_pkts_add.execute(meta.bucket_idx); }
    action do_bucket_bytes() { bucket_bytes_add.execute(meta.bucket_idx); }

    table bucket_pkts_update {
        key = { hdr.ipv4.isValid() : exact; }
        actions = { do_bucket_pkts; nop; }
        const default_action = nop();
        size = 2;
        const entries = { (true) : do_bucket_pkts(); }
    }

    table bucket_bytes_update {
        key = { hdr.ipv4.isValid() : exact; }
        actions = { do_bucket_bytes; nop; }
        const default_action = nop();
        size = 2;
        const entries = { (true) : do_bucket_bytes(); }
    }

    /**************************  Forwarding table  *****************************/
    table forwarding {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { send_using_port; drop; }
        size = 256;
    }

    /*********************************  Apply  *********************************/
    apply {
        compute_pkt_len.apply();

        // Direction based on ingress port (EDIT const entries as needed)
        set_direction.apply();

        // Decide which port participates in the hash (tcp/udp only)
        init_sel_port.apply();
        select_tcp_port.apply();
        select_udp_port.apply();

        // Compute bucket index and update registers (IPv4 only)
        if (hdr.ipv4.isValid()) {
            compute_bucket_idx();
        }
        bucket_pkts_update.apply();
        bucket_bytes_update.apply();

        forwarding.apply();
    }
}
