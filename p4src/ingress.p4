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
    Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_hasher2;

    /**********************  Advisor bucket registers  ************************/
    Register<bit<32>, bit<16>>(BUCKETS) src_bucket_pkts;
    Register<bit<32>, bit<16>>(BUCKETS) src_bucket_bytes;
    Register<bit<32>, bit<16>>(BUCKETS) dst_bucket_pkts;
    Register<bit<32>, bit<16>>(BUCKETS) dst_bucket_bytes;

    RegisterAction<bit<32>, bit<16>, bit<32>>(src_bucket_pkts) src_pkts_add = {
        void apply(inout bit<32> register_data) { 
            register_data = register_data + 32w1; 
        }
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(src_bucket_bytes) src_bytes_add = {
        void apply(inout bit<32> register_data) { 
            register_data = register_data + (bit<32>) meta.pkt_len; 
        }
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(dst_bucket_pkts) dst_pkts_add = {
        void apply(inout bit<32> register_data) { 
            register_data = register_data + 32w1; 
        }
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(dst_bucket_bytes) dst_bytes_add = {
        void apply(inout bit<32> register_data) { 
            register_data = register_data + (bit<32>) meta.pkt_len; 
        }
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

    /**************************  Forwarding table  *****************************/
    table forwarding {
        key = { 
            ig_intr_md.ingress_port : exact; 
        }
        actions = { 
            send_using_port; 
            drop; 
        }
        size = 256;
    }

    bit<16> bucket_src_idx;
    bit<16> bucket_dst_idx;

    /*********************************  Apply  *********************************/
    apply {

        // Compute bucket index and update registers
        meta.pkt_len = meta.pkt_len + 16w14;

        if (hdr.ipv4.isValid() || hdr.ipv6.isValid()) {

            bucket_src_idx = crc16_hasher.get({
                hdr.ethernet.ether_type,
                meta.sel_protocol,
                meta.sel_src_port
            });

            bucket_dst_idx = crc16_hasher2.get({
                hdr.ethernet.ether_type,
                meta.sel_protocol,
                meta.sel_dst_port
            });

            src_pkts_add.execute(bucket_src_idx);
            src_bytes_add.execute(bucket_src_idx);

            dst_pkts_add.execute(bucket_dst_idx);
            dst_bytes_add.execute(bucket_dst_idx);
        }

        forwarding.apply();
    }
}
