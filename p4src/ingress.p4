/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
typedef bit<16> flow_idx_t;
const bit<32> FLOW_BUCKETS = 65536;  // match CRC16 space

// Register<data_t, index_t>(num_boxes) instance;
Register<bit<64>, bit<16>>(FLOW_BUCKETS) reg_flow_pkts;        // TCP: packets per bucket
Register<bit<64>, bit<16>>(FLOW_BUCKETS) reg_flow_bytes;       // TCP: bytes per bucket

Register<bit<64>, bit<16>>(FLOW_BUCKETS) reg_https_flow_pkts;  // HTTPS subset
Register<bit<64>, bit<16>>(FLOW_BUCKETS) reg_https_flow_bytes; // HTTPS subset
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_hasher;
    RegisterAction<bit<64>, bit<16>, bit<64>>(reg_flow_pkts)
    reg_flow_pkts_increment = {
        void apply(inout bit<64> register_data, out bit<64> result) {
            result = register_data;
            register_data = register_data + 1;
        }
    };

    // RegisterAction for incrementing flow byte count
    RegisterAction<bit<64>, bit<16>, bit<64>>(reg_flow_bytes)
    reg_flow_bytes_increment = {
        void apply(inout bit<64> register_data, out bit<64> result) {
            result = register_data;
            register_data = register_data + (bit<64>)meta.pkt_len;
        }
    };
    RegisterAction<bit<64>, bit<16>, bit<64>>(reg_https_flow_pkts)
    reg_https_flow_pkts_increment = {
        void apply(inout bit<64> register_data, out bit<64> result) {
            result = register_data;
            register_data = register_data + 1;
        }
    };
    RegisterAction<bit<64>, bit<16>, bit<64>>(reg_https_flow_bytes)
    reg_https_flow_bytes_increment = {
        void apply(inout bit<64> register_data, out bit<64> result) {
            result = register_data;
            register_data = register_data + (bit<64>)meta.pkt_len;
        }
    };
    action send_using_port(PortId_t port){
	    ig_tm_md.ucast_egress_port = port;   
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table forwarding {
        key = { 
		    ig_intr_md.ingress_port : exact; 
        }
        actions = {
            send_using_port; 
            drop;
        }
    }

    apply {
	    forwarding.apply();
    }
}
