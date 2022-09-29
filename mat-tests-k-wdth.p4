/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>
#include "header.p4"
#include "util.p4"

#ifdef WDTH_32
struct wd_32 {
    bit<32> trash1;
}
#endif

#ifdef WDTH_64
struct wd_64 {
    bit<32> trash1;
    bit<32> trash2;
}
#endif

struct metadata_t {
    bit<1> usds;
#ifdef WDTH_32
    wd_32 trash1;
#endif
#ifdef WDTH_64
    wd_64 trash1;
#endif
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    gtp_v1_t   gtp;
    ipv4_t     ipv4_inner;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(packet_in pkt, out headers_t hdr, out metadata_t meta, out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETH_IP: parse_ipv4;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_UDP: pre_parse_udp;
        }
    }

    // first check if it's really needed to parse UDP
    // prevents parsing of UDP header if packet is *not* encapsulated in GTP
    // To encpasulate hdr.udp.setValid() would overwrite inner UDP header
    state pre_parse_udp {
        transition select((pkt.lookahead<udp_t>()).dstPort) { // lookahead srcPort
            UDP_GTP_V1: parse_udp; // srcPort and dstPort are same for GTP
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            UDP_GTP_V1: parse_gtp;  // port 2152
            default: accept;
        }
    }

    state parse_gtp {
        pkt.extract(hdr.gtp);
	transition parse_ipv4_inner;
    }

    state parse_ipv4_inner {
        pkt.extract(hdr.ipv4_inner);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(packet_out pkt, inout headers_t hdr, in metadata_t meta, in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Switch Ingress MAU
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_parser_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    action a_us_ds() {
        meta.usds = 1;
    }

    action a_set_port(bit<48> srcAddr) {
        hdr.ethernet.srcAddr = srcAddr;
        a_us_ds();
    }

    @name(".table_1")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table1 {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            a_set_port;
        }
        size = 1;
    }

    action a_table2(bit<48> dstAddr) {
	    hdr.ethernet.dstAddr = dstAddr;
        a_us_ds();
    }

    @name(".table_2")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table2 {
        key = {
            hdr.ethernet.srcAddr : exact;
            meta.trash1: exact;
        }
        actions = {
            a_table2;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }

    action a_table3(bit<16> etherType) {
        hdr.ethernet.etherType = etherType;
        a_us_ds();
    }

    @name(".table_3")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table3 {
        key = {
            hdr.ethernet.dstAddr : exact;
            meta.trash1: exact;
        }
        actions = {
            a_table3;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }

    action a_table4(bit<8> protocol) {
        hdr.ipv4.protocol = protocol;
        a_us_ds();
    }

    @name(".table_4")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table4 {
        key = {
            hdr.ethernet.etherType : exact;
#ifdef WDTH_32
    wd_32 meta.trash1;
#endif
#ifdef WDTH_64
    wd_64 meta.trash1;
#endif
        }
        actions = {
            a_table4;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }

    action a_table5(bit<32> srcAddr) {
        hdr.ipv4.srcAddr = srcAddr;
        a_us_ds();
    }

    @name(".table_5")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table5 {
        key = {
            hdr.ipv4.protocol : exact;
        }
        actions = {
            a_table5;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }

    action a_table6(bit<32> dstAddr) {
        hdr.ipv4.dstAddr = dstAddr;
        a_us_ds();
    }

    @name(".table_6")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table6 {
        key = {
            hdr.ipv4.srcAddr : exact;
        }
        actions = {
            a_table6;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }

    action a_table7(bit<16> srcPort) {
        hdr.udp.srcPort = srcPort;
        a_us_ds();
    }

    @name(".table_7")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table7 {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            a_table7;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }

    action a_table8(bit<16> dstPort) {
        hdr.udp.dstPort = dstPort;
        a_us_ds();
    }

    @name(".table_8")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table8 {
        key = {
            hdr.udp.srcPort : exact;
        }
        actions = {
            a_table8;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }

    action a_table9(bit<32> teid) {
        hdr.gtp.teid = teid;
        a_us_ds();
    }

    @name(".table_9")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table9 {
        key = {
            hdr.udp.dstPort : exact;
        }
        actions = {
            a_table9;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }

    action a_table10(bit<32> srcAddr) {
        hdr.ipv4_inner.srcAddr = srcAddr;
        a_us_ds();
    }

    @name(".table_10")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table10 {
        key = {
            hdr.gtp.teid : exact;
        }
        actions = {
            a_table10;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }

    action set_egress_port(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }
    @name(".table_11")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table11 {
        key = {
            hdr.ipv4_inner.srcAddr : exact;
        }
        actions = {
            set_egress_port;
        }
#ifdef TBL_SIZE_1
        size = 1;
#endif
#ifdef TBL_SIZE_64
        size = 64;
#endif
#ifdef TBL_SIZE_128
        size = 128;
#endif
#ifdef TBL_SIZE_512
        size = 512;
#endif
#ifdef TBL_SIZE_1024
        size = 1024;
#endif
#ifdef TBL_SIZE_2048
        size = 2048;
#endif
#ifdef TBL_SIZE_4096
        size = 4096;
#endif
    }


    apply {
        t_table1.apply();
        t_table2.apply();
        t_table3.apply();
        t_table4.apply();
        t_table5.apply();
        t_table6.apply();
        t_table7.apply();
        t_table8.apply();
        t_table9.apply();
        t_table10.apply();
        t_table11.apply();
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(packet_in pkt, out headers_t hdr, out metadata_t meta, out egress_intrinsic_metadata_t eg_intr_md) {
    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout headers_t hdr,
        inout metadata_t meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_parser_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    apply {
    }
}

// ---------------------------------------------------------------------------
// Switch Egress MAU
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(packet_out pkt, inout headers_t hdr, in metadata_t meta, in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}

Pipeline(SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()) pipe;

Switch(pipe) main;
