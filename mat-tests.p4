/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>
#include "header.p4"
#include "util.p4"

struct metadata_t {
    bit<3> usds;
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

    action a_set_port(bit<48> mac_address, PortId_t egress_port) {
        ig_intr_tm_md.ucast_egress_port = egress_port;
        hdr.ethernet.srcAddr = mac_address;
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
        size = 65536;
    }

    action a_table2(bit<48> mac_address) {
        hdr.ethernet.dstAddr = mac_address;
    }

    @name(".table_2")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table2 {
        key = {
            hdr.ethernet.srcAddr : exact;
        }
        actions = {
            a_table2;
        }
        size = 65536;
    }

    action a_table3(bit<16> etherType) {
        hdr.ethernet.etherType = etherType;
    }

    @name(".table_3")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table3 {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            a_table_3;
        }
        size = 65536;
    }

    action a_table4(bit<8> protocol) {
        hdr.ethernet.etherType = etherType;
    }

    @name(".table_4")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table4 {
        key = {
            hdr.ethernet.etherType : exact;
        }
        actions = {
            a_table4;
        }
        size = 65536;
    }

    action a_table5(bit<32> srcAddr) {
        hdr.ipv4.srcAddr = srcAddr;
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
            table_5;
        }
        size = 65536;
    }

    action a_table6(bit<32> dstAddr) {
        hdr.ipv4.dstAddr = dstAddr;
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
            table_6;
        }
        size = 65536;
    }

    action a_table7(bit<16> srcPort) {
        hdr.udp.srcPort = srcPort;
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
            table_7;
        }
        size = 65536;
    }

    action a_table8(bit<16> dstport) {
        hdr.udp.dstport = dstport;
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
            table_8;
        }
        size = 65536;
    }

    action a_table9(bit<32> teid) {
        hdr.gtp.teid = teid;
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
            table_9;
        }
        size = 65536;
    }

    action a_table10(bit<16> srcAddr) {
        hdr.ipv4_inner.srcAddr = srcAddr;
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
        size = 65536;
    }

    @name(".table_11")
#ifdef TCAM
    @pragma ternary 1
#endif
    table t_table11 {
        key = {
            hdr.ipv4_inner.srcAddr : exact;
        }
        actions = {}
        size = 65536;
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
