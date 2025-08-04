/*
 * FLARE Stateful Flag and Fragment Processing (P4-SFFP)
 * Target: BMv2 simple_switch (P4_16)
 * Description: Implements TCP flag and IP fragmentation tracking, stateful feature extraction,
 * and anomaly alerts via metadata.
 */

#include <core.p4>
#include <v1model.p4>

// -------------- Header Definitions --------------

header ethernet_t {
    mac_addr dstAddr;
    mac_addr srcAddr;
    bit<16>  etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// -------------- Metadata --------------

struct metadata_t {
    bit<1> alert_rst;
    bit<1> alert_fin;
    bit<1> alert_frag;
}

// -------------- Standard Metadata --------------

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

// -------------- Parser --------------

parser MyParser(packet_in packet,
                out headers hdr,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp; // TCP
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

// -------------- Checksums --------------

control MyVerifyChecksum(inout headers hdr, inout metadata_t meta) {
    apply { /* Not used here */ }
}

control MyComputeChecksum(inout headers hdr, inout metadata_t meta) {
    apply { /* Not used here */ }
}

// -------------- Ingress Processing --------------

control MyIngress(inout headers hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    // Stateful registers to store flag counters (per dest IP)
    // Note: For simplicity, keys are dstAddr, but production may use full 5-tuple.
    // This simple BMv2 sample only illustrates flag and fragment tracking.

    // Register declarations
    register<bit<32>>(1024) rst_count;
    register<bit<32>>(1024) fin_count;
    register<bit<32>>(1024) frag_count;

    action count_rst(bit<32> index) {
        bit<32> value;
        rst_count.read(value, index);
        rst_count.write(index, value + 1);
    }

    action count_fin(bit<32> index) {
        bit<32> value;
        fin_count.read(value, index);
        fin_count.write(index, value + 1);
    }

    action count_frag(bit<32> index) {
        bit<32> value;
        frag_count.read(value, index);
        frag_count.write(index, value + 1);
    }

    action set_rst_alert() {
        meta.alert_rst = 1;
    }

    action set_fin_alert() {
        meta.alert_fin = 1;
    }

    action set_frag_alert() {
        meta.alert_frag = 1;
    }

    table check_tcp_flags {
        key = {
            hdr.tcp.flags: ternary;
        }
        actions = {
            count_rst;
            count_fin;
            set_rst_alert;
            set_fin_alert;
            NoAction;
        }
        size = 2;
        default_action = NoAction();
    }

    table check_fragment {
        key = {
            hdr.ipv4.flags: ternary;
            hdr.ipv4.fragOffset: ternary;
        }
        actions = {
            count_frag;
            set_frag_alert;
            NoAction;
        }
        size = 2;
        default_action = NoAction();
    }

    apply {
        if (hdr.tcp.isValid()) {
            bit<32> index = hdr.ipv4.dstAddr;
            if (hdr.tcp.flags & 0x04) { // RST flag
                count_rst(index);
                set_rst_alert();
            }
            if (hdr.tcp.flags & 0x01) { // FIN flag
                count_fin(index);
                set_fin_alert();
            }
        }

        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.flags[1] == 1 || hdr.ipv4.fragOffset != 0) {
                bit<32> index = hdr.ipv4.dstAddr;
                count_frag(index);
                set_frag_alert();
            }
        }
    }
}

// -------------- Egress Processing --------------

control MyEgress(inout headers hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { /* Egress: no processing here */ }
}

// -------------- Deparser --------------

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

// -------------- Switch Pipeline --------------

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
