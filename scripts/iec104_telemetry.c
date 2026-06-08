/*** 
eBPF function for IEC104 parsing 
filip.holik@glasgow.ac.uk
Netlab, GCDL, University of Glasgow
***/

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ebpf_switch.h"

#define IEC104_PORT 2404
#define IEC104_START 0x68
#define MAX_IOA 96

struct ioa 
{
    uint8_t ioa[3]; 
    uint8_t value[4];
    uint8_t qds;     
    uint8_t timestamp[7];
}__attribute__((packed)); //Prevents padding issues

struct iec104asdu
{
    uint8_t type_id; 
    uint8_t sq_numx; //1 bit SQ, 7 bits NumIx 
    uint8_t cause_neg_test; //6 bits Cause, 1 bit Negative, 1 bit Test - Might be 2 bytes in some implementations?! 
    uint8_t oa;
    uint16_t addr;
    struct ioa ioa_list[MAX_IOA]; 
}__attribute__((packed)); 

struct iec104apdu
{
    uint8_t start; 
    uint8_t apdu_len; 
    uint32_t type_tx_rx;
    struct iec104asdu asdu; 
}__attribute__((packed));

struct iec104
{
    // Common metadata fields 
    uint32_t time_s; // Received timestamp (s)
    uint32_t time_ns; // Received timestamp (ns)
    uint32_t src_ip;
    uint32_t dst_ip;
    struct iec104apdu apdu; 
};

// eBPF map for dynamic allocation
struct bpf_map_def SEC("maps") buffer = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct iec104),
    .max_entries = 1,
};

// Definition of various TypeID structures - timestamp
static __always_inline int has_timestamp(uint8_t type_id)
{
    switch (type_id) {
        case 30: case 31: case 34: case 35: case 36:
            return 1;
        default:
            return 0;
    }
}

// Definition of various TypeID structures - value lengths
static __always_inline int value_size(uint8_t type_id)
{
    switch (type_id) {
        case 1: case 3:
            return 1;
        case 9: case 11:
            return 2;
        case 13:
            return 4;
        case 30: case 31:
            return 1;
        case 34: case 36:
            return 4;
        default:
            return -1; // unsupported
    }
}

uint64_t prog(struct packet *pkt)
{  
    // Check if the Ethernet frame contains an ipv4 payload
    if (pkt->eth.h_proto == 0x0008)
    {
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);

        //TODO this end check is most likely wrong! And the follow up checks for sure is! 
        void *data_end = (void *)(unsigned long)&pkt->eth + pkt->metadata.length;

        // Check if the IP packet contains a TCP payload
        if (ipv4->ip_p == 6)
        {
            struct tcphdr *tcp = (struct tcphdr *)(((uint32_t *)ipv4) + ipv4->ip_hl);
            __u16 iec_port_net = htons(IEC104_PORT); 

            // Check if the TCP payload is IEC104
            if (tcp->th_sport == iec_port_net || tcp->th_dport == iec_port_net)
            {
                uint8_t tcp_hdr_len = tcp->th_off * 4;
                uint8_t *payload = (uint8_t *)tcp + tcp_hdr_len;

                uint8_t apdu_len = payload[1]; 

                if (payload + 2 + apdu_len > (uint8_t *)data_end) //payload[1] == apdu_len
                     return NEXT;

                if (payload[0] != IEC104_START)
                    return NEXT;

                // Lookup IEC104 structure in map
                uint32_t key = 0;
                struct iec104 *iec104 = 0;
                bpf_map_lookup_elem(&buffer, &key, &iec104);
                if (!iec104)
                    return NEXT;

                // Clear previous contents, too big for memset 
                iec104->time_s = 0;
                iec104->time_ns = 0;
                iec104->src_ip = 0;
                iec104->dst_ip = 0;
                
                iec104->apdu.start = 0; 
                iec104->apdu.apdu_len = 0; 
                iec104->apdu.type_tx_rx = 0; 

                iec104->apdu.asdu.type_id = 0; 
                iec104->apdu.asdu.sq_numx = 0; 
                iec104->apdu.asdu.cause_neg_test = 0;
                iec104->apdu.asdu.oa = 0;
                iec104->apdu.asdu.addr = 0;

                // Load metadata
                iec104->time_s = pkt->metadata.sec;
                iec104->time_ns = pkt->metadata.nsec;
                iec104->src_ip = ipv4->ip_src.s_addr;
                iec104->dst_ip = ipv4->ip_dst.s_addr;

                // Fill APDU header
                iec104->apdu.start = payload[0];
                iec104->apdu.apdu_len = apdu_len;

                uint8_t *asdup = payload + 6;

                // Safety checks for eBPF verifier
                if (asdup + 6 > (unsigned char *)data_end)
                    return NEXT;

                uint16_t ioa_count = asdup[1] & 0x7F; // lower 7 bits
                if (ioa_count > MAX_IOA)
                    ioa_count = MAX_IOA;

                uint16_t asdu_payload_len = 0;
                if (apdu_len > 6) {
                    asdu_payload_len = apdu_len - 6;
                } else {
                    asdu_payload_len = 0;
                }

                // ASDU parsing 
                iec104->apdu.asdu.type_id = asdup[0];
                iec104->apdu.asdu.sq_numx = asdup[1];
                iec104->apdu.asdu.addr = asdup[4] | (asdup[5] << 8);

                // IOAs parsing  
                uint8_t *ioa_ptr = asdup + 6; // not 4! 

                // Init to 0s, too large memory for memset 
                for (int i = 0; i < ioa_count; i++) {
                    for (int j = 0; j < 3; j++)
                        iec104->apdu.asdu.ioa_list[i].ioa[j] = 0;

                    for (int j = 0; j < 4; j++)
                        iec104->apdu.asdu.ioa_list[i].value[j] = 0;

                    iec104->apdu.asdu.ioa_list[i].qds = 0;

                    for (int j = 0; j < 7; j++)
                        iec104->apdu.asdu.ioa_list[i].timestamp[j] = 0;
                }

                // Calculate IOA length 
                int vlen = value_size(iec104->apdu.asdu.type_id);
                if (vlen < 0)
                    return NEXT;

                int ts_len = has_timestamp(iec104->apdu.asdu.type_id) ? 7 : 0;
                int ioa_len = 3 + vlen + 1 + ts_len;

                for (int i = 0; i < ioa_count; i++)
                {
                    if (ioa_ptr + ioa_len > (uint8_t *)data_end) 
                    {
                        break;
                    } 

                    // IOA parsing for runtime computed len 
                    struct ioa *ioa = &iec104->apdu.asdu.ioa_list[i];

                    /* IOA address */
                    #pragma unroll
                    for (int j = 0; j < 3; j++)
                        ioa->ioa[j] = ioa_ptr[j];
                    ioa_ptr += 3;

                    /* value */
                    #pragma unroll
                    for (int j = 0; j < 4; j++) {
                        if (j < vlen)
                            ioa->value[j] = ioa_ptr[j];
                        else
                            ioa->value[j] = 0;
                    }
                    ioa_ptr += vlen;

                    /* timestamp */
                    #pragma unroll
                    for (int j = 0; j < 7; j++) {
                        if (ts_len)
                            ioa->timestamp[j] = ioa_ptr[j];
                        else
                            ioa->timestamp[j] = 0;
                    }

                    if (ts_len)
                        ioa_ptr += 7;

                }         
                
                //eBPF offload to the IOL with the extracted data; 
                bpf_notify(104, iec104, sizeof(*iec104));                             
            }            
        }
    }

    // Non-IEC104 traffic, continue the pipeline    
    return NEXT;
}
char _license[] SEC("license") = "GPL";
