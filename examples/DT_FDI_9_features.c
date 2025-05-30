#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h> // For bpf_trace_printk

#include <linux/icmp.h>
#include "ebpf_switch.h"
#include <string.h>
#include <arpa/inet.h> // for ntohl
#include "fixed-point.h"

//#define CLASS_0 0
//#define CLASS_1 1

// Define the thresholds as float values
#define FIXED_POINT_SCALE 10


uint32_t f = 0x42f80000; //124
uint32_t f1 = 0x43020000; //130


struct stsqnums {
    char timestamp[8];
    char stNum;
    char sqNum;
    int8_t  data1[4];   // Change from int8_t to struct fixed_point
    int8_t  data2[4];   // Change from int8_t to struct fixed_point
    int8_t  data3[4];   // Change from int8_t to struct fixed_point
    int8_t  data4[4];   // Change from int8_t to struct fixed_point
    int8_t  data5[4];   // Change from int8_t to struct fixed_point
    int8_t  data6[4];   // Change from int8_t to struct fixed_point
    int8_t  data7[4];   // Change from int8_t to struct fixed_point
    int8_t  data8[4];   // Change from int8_t to struct fixed_point
   // int8_t  data9[4];   // Change from int8_t to struct fixed_point
    int8_t label[4]; // Keep as int8_t since it's a label
    uint8_t classification_result;
   // int32_t data_entry_count; // Count of how many data entries have been processed
   // char tag_0x87_position; // Indicates the tag position for 0x87
};





struct bpf_map_def SEC("maps") goose_analyser = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(struct stsqnums),
    .max_entries = 256,
};

// Example usage within a BPF program:
uint64_t prog(struct packet *pkt) {



    struct stsqnums *item;
    void *data = (void *)(unsigned long)&pkt->eth;
    void *data_end = (void *)(unsigned long)&pkt->eth + pkt->metadata.length;

    if (pkt->eth.h_proto == 47240) { // GOOSE = 0x88B8 (LittleE) -> B888 (BigE) = 47240
        if (bpf_map_lookup_elem(&goose_analyser, pkt->eth.h_source, &item) == -1) {
            struct stsqnums newitem = {0};  // Initializing all fields to 0
            item = &newitem;
            bpf_map_update_elem(&goose_analyser, pkt->eth.h_source, &item, 0);
        }

        struct ethhdr *eth = data;
        unsigned char *ptr = (unsigned char *)(eth + 1); // Start of the GOOSE Header
        ptr += 11; // Start of APDU (length of GOOSE Header 8 bytes + TL meta 3 bytes)

        while (ptr + 2 <= (unsigned char *)data_end) {
            __u8 tag = *ptr++;
            __u8 length = *ptr++;
            if (ptr + length > (unsigned char *)data_end) {
                return 0;  // Return value to indicate no further action
            }

            if (tag == 0x84) { // Timestamp (8 bytes)
                if (length == 8) {
                    for (int i = 0; i < 8; i++) {
                        item->timestamp[i] = ptr[i];
                    }
                }
            } 
            else if (tag == 0x85) { // stNum
                if (length == 1) {
                    item->stNum = *ptr;
                }
            } 
            else if (tag == 0x86) { // sqNum
                if (length == 1) {
                    item->sqNum = *ptr;
                }
            }
            else if (tag == 0xab) { // Custom data tag (0x87)
                unsigned char  *tag_0x87_ptr = ptr++;
                for (int i = 0; i < 4; i++) {
                    // Convert each data value to fixed-point using to_fixed_point function
                    item->data1[i]= *(tag_0x87_ptr + 3 +i);
                    item->data2[i] =*(tag_0x87_ptr + 10+i);
                    item->data3[i] =*(tag_0x87_ptr + 17 +i);
                    item->data4[i] =*(tag_0x87_ptr + 24 +i);
                    item->data5[i] =*(tag_0x87_ptr + 31+i);
                    item->data6[i] =*(tag_0x87_ptr + 38+i);
                    item->data7[i] =*(tag_0x87_ptr + 45+i);
                    item->data8[i] =*(tag_0x87_ptr + 52+i);
 		   // item->data9[i] =*(tag_0x87_ptr + 59+i);
                    
                    // The label is assumed to be in raw format, so we copy it directly
	            item->label[i] =*(tag_0x87_ptr + 59 +i);
                }
                  




 // Use fixed-point representation
int32_t feature_8_value = 0;  // This will hold the 32-byte integer
int8_t feature_8_bytes[4];    // Array to hold the 4 bytes

	// Copy the bytes into the feature_8_bytes array
	for (int i = 0; i < 4; i++) {
	    feature_8_bytes[i] = *(tag_0x87_ptr + 52 + i);  // Assuming you're reading 4 bytes from the pointer
	}

	// Combine the bytes from feature_8_bytes[] into a 32-bit integer
	for (int i = 0; i < 4; i++) {
	    feature_8_value |= ((int32_t)feature_8_bytes[i] << (i * 8));  // Shift and combine the bytes
	}


	//printf("feature_8_value: 0x%x\n", feature_8_value);
	// Now compare the feature value
	if (feature_8_value <= 124) { //if 124 then 1 otherwise 0
	    item->classification_result = 1;  // Class 0
	} else  {
	    item->classification_result = 0;  // Class 1
	}
	   // Run the decision tree logic to classify
       // item->classification_result = check_decision_tree(item);
            
                            
        }
                    ptr += length;
        }

        bpf_notify(0, item, sizeof(struct stsqnums)); // Notify for debugging
   } 
    return NEXT;  // Ensure to return a value
}

char _license[] SEC("license") = "GPL";

