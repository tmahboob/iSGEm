//Author: Dr. Tahira Mahboob, NetLab, University of Glasgow, March 26, 2025
//Standard scaling method for Decision Tree

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "ebpf_switch.h"
#include <string.h>
#include <arpa/inet.h> // for ntohl
#include "fixed-point.h"
#include <linux/bpf.h>
#include <linux/types.h>


//this is for sv8.pkl model
//#define xt4_1 324
//#define xt7_1 -311043
//#define xt4_2 -1
//#define xt8_1 90942

//this is for sv8(1).pkl model

#define x4_1 3245//.5
#define x7_1 -3110435//.5
#define x4_2 -15//.5
#define x8_1 909425//.5
//#define x4_3 48899




static __always_inline int32_t bpf_ntohl(int32_t x) {
    return __builtin_bswap32(x);
}

//CLASS definitions
#define CLASS_0 0
#define CLASS_1 1

#define FIXED_POINT_SCALE 10



int TP=0;




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
    int8_t  label[4]; // Keep as int8_t since it's a label
    int8_t classification_result;
    //int32_t data_entry_count; // Count of how many data entries have been processed
    //char tag_0x87_position; // Indicates the tag position for 0x87
};


struct bpf_map_def SEC("maps") goose_analyser = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(struct stsqnums),
    .max_entries = 1,
};

// Example usage within a BPF program:
int64_t prog(struct packet *pkt) {

    struct stsqnums *item;
    void *data = (void *)(unsigned long)&pkt->eth;
    void *data_end = (void *)(unsigned long)&pkt->eth + pkt->metadata.length;

    if (pkt->eth.h_proto == 47240) { // GOOSE = 0x88B8 (LittleE) -> B888 (BigE) = 47240
        if (bpf_map_lookup_elem(&goose_analyser, pkt->eth.h_source, &item) == -1) {
            struct stsqnums newitem = {0};  // Initializing all fields to NULL

           bpf_map_update_elem(&goose_analyser, pkt->eth.h_source, &newitem, BPF_ANY);
                        item = &newitem;
        }
        
        //extracting TLV values

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
            	unsigned char *new = ptr;
                unsigned char  *tag_0x87_ptr = ptr;
                for (int i = 0; i < 4; i++) {
                    // Extract features
                    item->data1[i]= *(tag_0x87_ptr + 3 +i); //32 bytes, reading 1 byte 
                    item->data2[i] =*(tag_0x87_ptr + 10+i);
                    item->data3[i] =*(tag_0x87_ptr + 17 +i);
                    item->data4[i] =*(tag_0x87_ptr + 24 +i);
                    item->data5[i]=*(tag_0x87_ptr + 31+i);
                    item->data6[i] =*(tag_0x87_ptr + 38+i);
                    item->data7[i] =*(tag_0x87_ptr + 45+i);
                    item->data8[i] =*(tag_0x87_ptr + 52+i);
                    
                    // The label is assumed to be in raw format, so we copy it directly
	            item->label[i]=*(tag_0x87_ptr + 59 + i);
       		}



//scaling feature values
int32_t feature_4_value=0;
int32_t feature_8_value=0;
int32_t feature_7_value=0;

int8_t feature_4_bytes[4], feature_7_bytes[4], feature_8_bytes[4];//,feature_7_bytes[4];//, feature_8_bytes[4];    // Array to hold the

// Copy the bytes into the feature_8_bytes array
for (int i = 0; i < 4; i++) {
 //feature_2_bytes[i] = *(tag_0x87_ptr + 10 + i);
    feature_4_bytes[i] = *(new + 24 +i);//*(new + 24 + i);  // Assuming you're reading 4 bytes from the pointer
      feature_7_bytes[i] = *(new + 45+i);//*(new + 45 + i);  // Assuming you're reading 4 bytes from the pointer
        //feature_6_bytes[i] = *(tag_0x87_ptr + 38 + i);  // Assuming you're reading 4 bytes from the pointer
          feature_8_bytes[i] =*(new + 52+i);//*(new + 52 + i);
          //  feature_8_bytes[i] = *(tag_0x87_ptr + 52 + i);  // Assuming you're reading 4 bytes from the pointer

}

// Combine the bytes from feature_8_bytes[] into a 32-bit integer
for (int i = 0; i < 4; i++) {
//   feature_2_value |= ((int32_t)feature_2_bytes[i] << (i * 8));
    feature_4_value |= ((int32_t)feature_4_bytes[i] << (i * 8));  // Shift and combine the bytes
      feature_7_value |= ((int32_t)feature_7_bytes[i] << (i * 8));  // Shift and combine the bytes
        ///feature_6_value |= ((int32_t)feature_6_bytes[i] << (i * 8));  // Shift and combine the bytes
          feature_8_value |= ((int32_t)feature_8_bytes[i] << (i * 8));
         ///   feature_8_value |= ((int32_t)feature_8_bytes[i] << (i * 8));  // Shift and combine the bytes
}
 // Scale the features correctly
//int64_t scaled_feature_2_value = (int64_t)feature_2_value *FIXED_POINT_SCALE;
int64_t scaled_feature_4_value = (int64_t)feature_4_value * FIXED_POINT_SCALE;
int64_t scaled_feature_7_value = (int64_t)feature_7_value * FIXED_POINT_SCALE;
int64_t scaled_feature_8_value = (int64_t)feature_8_value * FIXED_POINT_SCALE;


    // Decision tree logic

      if ((scaled_feature_4_value)<= x4_1) {//324.5
        if ((scaled_feature_7_value) <= x7_1) {//-311043
            item->classification_result = CLASS_0;
        } else {
            if ((scaled_feature_4_value)<= x4_2) {//1.5
                item->classification_result = CLASS_0;
            } else 
            {
                        item->classification_result = CLASS_1;
            }
    }
    }
    else {
     
        if ((scaled_feature_8_value) <= x8_1){//90942.5
            item->classification_result = CLASS_0;
        } else {
    
            item->classification_result = CLASS_1; //
        }
      }
   
  }

            ptr+=length;
          
} 
        bpf_notify(0, item, sizeof(struct stsqnums)+6); // Notify for debugging
        bpf_map_delete_elem(&goose_analyser,&item); //delete entry after retrieving at user side
    }
    
    
    
    
    return NEXT;  // Ensure to return a value
}

char _license[] SEC("license") = "GPL";

