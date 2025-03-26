#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "ebpf_switch.h"
#include <string.h>
#include <arpa/inet.h> // for ntohl
#include "fixed-point.h"
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/bpf.h>
//#include <linux/ktime.h> //admin:///home/vboxuser/BPFabric/includes/linux/include/linux
//admin:///home/vboxuser/BPFabric/includes/linux/include/linux
//#include <linux/ktime.h>
//#include <bpf/libbpf.h>
//#include <linux/ktime.h>


// ... [other includes and definitions]

#define FIXED_POINT_SCALE 1
#define CLASS_0 0
#define CLASS_1 1

#define threshold1 127
#define threshold2 -32767
#define threshold3 -95
#define threshold4 32767
#define threshold5 8192



struct timecomplexity {
uint32_t start_time_sec;
uint32_t end_time_sec;
uint32_t start_time_nsec;
uint32_t end_time_nsec;
};


// Structure definition for incoming packet data
struct features {
    char timestamp[8];
    char stNum;
    char sqNum;
    int8_t data1[4];   
    int8_t data2[4];
    int8_t data3[4];
    int8_t data4[4];
    int8_t data5[4];
    int8_t data6[4];
    int8_t data7[4];
    int8_t data8[4];
    int8_t label[4];
    int8_t classification_result;
   // uint32_t classification_time;
   // int32_t data_entry_count;
   // char tag_0x87_position;
    //int8_t count;
};

// BPF map for storing GOOSE analyzer state
struct bpf_map_def SEC("maps") goose_analyser = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6,  // MAC address is the key
    .value_size = sizeof(struct features),
    .max_entries = 1,
};

// BPF map for storing Performance updates
struct bpf_map_def SEC("maps") performance_monitor = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6,  // MAC address is the key
    .value_size = sizeof(struct timecomplexity),
    .max_entries = 1,
};

// Example usage in eBPF program
int64_t prog(struct packet *pkt) {


uint8_t alpha = 10;
uint8_t alpha2 = 2;
uint8_t alpha3 = 8;
uint8_t b = 16;
uint8_t b2 = 8;
uint8_t b3 = 4;
int8_t lb= (-2 * (1 << (b-1)) + 1);
int8_t ub= (2 * (1 << (b-1)) - 1);
int8_t lb1= (-2 * (1 << (b2-1)) + 1);
int8_t ub1= (2 * (1 << (b2-1)) - 1);

int8_t lb2= (-2 * (1 << (b2-1)) + 1);
int8_t ub2= (2 * (1 << (b2-1)) - 1);


int TP =0;

    struct features *item;
    struct timecomplexity *timeC;
    void *data = (void *)(unsigned long)&pkt->eth;
    void *data_end = (void *)(unsigned long)&pkt->eth + pkt->metadata.length;

    if (pkt->eth.h_proto == 47240) { // GOOSE = 0x88B8 (LittleE) -> B888 (BigE) = 47240
        if (bpf_map_lookup_elem(&goose_analyser, pkt->eth.h_source, &item) == -1) {
            struct features newitem = {0};  // Initializing all fields to 0
            
            bpf_map_update_elem(&goose_analyser, pkt->eth.h_source, &newitem, BPF_ANY);
            item = &newitem;
        }
        if (bpf_map_lookup_elem(&performance_monitor, pkt->eth.h_source, &timeC) == -1) {
            
        	struct timecomplexity newtimeC={0};  // Initializing all fields to 0
            
            bpf_map_update_elem(&performance_monitor, pkt->eth.h_source, &newtimeC, BPF_ANY);
            timeC = &newtimeC;
        }

timeC->start_time_sec = pkt->metadata.sec;

timeC->start_time_nsec = pkt->metadata.nsec;

        struct ethhdr *eth = data;
        unsigned char *ptr = (unsigned char *)(eth + 1);  // Start of the GOOSE Header
        ptr += 11;  // Start of APDU (length of GOOSE Header 8 bytes + TL meta 3 bytes)

        while (ptr + 2 <= (unsigned char *)data_end) {
            __u8 tag = *ptr++;
            __u8 length = *ptr++;
            if (ptr + length > (unsigned char *)data_end) {
                return 0;  // Return value to indicate no further action
            }

            if (tag == 0xab) { // Custom data tag (0x87)
            
                unsigned char *new = ptr;
                unsigned char *tag_0x87_ptr = ptr;

                // Extract features and labels as done in your original code...
                // Assuming feature extraction is done here, we now focus on execution time

             


 for (int i = 0; i < 4; i++) {
                    // Convert each data value to fixed-point using to_fixed_point function
                    item->data1[i]= *(tag_0x87_ptr + 3 +i);
                    item->data2[i] =*(tag_0x87_ptr + 10 +i);
                    item->data3[i] =*(tag_0x87_ptr + 17 +i);
                    item->data4[i] =*(tag_0x87_ptr + 24 +i);
                    item->data5[i]=*(tag_0x87_ptr + 31 +i);
                    item->data6[i] =*(tag_0x87_ptr + 38 +i);
                    item->data7[i] =*(tag_0x87_ptr + 45 +i);
                    item->data8[i] =*(tag_0x87_ptr + 52 +i);
                    
                    
                    // The label is assumed to be in raw format, so we copy it directly
	            item->label[i]=*(tag_0x87_ptr + 59 + i);//59 orig for 8 feats
                }
                // Extract the number from the fixed-point structures for features
             //   feature_4 = item->data4[0].number;  // Use the 'number' part of fixed-point
               // feature_5 = item->data5[0].number;  // Use the 'number' part of fixed-point
                //feature_7 = item->data7[0].number;  // Use the 'number' part of fixed-point
            



   //int32_t FIXED_POINT_SCALE = 10;
int32_t feature_2_value=0;
int32_t feature_3_value=0;
int32_t feature_4_value=0;
///int32_t feature_8_value=0;
int32_t feature_5_value=0;
int32_t feature_7_value=0;
int32_t feature_8_value=0;  // This will hold the combined 4-byte integer
////int8_t feature_2_bytes[4], feature_4_bytes[4],feature_6_bytes[4], feature_7_bytes[4], feature_8_bytes[4];    // Array to hold the 4 bytes

int8_t feature_2_bytes[4], feature_3_bytes[4], feature_4_bytes[4], feature_5_bytes[4], feature_7_bytes[4],feature_8_bytes[4];//, feature_8_bytes[4];    // Array to hold the

// Copy the bytes into the feature_8_bytes array
for (int i = 0; i < 4; i++) {
 feature_2_bytes[i] = *(new + 10 + i);
 feature_3_bytes[i] = *(new + 17 + i);
    feature_4_bytes[i] = *(new + 24 +i);//*(new + 24 + i);  // Assuming you're reading 4 bytes from the pointer
      feature_5_bytes[i] = *(new + 31 +i);//*(new + 45 + i);  // Assuming you're reading 4 bytes from the pointer
        feature_7_bytes[i] = *(new + 45 + i);  // Assuming you're reading 4 bytes from the pointer

          /// feature_8_bytes[i] = *(tag_0x87_ptr + 52 + i);  // Assuming you're reading 4 bytes from the pointer

}
//uint32_t f=pkt->metadata.sec;// + pkt->metadata.nsec;
//for (int i = 0; i < 4; i++) {
//
    //      feature_8_bytes[i] =f;//*(new + 52 + i);
          
        //  }
// Combine the bytes from feature_8_bytes[] into a 32-bit integer
for (int i = 0; i < 4; i++) {
  feature_2_value |= ((int32_t)feature_2_bytes[i] << (i * 8));
   feature_3_value |= ((int32_t)feature_3_bytes[i] << (i * 8));
    feature_4_value |= ((int32_t)feature_4_bytes[i] << (i * 8));  // Shift and combine the bytes
      feature_5_value |= ((int32_t)feature_5_bytes[i] << (i * 8));  // Shift and combine the bytes
              feature_7_value |= ((int32_t)feature_7_bytes[i] << (i * 8));  // Shift and combine the bytes
          ///feature_8_value |= ((int32_t)feature_8_bytes[i] << (i * 8));
         ///   feature_8_value |= ((int32_t)feature_8_bytes[i] << (i * 8));  // Shift and combine the bytes
}
    // Scale the features correctly
//for (int i = 0; i < 4; i++) {  
 //feature_8_value |= ((int32_t)feature_8_bytes[i] << (i* 8));
 
//item->data8[i] = feature_8_value;
//}
int16_t scaled_feature_2_value = (int32_t)feature_2_value *alpha;
if(scaled_feature_2_value<lb){scaled_feature_2_value =lb;}
if(scaled_feature_2_value>ub){scaled_feature_2_value=ub;}

int16_t scaled_feature_3_value = (int32_t)feature_3_value *alpha;
if(scaled_feature_3_value<lb){scaled_feature_3_value =lb;}
if(scaled_feature_3_value>ub){scaled_feature_3_value=ub;}

int16_t scaled_feature_4_value = (int32_t)feature_4_value *alpha3;
if(scaled_feature_4_value<lb){scaled_feature_4_value =lb;}
if(scaled_feature_4_value>ub){scaled_feature_4_value=ub;}

int16_t scaled_feature_4_value1 = (int32_t)feature_4_value *alpha3; //a=8,b=8,th=324.5
if(scaled_feature_4_value<lb1){scaled_feature_4_value =lb1;}
if(scaled_feature_4_value>ub1){scaled_feature_4_value=ub1;}

int16_t scaled_feature_4_value2 = (int32_t)feature_4_value *alpha2;
if(scaled_feature_4_value<lb2){scaled_feature_4_value =lb2;}
if(scaled_feature_4_value>ub2){scaled_feature_4_value=ub2;}

int16_t scaled_feature_5_value = (int32_t)feature_5_value *alpha;
if(scaled_feature_5_value<lb){scaled_feature_5_value =lb;}
if(scaled_feature_5_value>ub){scaled_feature_5_value=ub;}

int16_t scaled_feature_7_value = (int32_t)feature_7_value *alpha3; //a=8,b=16
if(scaled_feature_7_value<lb){scaled_feature_7_value =lb;}
if(scaled_feature_7_value>ub){scaled_feature_7_value=ub;}

int16_t scaled_feature_7_value3 = (int32_t)feature_7_value *alpha3;
if(scaled_feature_7_value<lb2){scaled_feature_7_value =lb2;}
if(scaled_feature_7_value>ub2){scaled_feature_7_value=ub2;}


		
		
             // timecomplexity.start_time = bpf_ktime_get_ns();  // Capture the start time of the classification process
                // Decision tree logic for classification
                if (scaled_feature_4_value1 <= threshold1) { //127
                    if (scaled_feature_7_value <= threshold2) { //-32767
                        item->classification_result = CLASS_0;
                    } else {
                        if (scaled_feature_4_value2 <= threshold3) { //-95
                            item->classification_result = CLASS_0;
                        } else {
                            if (scaled_feature_7_value <= threshold4) { //32767
                                item->classification_result = CLASS_1;
                            } else {
                                item->classification_result = CLASS_0;
                            }
                        }
                    }
                } else {
                    if (scaled_feature_4_value <= threshold5) {  // 32767
                        item->classification_result = CLASS_0;
                    } else {
                        item->classification_result = CLASS_1;
                    }
                }
                
                
                //=============================================
                


   
//====================================
                
                
                

                // 3. End time for classification
               // timecomplexity.end_time = bpf_ktime_get_ns();  // Capture the end time after classification

                // 4. Calculate elapsed time for classification
                
              //  uint32_t t1 = timecomplexity.end_time_nsec - timecomplexity.start_time_nsec;
             //   uint32_t t2 = timecomplexity.end_time_sec - timecomplexity.start_time_sec;
                
  //  if (t1< 0) {
    // If nsec part goes negative, adjust by subtracting 1 second
  //  t1 += 1000000000; // 1 second in nanoseconds
  //  t2 -= 1;  // Adjust the seconds as well
 //   }
   		//item->classification_time = t2 * 1000000000 + t1;
   		   		//item->classification_time = t1;


                // Store the elapsed time in the BPF map
                //u32 pid = bpf_get_current_pid_tgid() >> 32;  // Use PID as key (or another identifier)
              //  classification_times.update(&pid, &classification_time);

                // Optionally, print the classification time for debugging
               // bpf_trace_printk("PID %d classification time: %llu ns\n", pid, classification_time);

                // //////////////(important for dropping packets) Check if label matches classification result
               // if (*(item->label) == (item->classification_result)) {
                // if (item->classification_result==1){
                    TP = TP + 1;
                    
                   // item->data_entry_count = pkt->metadata.sec;//+pkt->metadata.nsec;
                    //return DROP; 
                  //  item->count = TP;
              //  }//}
            }
            ptr += length;
        }
		timeC->end_time_sec = pkt->metadata.sec;
		timeC->end_time_nsec = pkt->metadata.nsec;
        bpf_notify(0, item, sizeof(struct features));  // Notify for debugging
        bpf_notify(0, timeC, sizeof(struct timecomplexity));  // Notify for debugging
       // bpf_map_delete_elem(&goose_analyser, &item);
        //bpf_map_delete_elem(&performance_monitor, &timeC);
    }
//if (*(item->label) == (item->classification_result))
// return DROP;
 //else
return NEXT;  // Ensure to return a value
}

char _license[] SEC("license") = "GPL";



