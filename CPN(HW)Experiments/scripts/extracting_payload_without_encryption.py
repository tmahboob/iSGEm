from scapy.all import sniff, sendp, Raw, Ether, IP, TCP
import time
import struct

# Fixed byte offset where MODBUS data starts (e.g., 26 bytes after the start of the payload)
START_OFFSET = 26  # Change this to the correct byte offset
packet_number = 0


from vmdpy import VMD

# --- Settings ---
time_steps = 10
features_per_timestep = 27
START_OFFSET = 26  # bytes after which Modbus data starts
chunk_buffer = []
packet_number = 0

# --- VMD Function ---
def apply_vmd_full_features2(data, alpha=20000, tau=0, K=time_steps, DC=0, init=1, tol=1e-7):
    samples, timesteps, features = data.shape
    vmd_features = np.zeros((samples, K, features))
    for i in range(samples):
        for f in range(features):
            signal = data[i, :, f]
            u, _, _ = VMD(signal, alpha, tau, K, DC, init, tol)
            vmd_features[i, :, f] = np.mean(u, axis=1)
    return vmd_features

# --- Pa

# Function to check and process MODBUS traffic
def process_modbus_packet(pkt):
    global packet_number
    packet_number += 1
    print(f'Intercepted packet no: {packet_number}')

    # Check if the packet has an Ethernet layer and a RAW payload
    if Raw in pkt and pkt[Ether].type == 0x0800:  # Ethernet type for IPv4
     ip_pkt = pkt[IP]

        # Check if the packet is TCP and has the MODBUS port (1505)
    if pkt.haslayer(TCP):
            tcp_pkt = pkt[TCP]
            if tcp_pkt.dport == 502 or tcp_pkt.sport == 502:
                print(f"MODBUS packet detected! Src IP: {ip_pkt.src}, Dst IP: {ip_pkt.dst}, Src Port: {tcp_pkt.sport}, Dst Port: {tcp_pkt.dport}")

                # Get the payload (Raw data in the packet)
                payload = pkt[Raw].load
                print(f"Raw Payload (Hex): {payload.hex()}")

                # Extract the MODBUS data starting from the fixed offset
                modbus_data = payload[START_OFFSET:]  # Get the data starting from the fixed offset

                # Estimate parsing time for extracting floats
                start_parse_time = time.time()

                # Extract 27 float values (4 bytes each float) from the MODBUS data
                floats = []
                for i in range(0, 27 * 4, 4):  # 4 bytes per float, extracting exactly 27 floats
                    if i + 4 <= len(modbus_data):
                        float_value = struct.unpack('<f', modbus_data[i:i+4])[0]  # Unpack little-endian float
                        floats.append(float_value)

                # Calculate the time taken for parsing
                parsing_time = (time.time() - start_parse_time) * 1000  # Convert to milliseconds
                print(f"Time to parse payload: {parsing_time:.3f} ms")

                # Print the extracted floats
                print(f"Extracted 27 floats: {floats}")
                if len(chunk_buffer) == time_steps:
                    chunk_np = np.array(chunk_buffer).reshape(1, time_steps, features_per_timestep)
                    print("\nReceived one chunk, shape:", chunk_np.shape)

                    # Apply VMD
                    t_start = time.time()
                    vmd_out = apply_vmd_full_features2(chunk_np)
                    t_end = time.time()
                    print('Latency of VMD feature extraction:', (t_end - t_start) * 1000, 'ms')
                    print("VMD output shape:", vmd_out.shape)
                    print("VMD output sample:", vmd_out[0])

                # Forward the packet without any encryption
                #sendp(pkt, iface="Software Loopback Interface 1")
                return

    # Forward the packet without any encryption (if it's not MODBUS)
    #sendp(pkt, iface="Software Loopback Interface 1")

# Main function
def main():
    print("-------- Starting interception on S1 ---------")
    # Sniff packets on interface S1-eth1 (from the ingress side)
    sniff(iface="Software Loopback Interface 1", prn=process_modbus_packet, store=0)

if __name__ == "__main__":
    main()
