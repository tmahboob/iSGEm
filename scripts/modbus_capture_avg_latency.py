from scapy.all import sniff, sendp, Raw, Ether
import time
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(plaintext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext)

key = b'\x00' * 32  # 32-byte key (replace with a securely generated key in production)
nonce = b'\x00' * 16  # 16-byte nonce (replace with a unique nonce in production)
no = 0  # Packet counter
latency_list = []  # To store latencies for the 12 packets
latency_sum = 0  # Sum of latencies for the current batch of packets
batch_size = 12  # Process latency after every 12 packets

def process_packet(pkt):
    global no, latency_sum, latency_list
    no += 1
    print(f'Intercepted packet no: {no}')

    # Measure encryption latency
    start_of_encrypt = time.time()

    # Check if the packet has an Ethernet layer and a RAW payload
    if Raw in pkt and pkt[Ether].type == 0x0800:  # Ethernet type for IPv4
        # Encrypt the packet payload
        pkt[Raw].load = struct.pack("d", time.perf_counter()) + encrypt(pkt[Raw].load, key, nonce)
        
    end_of_encrypt = (time.time() - start_of_encrypt) * 1000  # Convert to milliseconds
    latency_sum += end_of_encrypt
    latency_list.append(end_of_encrypt)

    print(f"Encryption latency for packet {no}: {end_of_encrypt:.3f} ms")

    # If we've processed 12 packets, calculate the average latency
    if no % batch_size == 0:
        average_latency = latency_sum / batch_size
        print(f"\nAverage latency for the last {batch_size} packets: {average_latency:.3f} ms\n")
        
        # Reset the latency tracking for the next batch
        latency_sum = 0
        latency_list = []

    sendp(pkt, iface="veth4")

def main():
    print("-------- Starting interception on S1 ---------")
    # Sniff packets on interface S1-eth1 (from the ingress side)
    sniff(iface="veth2", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
