from scapy.all import sniff, sendp, Raw, Ether, IP, TCP
import time
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(plaintext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext)

key = b'\x00' * 32
nonce = b'\x00' * 16
packet_number = 0

# Function to check and process MODBUS traffic
def process_modbus_packet(pkt):
    global packet_number
    packet_number += 1
    print(f'Intercepted packet no: {packet_number}')

    # Check if the packet has an Ethernet layer and a RAW payload
    if Raw in pkt and pkt[Ether].type == 0x0800:  # Ethernet type for IPv4
        ip_pkt = pkt[IP]

        # Check if the packet is TCP and has the MODBUS port (502)
        if pkt.haslayer(TCP):
            tcp_pkt = pkt[TCP]
            if tcp_pkt.dport == 1505 or tcp_pkt.sport == 1505:
                print(f"MODBUS packet detected! Src IP: {ip_pkt.src}, Dst IP: {ip_pkt.dst}, Src Port: {tcp_pkt.sport}, Dst Port: {tcp_pkt.dport}")
                
                # Encrypt the payload if it's MODBUS traffic
                start_of_encrypt = time.time()
                pkt[Raw].load = struct.pack("d", time.perf_counter()) + encrypt(pkt[Raw].load, key, nonce)
                end_of_encrypt = (time.time() - start_of_encrypt) * 1000
                print(f"Latency of capture- {end_of_encrypt:.3f} ms")
                
                # Forward the packet with encryption
                sendp(pkt, iface="veth4")
                return

    # Forward the packet without any encryption (if it's not MODBUS)
    sendp(pkt, iface="veth4")

def main():
    print("-------- Starting interception on S1 ---------")
    # Sniff packets on interface S1-eth1 (from the ingress side)
    sniff(iface="veth2", prn=process_modbus_packet, store=0)

if __name__ == "__main__":
    main()
