from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from scapy.all import sniff, Raw, Ether, IP, TCP
from ryu.lib.packet import ether_types, ethernet, ipv4, tcp
import struct
import time
import numpy as np
import tensorflow as tf
from vmdpy import VMD

# Constants
MODBUS_PORT = 1507
BATCH_SIZE = 10
TIME_STEPS = 27
START_OFFSET = 13
packet_number = 0

class ModbusPacket:
    def __init__(self, datapath, pkt, out_port):
        self.datapath = datapath
        self.pkt = pkt
        self.out_port = out_port


class FDISingleton:
    _instance = None
    client_connected = False  # Track whether the client has connected
    request_packet = None  # Track Modbus request packet

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(FDISingleton, cls).__new__(cls)
            cls._instance.batch_data = []
            cls._instance.modbus_packets_data = []
            cls._instance.packet_number = 0
        return cls._instance

    def modbus_packet_capture(self, datapath, pkt, out_port):
        if Raw in pkt and pkt[Ether].type == 0x0800 and pkt.haslayer(TCP):
            tcp_pkt = pkt[TCP]
            # Ensure that we capture Modbus packets only after connection is established
            if tcp_pkt.dport == MODBUS_PORT or tcp_pkt.sport == MODBUS_PORT:
                # Check if the Modbus client has established a connection with the server (initial packet)
                if not self.client_connected:
                    if self.check_modbus_connection(pkt):
                        self.client_connected = True
                        print("Modbus client connected.")
                    else:
                        print("Waiting for Modbus client connection.")
                        return

                # After the connection is established, continue with normal packet capture
                self.packet_number += 1
                ip_pkt = pkt[IP]

                # Parse the payload to extract floats
                payload = pkt[Raw].load
                floats = self.parse_modbus_payload(payload)

                # Capture Modbus request or response
                if self.is_modbus_request(pkt):
                    self.request_packet = pkt  # Capture the Modbus request packet
                    print(f"Captured Modbus request: {pkt.summary()}")
                elif self.is_modbus_response(pkt) and self.request_packet:
                    self.handle_modbus_response(pkt, self.request_packet)  # Handle response
                    print(f"Captured Modbus response: {pkt.summary()}")

                # Add packet to batch if complete
                if len(floats) == TIME_STEPS:
                    self.batch_data.append(floats)
                    self.modbus_packets_data.append(ModbusPacket(datapath, pkt, out_port))
                    print(f"Packet {self.packet_number} added to batch. Batch size: {len(self.batch_data)}")

                    if len(self.batch_data) == BATCH_SIZE:
                        batch_array = np.array(self.batch_data).reshape(1, BATCH_SIZE, TIME_STEPS)
                        print(f"Batch ready for VMD. Shape: {batch_array.shape}")

                        # Apply VMD to extract features
                        X_all = self.apply_vmd_full_features3(batch_array)
                        print(f"VMD features: {X_all.shape}")

                        new_model = tf.keras.models.load_model('FDI_AE.keras')
                        # Anomaly detection with pre-trained model
                        try:
                            print(new_model.summary())

                            mean = 1.2940699484182185
                            std_dev = 0.00844878665634276
                            th = 1.3006772074498418

                            X_a = new_model.predict(X_all, verbose=0)
                            errors2 = np.linalg.norm(X_all - X_a, axis=(1, 2))
                            ti = (errors2 - mean) / std_dev
                            predicted_labels = np.where(ti > th, 1, 0)

                            # If any packet is anomalous, block the batch
                            if 1 in predicted_labels:
                                print("Anomalous behavior detected. Blocking batch.")
                                self.batch_data.clear()
                                self.modbus_packets_data.clear()
                                # Send an anomaly alert
                                self.send_anomaly_alert(datapath)
                            else:
                                print("Batch is normal. Forwarding batch.")
                                self.batch_data.clear()
                                for modbus_packet in self.modbus_packets_data:
                                    self.send_packet_out(modbus_packet)
                                self.modbus_packets_data.clear()

                        except Exception as e:
                            print(f"An error occurred during model prediction: {e}")
                            self.batch_data.clear()
                            self.modbus_packets_data.clear()

                else:
                    print(f"Packet {self.packet_number} has incomplete data; skipping.")
            else:
                print(f"Packet not Modbus. Skipping.")

    def check_modbus_connection(self, pkt):
        # Check if the packet is a Modbus TCP handshake request (usually a function code like 0x03 or 0x06)
        if Raw in pkt and pkt[Raw].load:
            payload = pkt[Raw].load
            print(f"Raw payload: {payload.hex()}")  # Log the raw payload for inspection
            # Modbus request typically has a function code at byte offset 7
            if len(payload) > 7:
                function_code = payload[7]
                print(f"Function code: {function_code}")  # Log the function code for inspection
                # Check for function codes that indicate a connection request (like 0x03 or 0x06)
                if function_code in [0x03, 0x06]:
                    print(f"Connection handshake detected with function code {function_code}")
                    return True
                else:
                    print(f"No connection handshake found (function code: {function_code})")
        else:
            print("No Modbus data in the packet")
        return False

    def is_modbus_request(self, pkt):
        # Check if the packet is a Modbus request (request will have a specific function code)
        if Raw in pkt and pkt[Raw].load:
            payload = pkt[Raw].load
            if len(payload) > 7:
                function_code = payload[7]
                # Function codes like 0x03 (read) or 0x06 (write)
                if function_code in [0x03, 0x06]:
                    return True
        return False

    def is_modbus_response(self, pkt):
        # Check if the packet is a Modbus response (response has slave address + function code)
        if Raw in pkt and pkt[Raw].load:
            payload = pkt[Raw].load
            if len(payload) > 7:
                function_code = payload[7]
                # Modbus response will echo the same function code
                if function_code in [0x03, 0x06]:
                    return True
        return False

    def handle_modbus_response33(self, response_pkt, request_pkt):

        print(f"Handling Modbus response from server: {response_pkt.summary()}")


    def send_packet_out(self, modbus_packet):
        ofproto = modbus_packet.datapath.ofproto
        parser = modbus_packet.datapath.ofproto_parser

        actions = [parser.OFPActionOutput(modbus_packet.out_port)]
        packet_out = parser.OFPPacketOut(
            datapath=modbus_packet.datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=modbus_packet.pkt
        )
        print(f"Sending packet out to port {modbus_packet.out_port}")
        modbus_packet.datapath.send_msg(packet_out)

    def send_anomaly_alert(self, datapath):
        # Create a packet that indicates an anomaly, and send it to a specific port
        anomaly_packet = self.create_anomaly_packet()
        out_port = 1  # or another port where alerts should go
        self.send_packet_out(ModbusPacket(datapath, anomaly_packet, out_port))

    def create_anomaly_packet(self):
        # Create a dummy packet or an error packet to indicate anomaly
        return Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / IP(dst="255.255.255.255") / UDP(sport=12345, dport=12345) / Raw(load=b"Anomaly detected")

    # Parsing Modbus packet to extract floats
    def parse_modbus_payload(self, payload):
        floats = []
        for i in range(0, time_steps * 4, 4):
            if i + 4 <= len(payload):
                float_value = struct.unpack('>f', payload[i:i+4])[0]
                floats.append(float_value)
            else:
                print(f"Warning: not enough bytes to extract float at offset {i}")
                break
        return floats

    # VMD Feature Extraction
    def apply_vmd_full_features3(self, data, alpha=2000, tau=0, K=5, DC=0, init=1, tol=1e-7):
        samples, timesteps, features = data.shape
        vmd_features = np.zeros((samples, K, features))
        for i in range(samples):
            for f in range(features):
                signal = data[i, :, f]
                u, _, _ = VMD(signal, alpha, tau, K, DC, init, tol)
                vmd_features[i, :, f] = np.mean(u, axis=1)
        return vmd_features

  

    def handle_modbus_responseOrig(self, response_pkt, request_pkt):
     """
     Logic to handle Modbus response (e.g., validate response, match request/response pairs).
     """
     print(f"Handling Modbus response from server: {response_pkt.summary()}")

     if Raw in response_pkt and response_pkt[Raw].load:
        response_payload = response_pkt[Raw].load
        request_payload = request_pkt[Raw].load

        # Extract transaction ID from the request and response
        request_transaction_id = struct.unpack('>H', request_payload[:2])[0]
        response_transaction_id = struct.unpack('>H', response_payload[:2])[0]

        if request_transaction_id != response_transaction_id:
            print(f"Transaction ID mismatch: Request ID {request_transaction_id} != Response ID {response_transaction_id}")
            return  # Transaction ID mismatch, can't match request/response pair

        # Extract function code to validate if it matches the request's function code
        request_function_code = request_payload[7]
        response_function_code = response_payload[7]

        if request_function_code != response_function_code:
            print(f"Function code mismatch: Request function {request_function_code} != Response function {response_function_code}")
            return  # Function codes must match for a valid response

        # Handle Modbus read response (function code 0x03)
        if request_function_code == 0x03:
            expected_length = 2 * (len(response_payload) - 9)  # Assuming each register is 2 bytes
            actual_length = len(response_payload) - 9

            if expected_length != actual_length:
                print(f"Invalid response length: Expected {expected_length} bytes, but got {actual_length} bytes")
                return

            # Process data, e.g., extracting registers or values from the response
            registers = struct.unpack(f">{actual_length // 2}H", response_payload[9:])
            print(f"Extracted registers from response: {registers}")

        # Handle Modbus write response (function code 0x06)
        elif request_function_code == 0x06:
            print(f"Handling Modbus write response: {response_payload[9:]}")
            # For example, process the write response here (check if the write was successful)

        # After handling the response, reset request_packet to None
        self.request_packet = None

        # Send the Modbus response back to the client (packet_out)
        self.send_packet_out(response_pkt)
        print(f"Sent Modbus response back to client: {response_pkt.summary()}")

    def modbus_packet_capture(self, datapath, pkt, out_port,logger):
          logger.info("Tahira function works")
        

    def check_modbus_connection(self, pkt):
        # Check if the packet is a Modbus TCP handshake request (usually a function code like 0x03 or 0x06)
        if Raw in pkt and pkt[Raw].load:
            payload = pkt[Raw].load
            print(f"Raw payload: {payload.hex()}")  # Log the raw payload for inspection
            # Modbus request typically has a function code at byte offset 7
            if len(payload) > 7:
                function_code = payload[7]
                print(f"Function code: {function_code}")  # Log the function code for inspection
                # Check for function codes that indicate a connection request (like 0x03 or 0x06)
                if function_code in [0x03, 0x06]:
                    print(f"Connection handshake detected with function code {function_code}")
                    return True
                else:
                    print(f"No connection handshake found (function code: {function_code})")
        else:
            print("No Modbus data in the packet")
        return False

