from pymodbus.client.sync import ModbusTcpClient
from pymodbus.payload import BinaryPayloadBuilder
from pymodbus.constants import Endian
import csv
import time

SCADA_IP = '127.0.0.1'
PORT = 502
UNIT_ID = 1
CHUNK_SIZE = 27
CHUNKS_PER_ROW = 10


def build_modbus_payload(chunk):
    builder = BinaryPayloadBuilder(byteorder=Endian.Big, wordorder=Endian.Big)
    for val in chunk:
        builder.add_32bit_float(float(val))
    return builder.to_registers()


def send_pmu_data(client, chunk, address=0):
    registers = build_modbus_payload(chunk)
    result = client.write_registers(address, registers, unit=UNIT_ID)
    return result


if __name__ == "__main__":
    client = ModbusTcpClient(SCADA_IP, port=PORT)
    if client.connect():
        print(f"Connected to SCADA at {SCADA_IP}:{PORT}")
        try:
            with open('X_attack_10x27_chunks_with_labels.csv', 'r') as file:
                reader = csv.reader(file)
                next(reader)  # skip header if present
                for row in reader:
                    row = list(map(float, row))  # Convert all to float
                    features = row[:270]  # First 270 columns
                    label = row[270]  # Last column
                    print('features',features)
                    # Split into 10 chunks of 27
                    for i in range(0, 270, CHUNK_SIZE):
                        chunk = features[i:i + CHUNK_SIZE]
                        result = send_pmu_data(client, chunk)
                        if result.isError():
                            print("Error sending chunk:", result)
                        else:
                            print("Sent chunk:", chunk)
                        time.sleep(0.2)  # delay between packets
        except KeyboardInterrupt:
            print("Client stopped by user.")
        finally:
            client.close()
    else:
        print("Unable to connect to SCADA server.")
