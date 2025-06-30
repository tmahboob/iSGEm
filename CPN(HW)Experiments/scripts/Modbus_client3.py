from pymodbus.client.sync import ModbusTcpClient
from pymodbus.payload import BinaryPayloadBuilder
from pymodbus.constants import Endian
import csv
import time

# Configuration
SCADA_IP = '127.0.0.1'
PORT = 502
UNIT_ID = 1
START_ADDRESS = 0

def build_modbus_payload(pmu_data):
    builder = BinaryPayloadBuilder(byteorder=Endian.Big, wordorder=Endian.Big)
    for val in pmu_data:
        builder.add_32bit_float(float(val))
    return builder.to_registers()

def send_pmu_data(client, pmu_data):
    registers = build_modbus_payload(pmu_data)
    address = 0  # Register start address
    result = client.write_registers(address, registers, unit=1)
    return result

#client = ModbusTcpClient('127.0.0.1', port=502)
#client.connect()

if __name__ == "__main__":
    client = ModbusTcpClient(SCADA_IP, port=PORT)
    if client.connect():
        print(f"Connected to SCADA at {SCADA_IP}:{PORT}")
        try:
            while True:
                with open('vT.csv', 'r') as file:
                    reader = csv.reader(file)
                    for row in reader:
                        pmu_data = [float(x) for x in row[0:-1]]  # Exclude index and label
                        result = send_pmu_data(client, pmu_data)
                       # break  # remove this if you want to send all rows one-by-one
                        if result.isError():
                            print("Error sending data:", result)
                        else:
                            print("Data sent:", pmu_data)
                        time.sleep(0.5)
        except KeyboardInterrupt:
                    print("Client stopped by user.")
        finally:
            client.close()
    else:
        print("Unable to connect to SCADA server.")

#client.close()
