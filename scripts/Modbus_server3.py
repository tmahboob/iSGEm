from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadDecoder
from threading import Thread
import time,csv

# Initialize Modbus data store with 100 holding registers
store = ModbusSlaveContext(
    hr=ModbusSequentialDataBlock(0, [0]*100)
)
context = ModbusServerContext(slaves=store, single=True)

# Device identity info
identity = ModbusDeviceIdentification()
identity.VendorName = 'OpenAI PMU'
identity.ProductCode = 'PMU001'
identity.ProductName = 'PMU Modbus Server'
identity.ModelName = 'PMU Server'
identity.MajorMinorRevision = '1.0'


def save_to_csv(float_values):
    with open("received_pmu_data_server.csv", "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(float_values)

def monitor_registers(context):
    while True:
        # Read 54 registers (27 floats × 2 registers each) starting at 0
        hr_values = context[0x00].getValues(3, 0, count=54)

        import struct
        floats = []
        for i in range(0, len(hr_values), 2):
            high = hr_values[i]
            low = hr_values[i + 1]
            combined = (high << 16) + low
            floats.append(struct.unpack('>f', combined.to_bytes(4, 'big'))[0])
        print("Received row:", floats)
        decoder = BinaryPayloadDecoder.fromRegisters(
           hr_values,
            byteorder=Endian.Big#,
            #wordorder=Endian.Little
        )
        float_values = [decoder.decode_32bit_float() for _ in range(27)]
        print("Received PMU floats:")
        print(float_values)
        print('-'*50)
        save_to_csv(float_values)
        time.sleep(0.5)

if __name__ == "__main__":
    # Start thread to monitor and print data received
    monitor_thread = Thread(target=monitor_registers, args=(context,), daemon=True)
    monitor_thread.start()

    print("Starting Modbus TCP Server on 10.0.0.5:502...")
    StartTcpServer(context, identity=identity, address=("0.0.0.0", 502))

