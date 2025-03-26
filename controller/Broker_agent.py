######## Contributor: Dr. Tahira Mahboob, NetLab, University of Glasgow, UK #######
####### Code: Broker agent ##############

#!/usr/bin/env python
import cmd
import os
import struct
import pandas as pd
''' new code here'''
import time
import sys
#global part2
import joblib 
import csv
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

import numpy as np
#part2 = open("stateData.csv","w")


# Load the pre-trained ML inference model
#tree_model = joblib.load('trained_model-SV9.pkl')
#tree_model = joblib.load('trained_model-SV8F.pkl') #8 features decision tree
#tree_model = joblib.load('trained_model-SV8F(1).pkl')
#tree_model = joblib.load('trained_model-SV-RF.pkl') #8 features Random forest
#tree_model = joblib.load('trained_model-SV-6F.pkl')
#tree_model = joblib.load('RFS.pkl')
#tree_model = joblib.load('DT9F.pkl')
#tree_model = joblib.load('DT8F.pkl')  # good use this for DT for 90% accuracy
#tree_model = joblib.load('DT4F.pkl')
tree_model = joblib.load('RF1.pkl')

from matplotlib import pyplot as plt

from threading import Thread
from twisted.internet import reactor

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

# The intro message to show at the top when running the program
banner = "-" * 80 + """
    eBPF Switch Controller Command Line Interface - Netlab 2025
    Simon Jouet <simon.jouet@gmail.com> - University of Glasgow 
    iSGEm Intelligent Smart Grid Emulator - Netlab 2025
    Tahira Mahboob <tahira.mahboob@yahoo.com> - University of Glasgow
""" + '-' * 80 + '\n'

def tabulate(rows, headers=None):
    if not rows or len(rows) == 0:
        print('<Empty Table>')
        return

    # Find the largest possible value for each column
    columns_width = [ max([ len(str(row[i])) for row in rows ]) for i in range(len(rows[0])) ]

    # If there are headers check if headers is larger than content
    if headers:
        columns_width = [ max(columns_width[i], len(header)) for i, header in enumerate(headers) ]

    # Add two extra spaces to columns_width for prettiness
    columns_width = [ w+2 for w in columns_width ]

    # Generate the row format string and delimiter string
    row_format = '  '.join(['{{:>{}}}'.format(w) for w in columns_width ])
    row_delim  = [ '='*w for w in columns_width ]

    # Print the headers if necessary
    print('')
    if headers:
        print(row_format.format(*headers))

    # Print the rows
    print(row_format.format(*row_delim))
    for row in rows:
        print(row_format.format(*row))
    print(row_format.format(*row_delim))

class SwitchTableCli(cmd.Cmd):
    def __init__(self, connection, function_id, table_name):
        cmd.Cmd.__init__(self)
        self.connection = connection
        self.function_id = function_id
        self.table_name = table_name

    def do_list(self, line):
        self.connection.send(TableListRequest(index=self.function_id, table_name=self.table_name))

    def do_get(self, line):
        self.connection.send(TableEntryGetRequest(index=self.function_id, table_name=self.table_name, key=bytes.fromhex(line)))

    def do_update(self, line):
        args = line.split()
        if len(args) != 2:
            print("update <hex:key> <hex:value>")
            return

        self.connection.send(TableEntryInsertRequest(index=self.function_id, table_name=self.table_name, key=bytes.fromhex(args[0]), value=bytes.fromhex(args[1])))

    def do_delete(self, line):
        self.connection.send(TableEntryDeleteRequest(index=self.function_id, table_name=self.table_name, key=bytes.fromhex(line)))

    def emptyline(self):
         self.do_help(None)

class SwitchTablesCli(cmd.Cmd):
    def __init__(self, connection, function_id: int):
        cmd.Cmd.__init__(self)
        self.connection = connection
        self.function_id = function_id

    def do_list(self, line):
        self.connection.send(TablesListRequest(index=self.function_id))

    def default(self, line: str) -> None:
        args = line.split(maxsplit=1)

        if len(args) == 0:
            cmd.Cmd.default(self, line)
        else:
            try:
                SwitchTableCli(self.connection, self.function_id, args[0]).onecmd(args[1] if len(args) > 1 else '')
            except ValueError:
                cmd.Cmd.default(self, line)

    def emptyline(self):
         self.do_help(None)

class SwitchCLI(cmd.Cmd):
    def __init__(self, connection):
        cmd.Cmd.__init__(self)
        self.connection = connection

    def do_list(self, line: str):
        self.connection.send(FunctionListRequest())

    def do_add(self, line: str) -> None:
        args = line.split()

        # 1 add 0 test ../examples/learningswitch.o
        if len(args) != 3:
            print("invalid")
            return
        
        index, name, path = args

        if not os.path.isfile(path):
            print('Invalid file path')
            return

        with open(path, 'rb') as f:
            elf = f.read()
            self.connection.send(FunctionAddRequest(name=name, index=int(index), elf=elf))

    def do_remove(self, line: str) -> None:
        self.connection.send(FunctionRemoveRequest(index=int(line)))

    def do_table(self, line: str) -> None:
        args = line.split(maxsplit=1)

        if len(args) == 0:
            cmd.Cmd.default(self, line)
        else:
            try:
                function_id = int(args[0], 16)

                SwitchTablesCli(self.connection, function_id).onecmd(args[1] if len(args) > 1 else '')
            except ValueError:
                cmd.Cmd.default(self, line)

    def emptyline(self):
         self.do_help(None)

class MainCLI(cmd.Cmd):
    def __init__(self, application):
        cmd.Cmd.__init__(self)
        self.application = application

    def preloop(self):
        print(banner)
        self.do_help(None)

    def default(self, line):
        args = line.split()

        if len(args) == 0:
            cmd.Cmd.default(self, line)
        else:
            try:
                dpid = int(args[0], 16)

                if dpid in self.application.connections:
                    SwitchCLI(self.application.connections[dpid]).onecmd(' '.join(args[1:]))
                else:
                    print(f'Switch with dpid {dpid} is not connected.')
            except ValueError:
                cmd.Cmd.default(self, line)

    def do_connections(self, line):
        tabulate([ ('{:08X}'.format(k), c.version, c.connected_at) for k,c in self.application.connections.items() ], headers=['dpid', 'version', 'connected at'])
        
    def initialize():
        print(f'Installing SGSim orchestration functions...')
        if(len(self.application.connections)): 
            print(f'All networking device connected. ')
            with open('../examples/learningswitch.o', 'rb') as f:
                print("Installing forwarding services...")
                elf = f.read()
                
                self.application.connections[1].send(FunctionAddRequest(name="goose_analyser", index=0, elf=elf))#
                
                self.application.connections[1].send(FunctionAddRequest(name="learningswitch", index=1, elf=elf)) #
                print("All forwarding services installed...")                                           

    def emptyline(self):
         pass

    # def do_EOF(self, line):
    #     return True

class eBPFCLIApplication(eBPFCoreApplication):
    """
        Controller application that will start a interactive CLI.
    """
    def run(self):
        Thread(target=reactor.run, kwargs={'installSignalHandlers': 0}).start()

        try:
            MainCLI(self).cmdloop()
        except KeyboardInterrupt:
            print("\nGot keyboard interrupt. Exiting...")
        finally:
            reactor.callFromThread(reactor.stop)
            
    def get_str_values(value): 
        #print(int.from_bytes(bytes.fromhex(str(value.hex())[:8]), byteorder="little")) # Bytes 
        #print(int.from_bytes(bytes.fromhex(str(value.hex())[-8:]), byteorder="little")) # Packets 
        value_bytes = int.from_bytes(bytes.fromhex(str(value.hex())[:8]), byteorder="little") 
        value_packets = int.from_bytes(bytes.fromhex(str(value.hex())[-8:]), byteorder="little")
        #print(str(value_packets) + "," + str(value_bytes))
        return str(value_packets) + "," + str(value_bytes)

    @set_event_handler(Header.TABLES_LIST_REPLY)
    def tables_list_reply(self, connection, pkt):
        tabulate([ (e.table_name, TableDefinition.TableType.Name(e.table_type), e.key_size, e.value_size, e.max_entries) for e in pkt.entries ], headers=['name', 'type', 'key size', 'value size', 'max entries'])

    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        entries = []
    

        
        if pkt.entry.table_type in [TableDefinition.HASH, TableDefinition.LPM_TRIE]:
            item_size = pkt.entry.key_size + pkt.entry.value_size
            fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

            for i in range(pkt.n_items):
                key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
                entries.append((key.hex(), value.hex()))
                
        if pkt.entry.table_name == "goose_analyser":
            self.goose_analyser_list(connection.dpid, pkt) # Collecting data for GOOSE Analyser
            return
            
        if pkt.entry.table_name == "performance_monitor":
            self.performance_monitor_list(connection.dpid, pkt) # Collecting data for performance monitoring
                


        elif pkt.entry.table_type == TableDefinition.ARRAY:
            item_size = pkt.entry.value_size
            fmt = "{}s".format(pkt.entry.value_size)

            for i in range(pkt.n_items):
                value = struct.unpack_from(fmt, pkt.items, i * item_size)[0]
                entries.append((i, value.hex()))
        

        tabulate(entries, headers=["Key", "Value"])

    @set_event_handler(Header.TABLE_ENTRY_GET_REPLY)
    def table_entry_get_reply(self, connection, pkt):
        tabulate([(pkt.key.hex(), pkt.value.hex())], headers=["Key", "Value"])
        print()
        
        
    def performance_monitor_list(self, connection, pkt):

        
        entries = {}
        packets = {}
        
        item_size = pkt.entry.key_size + pkt.entry.value_size
        fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)
      
        print('!!!!!!!!!!!Checking packets!!!!!!!!!!!')
        
        total_entries = round(len(pkt.items) / item_size)  # Assuming each entry is of fixed size
        for i in range(total_entries):
            key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
            #entries.append((key.hex(), value.hex()))   
            entries[i] = str(value.hex())#{str(key.hex()) : eBPFCLIApplication.get_str_values(value)} # str(value.hex()
            #entries = bytes.fromhex(entries)
            packets[i] = entries[i]

            
            print('CHECKINGGGGGGG')#,packets)

            MonitorData = str(packets[i])  # Convert the data to hex for easier manipulation
            #GOOSEData = pkt.data.hex()  # Convert the data to hex for easier manipulation
            print("THE DATA RETRIEVED IS", MonitorData)   
           # Define the split points (based on the given lengths)
            split1 = 8  # 
            print("Performance Analyser")

            start_sec, right = MonitorData[:split1], MonitorData[split1:]
            end_sec, right = right[:split1], right[split1:]
            start_nsec, right = right[:split1], right[split1:]
            end_nsec = right 
            
       # start_sec, start_nsec, end_sec, end_nsec = struct.unpack('<IIII', pkt.data)

            start = int(start_sec,16) * 10**9 + int(start_nsec,16)
            end = int(end_sec,16) * 10**9 + int(end_nsec,16)
            
            print('start', int(start_sec,16))
            print('end', int(end_sec,16))
            print('start', int(start_nsec,16))
            print('end', int(end_nsec,16))
          
            TimeComplexity = ((end- start)/10**6)
        
            print('time complexity at ebpf', TimeComplexity)
            #out.write('{} \n'.format((end - start)/10**6))#94e4bd67  94e4bd67  febd3623 febd3623
        
    def goose_analyser_list(self, connection, pkt):
        #os.system('clear')
        #entries = []
        start1=time.time()
        entries = {}
        packets = {}
        
        item_size = pkt.entry.key_size + pkt.entry.value_size
        fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

        print("GOOSE Analyser")
        total_entries = round(len(pkt.items) / item_size)  # Assuming each entry is of fixed size
        for i in range(total_entries):
            key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
            #entries.append((key.hex(), value.hex()))   
            entries[i] = str(value.hex())#{str(key.hex()) : eBPFCLIApplication.get_str_values(value)} # str(value.hex()
            #entries = bytes.fromhex(entries)
            packets[i] = entries[i]

            
            print('CHECK point!!')#,packets)

            GOOSEData = str(packets[i])  # Convert the data to hex for easier manipulation
            ##################################################################################
            end1=time.time()
            ####################################################################################		
            #GOOSEData = pkt.data.hex()  # Convert the data to hex for easier manipulation
            print("THE DATA RETRIEVED IS", GOOSEData)   
            
            startP=time.time()
           # Define the split points (based on the given lengths)
            split1 = 2  # For state
            split2 = 2  # For sqnum
            split3 = 16 # For Timestamp (this could be adjusted depending on your data)
            split6 = 8# For data3
  

           # Extract the individual pieces of data from GOOSEData
            Timestamp, right = GOOSEData[:split3], GOOSEData[split3:]
            state, right = right[:split1], right[split1:]
            sqnum, right = right[:split2], right[split2:]
            data1, right = right[:split6], right[split6:]
            data2, right = right[:split6], right[split6:]
            data3, right = right[:split6], right[split6:]
            data4, right = right[:split6], right[split6:]
            data5, right = right[:split6], right[split6:]
            data6, right = right[:split6], right[split6:]
            data7, right = right[:split6], right[split6:]
            data8, right = right[:split6], right[split6:]
            #data9, right = right[:split6], right[split6:]
            label_g, right = right[:split6], right[split6:]
            classification_result_g,right = right[:split1], right[split1:]
        



        def hex_to_floats(hex_string, precision='float64'):
            """Convert a 128-bit hex string to a list of floating-point values.

            Args:
                 hex_string (str): 32-character hex string (128 bits).
                 precision (str): 'float32' (default, 4 floats) or 'float64' (2 floats).

            Returns:
                 tuple: Decoded floating-point values.
                 """
            # Ensure the input is valid
            if len(hex_string) !=8:
                  raise ValueError(f"Expected a multiple of 8(64 bits), got {len(hex_string)}")

             # Convert hex string to bytes
            bytes_value = bytes.fromhex(hex_string)

    # Determine unpack format
            format_map = {
              'float32': '!4f',  # 4 IEEE 754 single-precision floats (each 4 bytes)
              'float64': '!2d'   # 2 IEEE 754 double-precision floats (each 8 bytes)
            }

            if precision not in format_map:
               raise ValueError("Invalid precision. Choose 'float32' or 'float64'")

    # Unpack bytes into floats
            return struct.unpack(format_map[precision], bytes_value)


          
        def hex_to_float2(hex_value):
            bytes_value = bytes.fromhex(hex_value)  # Convert hex string to bytes
            return struct.unpack('!f', bytes_value)[0]  

        # Convert data fields into float (if needed, such as data1, data2, etc.)
        data1_float = hex_to_float2(data1)
        data2_float = hex_to_float2(data2)
        data3_float = hex_to_float2(data3)
        data4_float = hex_to_float2(data4)
        data5_float = hex_to_float2(data5)
        data6_float = hex_to_float2(data6)
        data7_float = hex_to_float2(data7)
        data8_float = hex_to_float2(data8)
        data8_float = hex_to_float2(data8)
        #####data9_float = hex_to_float2(data9)
        label = hex_to_float2(label_g)
        
        classificaton_result = int(classification_result_g)

        def unpack_floats(data, fmt, offset=0):
               """Unpacks floating-point numbers from data starting at the specified offset"""
               return struct.unpack_from(fmt, data, offset)[0]

        
       
         # Convert hex to int
        # Print the extracted and converted data for verification
        print('State:', state)
        print('Sequence Number:', sqnum)
        print('Timestamp:', Timestamp)
        print('Data1 (float):', data1_float)
        print('Data2 (float):', data2_float)
        print('Data3 (float):', data3_float)
        print('Data4 (float):', data4_float)
        print('Data5 (float):', data5_float)
        print('Data6 (float):', data6_float)
        print('Data7 (float):', data7_float)
        print('Data8 (float):', data8_float)
       #####print('Data9 (float):', data9_float)
        print('Label:' , label)
        print('Classification result:', classificaton_result)
       
       #### print('Count:', count)
        ####print('Dropped Pkts', droppedPkts)
        
        endP=time.time()
        print('Retrieval time', end1-start1)
        print('Parsing time', endP-startP)

        # Initialize CSV saving
        print("Initialized data saving")
        
        startC=time.time() # classification time

        # Prepare features for prediction based on obtained data
        features = [[data1_float, data2_float, data3_float, data4_float, data5_float, data6_float, data7_float, data8_float]]#, data9_float]]


        # Predict using the trained decision tree classifier
        prediction = tree_model.predict(features)
        endC=time.time()
        tt=endC-startC
        print('Prediction time',tt)
        
        print(f"Prediction from Tree Classifier: {prediction}")

        
        with open('goose_data.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            file.seek(0, 2)
            writer.writerow([state, sqnum, Timestamp, data1_float, data2_float, data3_float, data4_float, data5_float, data6_float, data7_float, data8_float, prediction[0],label,classificaton_result])

        print("Data has been written to 'goose_data.csv'.")
        

# Assuming the event handler function as per the structure
    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        connection.send(TableListRequest(index=0, table_name="goose_analyser"))
        print(f'\n[{connection.dpid}] Received notify event {pkt.id}, data length {pkt.data}')
        
    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        connection.send(TableListRequest(index=0, table_name="performance_monitor"))
        print(f'\n[{connection.dpid}] Received notify event {pkt.id}, data length {pkt.data}')
 

    @set_event_handler(Header.PACKET_IN)
    def packet_in(self, connection, pkt):
        print(f"\n[{connection.dpid}] Received packet in {pkt.data.hex()}")

    @set_event_handler(Header.FUNCTION_LIST_REPLY)
    def function_list_reply(self, connection, pkt):
        tabulate([ (e.index or 0, e.name, e.counter or 0) for e in pkt.entries ], headers=['index', 'name', 'counter'])

    @set_event_handler(Header.FUNCTION_ADD_REPLY)
    def function_add_reply(self, connection, pkt):
        if pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_STAGE:
            print("Cannot add a function at this index")
        elif pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_FUNCTION:
            print("Unable to install this function")
        else:
            print("Function has been installed")

    @set_event_handler(Header.FUNCTION_REMOVE_REPLY)
    def function_remove_reply(self, connection, pkt):
        if pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_STAGE:
            print("Cannot remove a function at this index")
        else:
            print("Function has been removed")

#if __name__ == '__main__':
eBPFCLIApplication().run()
