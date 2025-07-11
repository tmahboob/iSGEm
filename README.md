Main BPFabric guide
(https://github.com/UofG-netlab/BPFabric/wiki/Running%20BPFabric)

# iSGEm - NetLab
Contributor:
- Dr. Tahira Mahboob (tahira.mahboob@glasgow.ac.uk)
- University of Glasgow March 2025


************************************************************************************
//Experiment1: FDI detection on Power Systems State Estimations on Smart Grids

*************************************************************************************
CONTRIBUTIONS:

* Modbus TCP client/server traffic simulation, read multiple registers
* Industrial commodity hardware--based test setup
* Modelling a statistical FDI attack on PSSE
* Bad data detection
* Variational decomposition mode (VMD) based Intrinsic mode function--feature extraction via eBPF and non-eBPF functions
* Scapy-based Modbus TCP payload parsing
* LSTM Encoder Decoder implementation
* FDI mitigation on PSSE
* Non-eBPF and eBPF function chaining


//configuration: Modbus TCP server on raspberry_pi1(enp2s0),  Modbus TCP client on raspberry_pi2(enp3s0), CPN node (controller, scripts, uNFs installed on switch, non-ebpf function on dataplane processing pipeline)

//Requirements:
*Linux lite 7.4 24.04 codename noble x86_64 GNU/Linux on CPN nodekernel 6.8.0-60-generic
*clang ver 18.1.3 thread posix
*python 3.12.3
*use sudo for wireshark and commands, su not supported

*pip install vmdpy or GitHub lone https://github.com/vrcarv/vmdpy.git
% may need to run in virtual environment and file vmdp.py file in project folder where sniffer/modbusparser/fdi detection scripts are placed

*pip install tensorflow
*pip install scikit-learn

1. Run the simulation to generate system state [V_b, I_b]

2. Execute the Modbus TCP server script at raspberry pi1
setup virtual environment on raspberry pi:
python -m venv myenv
source myenv/bin/activate
sudo /myenv/bin/python ModbusClient_271.py

3. Setup the CPN node (Protecli or Topton N100 mini PC)
	        sudo ip link add veth1 type veth peer name veth2
		sudo ip link add veth3 type veth peer name veth4
		sudo ip link set dev veth1 up
                sudo ip link set dev veth2 up
                sudo ip link set dev veth3 up
                sudo ip link set dev veth4 up

4. Setup the epbf_softswitch on interfaces
sudo ~/BPFabric/softswitch/softswitch --dpid=1 --controller="127.0.0.1:9000" --promiscuous veth1 veth3 enp2s0 enp3s0 enp4s0
%enp2s0=raspberry_pi1(Modbus TCP server) enp3s0=respberry_pi2(Modbus TCP client)  

4.Setup the controller: 'cd BPFabric/controller  
./cli.py' %Brokeragent.py

5.Install script on the CPN switch: 
 1 add 0 modbus_fwd ../examples/modbus_fwd.o 

6. Execute non-ebpf function 'FDI mitigator' at the CPN node in examples folder: cd BPFabric/examples
python -m venv myenv
source myenv/bin/activate
sudo /myenv/bin/python Modbus_fwd_parser_fdi.py


7. Execute code on the raspberry_pi2
setup virtual environment on raspberry pi:
python -m venv myenv
source myenv/bin/activate
sudo /myenv/bin/python Modbus_server3.py


************************************************************************************
#//Experiment 2: FDI detection on GOOSE 61850 measurements
June 19, 2025 update
Cite: Tahira Mahboob, Filip Holik, Awais Aziz Shah, and Dimitrios Pezaros, "Adaptive Learning Feature Quantization for In-network FDI Detection in IEC 61850 Digital Substations", accepted for publication, SmartGridComm'25 conference, Sep 29-Oct 2, 2025 Canada.
************************************************************************************
//configuration: GOOSE publisher VM on laptop(enp4s0), GOOSE subscriber raspberry_pi1(enp2s0), CPN node (controller, scripts, uNFs installed on switch,ebpf functions on dataplane processing pipeline)

//Requirements:
-Linux lite 7.4 24.04 codename noble x86_64 GNU/Linux on CPN nodekernel 6.8.0-60-generic
-clang ver 18.1.3 thread posix
-python 3.12.3
%use sudo for wireshark and commands, su not supported


//--- Softswitch
sudo ~/BPFabric/softswitch/softswitch --dpid=1 --controller="127.0.0.1:9000" --promiscuous enp2s0 enp3s0 enp4s0

// --- Controller
 ~/BPFabric/controller/cli.py
1 add 0 FDI ../examples/fdiDT.o %GOOSE payload FDI detection

//Execution steps

Step 1: 
a. Setup goose traffic generator VM:
-Network setting->Bridged adaptor, allow all VMs, IP: 10.0.0.5/8

b. Generate GOOSE traffic using libiec61850-1.5.1 library. Goto folder '/mininet/libiec61850-1.5.1/examples/goose_publisher/' containing this library
./CSVG enp2s0 XTest.csv % GOOSE payload data via simulation or csv file of features V and I measurement data 8 features



# Experimentation:
- Run the broker agent at the command line: python3 broker_agent.py
- Run the mininet topology: python3 3sw_ctopo.py
- xterm on host: xterm h1
- setup wireshark on host interface
- Run: ./IEC61850-1.5.1 *.csv % GOOSE traffic
  Observe command line to view parsed traffic and execution times
- Run: MetricsExtractor.csv %extract machine learning metrics
  

![Experimental Setup](https://github.com/tmahboob/iSGEm/blob/main/experimentalsetup.jpg)
An intelligent programmable data plane leveraging BPFabric

Follow first example: A machine learning based FDI detection and mitigation on GOOSE traffic in IEC 61850 Digital secondary substation environment
# Example: ML micro functions added in folder "examples"
-     eBPF-based Decision Tree mitigator micro service
-     eBPF-based Random Forest detection micro service
  
# Example: Broker agent at "\controller\core" folder
-    Userspace based FDI detection using Decision Tree and Random Forest 


Main BPFabric guide (https://github.com/UofG-netlab/BPFabric/wiki/Running%20BPFabric)

Contributor: Dr. Tahira Mahboob, tahira.mahboob@yahoo.com University of Glasgow, Scotland, UK

******************************************************************************
//Experiment1: FDI detection on Power Systems State Estimations on Smart Grids
******************************************************************************


CONTRIBUTIONS:
#Modbus TCP client/server traffic simulation, read multiple registers
#Industrial commodity hardware--based test setup
#Modelling a statistical FDI attack on PSSE
#Bad data detection
#Variational decomposition mode (VMD) based Intrinsic mode function--feature extraction via eBPF and non-eBPF functions
#Scapy-based Modbus TCP payload parsing
#LSTM Encoder Decoder implementation
#FDI mitigation on PSSE
#Non-eBPF and eBPF function chaining
******************************************************************************

//configuration: Modbus TCP server on raspberry_pi1(enp2s0), Modbus TCP client on raspberry_pi2(enp3s0), CPN node (controller, scripts, uNFs installed on switch, non-ebpf function on dataplane processing pipeline)

//Requirements: -Linux lite 7.4 24.04 codename noble x86_64 GNU/Linux on CPN nodekernel 6.8.0-60-generic -clang ver 18.1.3 thread posix -python 3.12.3 %use sudo for wireshark and commands, su not supported

-pip install vmdpy or GitHub lone https://github.com/vrcarv/vmdpy.git % may need to run in virtual environment and file vmdp.py file in project folder where sniffer/modbusparser/fdi detection scripts are placed

-pip install tensorflow -pip install scikit-learn

Run the simulation to generate system state [V_b, I_b]

Execute the Modbus TCP server script at raspberry pi1 setup virtual environment on raspberry pi: 

python -m venv myenv source 
myenv/bin/activate 
sudo /myenv/bin/python ModbusClient_271.py

#Setup the CPN node (Protecli or Topton N100 mini PC) 
sudo ip link add veth1 type veth peer name veth2 
sudo ip link add veth3 type veth peer name veth4 
sudo ip link set dev veth1 up sudo ip link set dev veth2 up 
sudo ip link set dev veth3 up sudo ip link set dev veth4 up

#Setup the epbf_softswitch on interfaces 
sudo ~/BPFabric/softswitch/softswitch --dpid=1 --controller="127.0.0.1:9000" --promiscuous veth1 veth3 enp2s0 enp3s0 enp4s0 
%enp2s0 raspberry_pi1(Modbus TCP server) enp3s0=respberry_pi2(Modbus TCP client)

4.Setup the controller: 'cd BPFabric/controller
./cli.py' %Brokeragent.py

5.Install script on the CPN switch: 1 add 0 modbus_fwd ../examples/modbus_fwd.o

#Execute non-ebpf function 'FDI mitigator' at the CPN node in examples folder: 
cd BPFabric/examples python -m venv myenv source 
myenv/bin/activate 
sudo /myenv/bin/python Modbus_fwd_parser_fdi.py

#Execute code on the raspberry_pi2 setup virtual environment on raspberry pi: 
python -m venv myenv source myenv/bin/activate sudo /myenv/bin/python Modbus_server3.py

********************END: BPFabric eBPF Modbus experiment**********************



******************************************************************************

SDN experiment: Setting up RYU controller, where all Modbus TCP traffic forwarded to 
the controller via openflow rules set up FDI detection and then mitigation logic 
implemented at the RYU controller
******************************************************************************

1. PacketIn from switch to controller
2. Call FDI script
2.1. Parse packets to extract feature using scapy
2.2. Create batch of packets
2.3. Pass through VMD feature extractor
2.4. Detect FDI on batch of packets
2.5. Return Classification label '1' attack, '0' normal
3. Drop packets at controller if label '1' otherwise packet_out packets via out_port ethernet port  
*********************************************************************************

# Setting up ovs rules at the switch
* Experiment
ethstats -n 2

* Open vSwitch
sudo ovs-vsctl show
ip link show

sudo ovs-vsctl del-br br0
sudo ovs-vsctl add-br br0
sudo ovs-vsctl add-port br0 enp2s0
sudo ovs-vsctl add-port br0 enp3s0
sudo ip link set dev enp2s0 up
sudo ip link set dev enp3s0 up

sudo ovs-vsctl set-controller br0 tcp:192.168.10.1:6633
(the switch is configured with 192.168.10.2) 

*RYU SDN Controller
pyenv activate ryu
cd /home/otsentry/ryu/ryu/app/
ryu-manager fdi_switch.py
(default L2 switch): ryu-manager simple_switch_13.py

More details about installation: https://heltale.com/sdn/setting_up_ryu/ 

***************END: SDN RYU controller experiment********************************

*********************************************************************************


# Experiment2: FDI detection on GOOSE 61850 measurements June 19, 2025 update 

# Cite: Tahira Mahboob, Filip Holik, Awais Aziz Shah, and Dimitrios Pezaros, "Adaptive Learning Feature Quantization for In-network 
FDI Detection in IEC 61850 Digital Substations", https://eprints.gla.ac.uk/358810/, SmartGridComm'25 conference, Sep 29-Oct 2, 2025 Canada.



* configuration: GOOSE publisher VM on laptop(enp4s0), GOOSE subscriber raspberry_pi1(enp2s0), CPN node (controller, scripts,
 uNFs installed on switch,ebpf functions on dataplane processing pipeline)

//--- Requirements: 
*Linux lite 7.4 24.04 codename noble x86_64 GNU/Linux on CPN node 
kernel 6.8.0-60-generic 
*clang ver 18.1.3 thread posix -python 3.12.3 
%use sudo for wireshark and commands, su not supported
*********************************************************************************


//--- Softswitch initialization
sudo ~/BPFabric/softswitch/softswitch --dpid=1 --controller="127.0.0.1:9000" --promiscuous enp2s0 enp3s0 enp4s0

//--- Controller ~/BPFabric/controller/cli.py 1 add 0 FDI ../examples/fdiDT.o 
%GOOSE payload FDI detection

//---Execution steps
Step 1: 
a. Setup goose traffic generator VM: -Network setting->Bridged adaptor, ->allow all VMs, IP: 10.0.0.5/8

b. Generate GOOSE traffic using libiec61850-1.5.1 library. 
Goto folder '/mininet/libiec61850-1.5.1/examples/goose_publisher/' containing this library 
>>./CSVG enp2s0 XTest.csv 
% GOOSE payload data via simulation or csv file of features V and I measurement data 8 features


******************END: GOOSE payload FDI detection****************************************************************************************

# MAIN Architecture

# BPFabric - Netlab

## Description

A programmable dataplane using the eBPF instruction set.

## Dependencies

Tested and working with

- Ubuntu 22.04.3 LTS - kernel 5.15.0-92-generic
- clang 14.0.0

## Examples

### Learning Switch

#### Description

Very simple (legacy) learning switch that learn the source mac address and
associated input port. If the port is unknown the packet is flooded.

#### How-To

Run a mininet topology and install the learningswitch.o eBPF elf to the
switches.

```zsh
# Run the mininet topology with three switches and 4 hosts
cd mininet
sudo ./3sw_topo.py
```

```zsh
# Run the interactive controller
cd controller
./cli.py
--------------------------------------------------------------------------------
    eBPF Switch Controller Command Line Interface - Netlab 2025
    Simon Jouet <simon.jouet@glasgow.ac.uk> - University of Glasgow
--------------------------------------------------------------------------------


Documented commands (type help <topic>):
========================================
help

Undocumented commands:
======================
EOF  connections

(Cmd) Connection from switch 00000001, version 1
Connection from switch 00000002, version 1
Connection from switch 00000003, version 1

(Cmd) connections

      dpid    version     connected at
==========  =========  ===============
  00000001          1    1467377575.33
  00000002          1    1467377575.37
  00000003          1     1467377575.4
==========  =========  ===============

(Cmd) 1 install ../examples/learningswitch.o
(Cmd) 2 install ../examples/learningswitch.o
(Cmd) 3 install ../examples/learningswitch.o
```

Try the connectivity in Mininet between the hosts

```zsh
mininet> pingall
*** Ping: testing ping reachability
h1 -> h2 h3 h4
h2 -> h1 h3 h4
h3 -> h1 h2 h4
h4 -> h1 h2 h3
*** Results: 0% dropped (12/12 received)
```

Analyze the tables of the switches to see the ethernet addres to port mapping

```zsh
# List the BPF tables available on switch 1
(Cmd) 1 tables
(Cmd)
     name    type    key size    value size    max entries
=========  ======  ==========  ============  =============
  inports    HASH           6             4            256
=========  ======  ==========  ============  =============

# List the entries in the inports table
(Cmd) 1 table inports list
(Cmd)
           Key       Value
==============  ==========
  000400000000    00000000
  000400000003    01000000
  000400000002    01000000
  000400000001    00000000
==============  ==========
```

### Centralized Learning Switch

#### Description

A simple centralized switch that will delegate the mac address to port mapping
to the controller if the destination is unknown.

#### How-To

Run a mininet topology and run the controller responsible to reply to the
PacketIn events from the switches.

```zsh
# Start the mininet topology
cd mininet
sudo ./3sw_topo.py
```

```zsh
# Start the controller
cd controller
./simpleswitch.py
Connection from switch 00000001, version 1
Installing the eBPF ELF
Connection from switch 00000003, version 1
Installing the eBPF ELF
Connection from switch 00000002, version 1
Installing the eBPF ELF
2 333300000002 ba776cdc9a6b 0x86dd
1 333300000002 ba776cdc9a6b 0x86dd
0 333300000002 ba776cdc9a6b 0x86dd
1 333300000002 000400000000 0x86dd
Inserting entry in switch 2  000400000000 1
[...]
```

## Building BPFabric for OpenWRT routers

More on the wiki at https://github.com/UofG-netlab/BPFabric/wiki/OpenWRT

## Issues

- Error while compiling the examples `/usr/include/linux/types.h:4:10: fatal error: 'asm/types.h' file not found`
  - `sudo ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm`
  - `sudo apt-get install g++-multilib`

## Debugging

### Disassembling eBPF

```zsh
objcopy -I elf64-little -O binary --only-section=.text program.o program.bin
ubpf/bin/ubpf-disassembler program.bin program.asm
cat program.asm
```

## Known Issues

- String relocation is not working properly. The symbol in the ELF file is not containing the offset to the string table preventing the relocation of the string.

## Authors

- Simon Jouet (simon.jouet@glasgow.ac.uk)
- Dimitrios Pezaros (dimitrios.pezaros@glasgow.ac.uk)

## Acknowledgements

- EPSRC EP/L026015/1: A Situtation-Aware Information Infrastructure
