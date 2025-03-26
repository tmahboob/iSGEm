######## Contributor: Dr. Tahira Mahboob, NetLab, University of Glasgow, UK #######
####### Code: Topology of Digital secondary substation ##############
#!/usr/bin/env python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI

from eBPFSwitch import eBPFSwitch, eBPFHost

class ThreeSwitchTopo(Topo):
    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        coreSwitch = self.addSwitch('s1', switch_path="../softswitch/softswitch")
        aggSwitch1 = self.addSwitch('s2', switch_path="../softswitch/softswitch")
        aggSwitch2 = self.addSwitch('s3', switch_path="../softswitch/softswitch")

        self.addLink(aggSwitch1, coreSwitch)
        self.addLink(aggSwitch2, coreSwitch)

        
        h1=self.addHost('h1', ip= '10.0.0.1/24', mac='00:00:00:00:aa:01')
        h2=self.addHost('h2', ip= '10.0.0.2/24', mac='00:00:00:00:aa:02')
        h3=self.addHost('h3', ip= '10.0.0.3/24', mac='00:00:00:00:aa:03')
        h4=self.addHost('h4', ip= '10.0.0.4/24', mac='00:00:00:00:aa:04')
        self.addLink(h1, aggSwitch1)
        self.addLink(h2, aggSwitch1)
        self.addLink(h3, aggSwitch2)
        self.addLink(h4, aggSwitch2)
   

       

def main():
    topo = ThreeSwitchTopo()
    net = Mininet(topo = topo, host = eBPFHost, switch = eBPFSwitch, controller = None)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()
