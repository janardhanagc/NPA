import pytz
import scapy.all as scapy

import Lacp_selection
from LacPdu import *
import Lacp_Rx_Tx_Sm
import Lacp_MUX
from main import NPA
from Interface import *
from pcapfile import savefile
import logging as log

class LacpNPA(NPA):

    def __init__(self):
        self.pcap_file = ''
        self.time_zone = ''
        self.interfaces = []
        self.detailed = True
        self.hosts = []

    def take_input(self):
        # host is tuple in format (mac, partnerMac, port, partnerPort)
        self.hosts = [('1C 6A 7A 1F 1D 7F', '', '', '')]
        #self.hosts = [('AC 3A 67 0D CC D7',)]
        self.hostEthMacs=[]
        self.pcap_file = "/Users/jgowdac/Documents/PCAP FILES/Timestamp shifted/lacp_copy_ts.pcap"
        # self.pcap_file = "/Users/jgowdac/Documents/PCAP FILES/Timestamp shifted/lacp_copy(1).pcap"
        self.time_zone = 'Asia/Shanghai'

        for host in self.hosts:
            self.interfaces.append(LacpInterface(host))
        for host in self.hosts:
            self.hostEthMacs.append(host[0])

    def run_analyzer(self):
        self.take_input()
        tz = pytz.timezone(self.time_zone)
        pkts = scapy.rdpcap(self.pcap_file)
        log.debug("Reading file - {}".format(self.pcap_file))
        testcap = open(self.pcap_file, 'rb')
        capfile = savefile.load_savefile(testcap, verbose=True)

        index = 0
        for pkt in pkts:
            pkt_time = capfile.packets[index].timestamp_us * pow(10, -6) + capfile.packets[index].timestamp
            Lacp_Rx_Tx_Sm.run_rx_tx_sm(index, pkt, pkt_time, self.interfaces, self.hostEthMacs, self.detailed, tz)
            Lacp_selection.run_selection_logic(pkt, index, self.hostEthMacs, self.interfaces)
            Lacp_MUX.run_mux_machine(index, pkt, pkt_time, self.hostEthMacs, self.interfaces)
            index=index+1
