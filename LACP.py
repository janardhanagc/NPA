import pytz
import os.path
import scapy.all as scapy

import LacPdu
import Lacp_selection
from LacPdu import *
import Lacp_Rx_Tx_Sm
import Lacp_MUX
from NPA import NPA
from Interface import *
from pcapfile import savefile
import logging as log

class LacpNPA(NPA):

    def __init__(self):
        self.pcap_file = ''
        self.time_zone = ''
        self.interfaces = []    # list of objects of type LacpInterfaces
        self.detailed = False     # used in Rx_Tx machine packet jitter calculation
        self.hosts = []         # list of tuples having each host information

    def take_input(self, cnfg):
        # cnfg format
        # 0 pcap path
        # 1 protocol
        # 2 time zone
        # 3 detailed or not
        # 4 agent count
        # 5 list of agents in tuple form

        self.pcap_file = cnfg[0][cnfg[0].rfind(' ')+1:-1]      # considering string after space character till newline
        if os.path.exists(self.pcap_file) is False:
            print('Input pcap file does not exist')
            exit(0)
        self.time_zone = cnfg[2][cnfg[2].rfind(' ')+1:-1]
        if self.time_zone not in list(pytz.all_timezones_set):
            print('Invalid Timezone, processing in Asia/Kolkata Timezone')
            self.time_zone = 'Asia/Kolkata'
        self.detailed = bool(int(cnfg[3][cnfg[3].rfind(' ')+1:-1]))  # 0 or 1 only
        interface_count = int(cnfg[4][cnfg[4].rfind(' ')+1:-1])
        # host is tuple, in format (mac, partnerMac, port, partnerPort)
        self.hostEthMacs = []  # list of MAC IDs of hosts

        count = 0
        while count < interface_count:
            user_entry = cnfg[count+5]
            user_entry_mac = user_entry[user_entry.find("'")+1:user_entry.find("'", user_entry.find("'")+1)]
            [flag, mac] = is_valid_mac(user_entry_mac)
            if flag is False:
                print('You have entered Actor ethernet MAC in invalid format')
                print('You entered', user_entry_mac, 'and the interface is removed from analysis')
                count = count + 1
                continue
            user_entry = user_entry[user_entry.find(',')+1:]   # actor mac removed from line reading
            host = (mac,)
            user_entry_pmac = user_entry[user_entry.find("'")+1:user_entry.find("'", user_entry.find("'")+1)]
            if len(user_entry_pmac) != 0:
                [flag, mac] = is_valid_mac(user_entry_pmac)
            if flag is True:
                mac = (mac, )
                host = host + mac
            else:
                print('You have entered Partner Ethernet MAC -', user_entry_pmac, ' in invalid format and is ignored')
                host = host + tuple(" ")

            user_entry = user_entry[user_entry.find(',') + 1:]  # partner mac removed from line reading
            user_entry_port = user_entry[user_entry.find("'")+1:user_entry.find("'", user_entry.find("'")+1)]
            [flag, port] = is_valid_port(user_entry_port)
            if flag is True:
                port = (port, )
                host = host + port
            else:
                print('You have entered Actor port number-', user_entry_port,' in invalid format and is ignored')
                host = host + tuple(" ")

            user_entry = user_entry[user_entry.find(',') + 1:]  # actor port removed from line reading
            user_entry_par_port = user_entry[user_entry.find("'")+1:user_entry.find("'", user_entry.find("'")+1)]
            [flag, port] = is_valid_port(user_entry_par_port)
            if flag is True:
                port = tuple(port, )
                host = host + port
            else:
                print('You have entered Partner port number-',user_entry_par_port,' in invalid format and is ignored')
            self.hosts.append(host)
            count = count + 1

        for host in self.hosts:
            self.interfaces.append(LacpInterface(host))
        for host in self.hosts:
            self.hostEthMacs.append(host[0])

    def run_analyzer(self, cnfg):
        self.take_input(cnfg)
        tz = pytz.timezone(self.time_zone)
        pkts = scapy.rdpcap(self.pcap_file)
        log.debug("Reading file - {}".format(self.pcap_file))
        log.debug("Processing in interfaces {} perspective".format(self.hostEthMacs))
        testcap = open(self.pcap_file, 'rb')
        capfile = savefile.load_savefile(testcap, verbose=True)

        index = 0
        for pkt in pkts:
            pkt_time = capfile.packets[index].timestamp_us * pow(10, -6) + capfile.packets[index].timestamp
            Lacp_Rx_Tx_Sm.run_rx_tx_sm(index, pkt, pkt_time, self.interfaces, self.hostEthMacs, self.detailed, tz)
            Lacp_selection.run_selection_logic(pkt, index, self.interfaces)
            Lacp_MUX.run_mux_machine(index, pkt, pkt_time, self.hostEthMacs, self.interfaces)
            index = index+1
            for batch in range(1, 20):    # total packets are split into 20 batches
                if index == len(pkts)//20*batch:
                    print("{ind:5d} packets processed".format(ind=index))
        print('All packets processed')
        print('Total', len(LacPdu.LACP_indices), 'LACP packets found out of', len(pkts), 'packets in pcap file')
        log.debug('LACP indices are\n{}'.format(LacPdu.LACP_indices))  # will be useful for post analysis


