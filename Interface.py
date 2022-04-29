from Lacp_MUX import MuxMachine


class Interface:

    def __init__(self,mac,last_sent_time=0,last_received_time=0):
        self.mac = mac
        self.last_sent_time=last_sent_time
        self.last_received_time=last_received_time
        self.last_pdu_tx = dict()
        self.last_pdu_rx = dict()

    #Return the interface from interfaces list which has same mac address
    @staticmethod
    def find_interface_from_mac(interfaces, mac):
        for interface in interfaces:
            if mac == interface.mac:
                return interface
        return None

class LacpInterface(Interface):

    def __init__(self,mac,port=' '):
        super().__init__(mac)
        self.port = port
        self.actor_state = dict()
        self.partner_state = dict()
        self.actor_timeout = 1
        self.partner_timeout = 1
        self.mux_sm = MuxMachine()
        self.defaulted = True
        self.Rx_warned=False

    # Return the interface from interfaces list which has same port number
    @staticmethod
    def find_interface_from_port(interfaces, port):
        for interface in interfaces:
            if port == interface.port:
                return interface
        return None
