from Lacp_MUX import MuxMachine


class Interface:
    def __init__(self, mac, last_sent_time=0, last_received_time=0):
        self.mac = mac
        self.last_sent_time = last_sent_time
        self.last_received_time = last_received_time
        self.last_pkt_tx = ''
        self.last_pkt_rx = ''

    # Return the interface from interfaces list which has same mac address
    @staticmethod
    def find_interface_from_mac(interfaces, mac):
        for interface in interfaces:
            if mac == interface.mac:
                return interface
        return None


class LacpInterface(Interface):

    def __init__(self, host):
        attributes = dict({'mac': '', 'partnerMac': '', 'port': '', 'partnerPort': ''})
        self.port = ''
        self.partnerMac = ''
        self.partnerPort = ''
        super().__init__(host[0])
        for index in range(1, len(host)):
            setattr(self, list(attributes.keys())[index], host[index])
        self.actor_timeout = 1
        self.partner_timeout = 1
        self.mux_sm = MuxMachine()
        self.selected = 'UNSELECTED'
        self.tx_timeout_buffer = -3
        self.rx_timeout_buffer = -3

    # Return the interface from interfaces list which has same port number
    @staticmethod
    def find_actor_interface(interfaces, actor_port, sender):
        for interface in interfaces:
            if interface.partnerMac == ' ':     # for first packet received when partnerMac not available
                if actor_port == interface.port:
                    return interface
            elif interface.partnerMac == sender:  # from second packet onwards, port number may change
                return interface
        return None

    def get_interface_details(self):
        attributes = ['mac', 'port', 'partnerMac', 'last_sent_time', 'last_received_time', 'actor_timeout',
                      'partner_timeout', 'actor_state', 'partner_state']
        interface = {'mac': self.mac, 'port': self.port, 'partnerMac': self.partnerMac, 'partnerPort': self.partnerPort,
                                      'last_sent_time': self.last_sent_time, 'last_received_time': self.last_received_time,
                                      'actor_timeout': self.actor_timeout, 'partner_timeout': self.partner_timeout,
                                      'actor_state': self.mux_sm.actor_state, 'partner_state': self.mux_sm.partner_state}
        return interface
