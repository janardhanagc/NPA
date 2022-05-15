import scapy.all as scapy
import logging as log

LACPDU = {"Destination_Address": [6,6,'01 80 C2 00 00 02'],
              "Source_Address": [6,12],
              "type": [2,14,'88 09'],
              "subtype": [1,15,'01'],
              "Version_number": [1,16,'01'],
              "Actor_TLV_type": [1,17,'01'],
              "Actor_information_length": [1,18,'14'],
              "Actor_system_priority": [2,20,],
              "Actor_system": [6,26],
              "Actor_key": [2,28],
              "Actor_port_priority": [2,30],
              "Actor_port": [2,32],
              "Actor_state": [1,33],
              "Actor_Reserved": [3,36],
              "Partner_TLV_type": [1,37,'02'],
              "Partner_information_length": [1,38,'14'],
              "Partner_system_priority": [2,40],
              "Partner_system": [6,46],
              "Partner_key": [2,48],
              "Partner_port_priority": [2,50],
              "Partner_port": [2,52],
              "Partner_state": [1,53],
              "Partner_Reserved": [3,56],
              "Collector_TLV_type": [1,57,'03'],
              "Collector_information_length": [1,58,'10'],
              "CollectorMaxDelay": [2,60],
              "Collector_Reserved": [12,72],
              "TLV_type": [1,73],
              "Terminator_length": [1,74],
              "Reserved": [50,124],
              #"FCS": 4
        }
#
# State_fields=["LACP_Activity","LACP_Timeout","Aggregation","Synchronization","Collecting","Distributing",
#               "Defaulted","Expired"]

State_fields=["activity","time_out","aggregation","synchronization",
              "collecting","distributing","defaulted","expired"]
state_values={'activity':['passive','active'],'time_out':['long','short'],'aggregation':['individual','aggregatable'],
              'synchronization':['Out of sync','In sync'],'collecting':['disabled','enabled'],
              'distributing':['disabled','enabled'],'defaulted':['No','Yes'],'expired':['No','Yes']}

agent_keys = ['system_priority', 'system', 'key', 'port_priority', 'port']

def get_PDU(pkt):
    PDU={}
    printed = 0
    pkt = scapy.hexstr(pkt)
    if (pkt[36:42] == '81 00 '):  # ignoring 802.1q header
        pkt = pkt[:37] + pkt[49:372]
    else:
        pkt = pkt[:372]

    for j in LACPDU:
        PDU.update({j: pkt[printed:printed + LACPDU[j][0] * 3 - 1]})
        printed = printed + LACPDU[j][0] * 3
    return PDU


def print_PDU_info(pkt):  # p means packet
    PDU=get_PDU(pkt)
    for j in PDU:
        print(j,": ",PDU[j])


def get_actor_state(pkt):
    state=get_PDU(pkt)['Actor_state']
    state=str(bin(int(state,16)))[2:].zfill(8)
    state=state[::-1]
    actor_state={}
    for bit in range(8):
        actor_state.update({State_fields[bit]:int(state[bit])})
    return actor_state


def get_partner_state(p):
    state = get_PDU(p)['Partner_state']
    state = str(bin(int(state, 16)))[2:].zfill(8)
    state = state[::-1]     # reversing string
    partner_state = {}
    for bit in range(8):
        partner_state.update({State_fields[bit]:int(state[bit])})
    return partner_state


def print_actor_state(p):
    state = get_actor_state(p)
    for bit in state:
        print(bit, ':', state_values[bit][state[bit]])


def print_partner_state(p):
    state = get_partner_state(p)
    for bit in state:
        print(bit, ':', state_values[bit][state[bit]])


def get_src_eth_mac(p):
    p=scapy.hexstr(p)
    p=p[6*3:6*3+17]
    return p


def get_info_of(agent, pkt):   # agent can be partner or actor
    # keys = ['system_priority', 'system', 'key', 'port_priority', 'port']
    PDU = get_PDU(pkt)
    agent_info = dict()
    agent = agent + '_'     # to match with actual PDU keys
    for each in agent_keys:  # global variable agent_keys
        agent_info.update({agent+each: PDU[agent+each]})
    return agent_info


def validate_packet(p):
    flag = True
    if (get_PDU(p)['type']!= '88 09'):
        #log.debug("Protocol type is not '0x8809', but '0x{}'".format(get_PDU(p)['type']))
        flag = False

    if (get_PDU(p)['subtype']!= '01'):
        #log.debug("Protocol subtype is not '01', but '{}'".format(get_PDU(p)['subtype']))
        flag = False

    if (get_PDU(p)['Version_number']!= '01'):
        #log.debug("Protocol version number is not '01', but '{}'".format(get_PDU(p)['Version_number']))
        flag = False

    if(get_PDU(p)['Actor_TLV_type']!='01'):
        #log.debug("Actor_TLV_type is not '01', but '{}'".format(get_PDU(p)['Actor_TLV_type']))
        flag=False

    if (get_PDU(p)['Actor_information_length']!= '14'):
        #log.debug("Actor_information_length is not '0x14', but '0x{}'".format(get_PDU(p)['Actor_information_length']))
        flag = False

    if (get_PDU(p)['Partner_TLV_type']!= '02'):
        #log.debug("Partner_TLV_type is not '0x02', but '{}'".format(get_PDU(p)['Partner_TLV_type']))
        flag = False

    if (get_PDU(p)['Partner_information_length']!= '14'):
        #log.debug("Partner_information_length is not '0x14', but '0x{}'".format(get_PDU(p)['Partner_information_length']))
        flag = False

    return flag


prev_index = -1
LACP_indices = list()


def is_of_interest(pkt, index, interfaces):
    global LACP_indices, prev_index
    if validate_packet(pkt) is False:
        #log.debug("Packet no. : {} - Not valid LACP packet to process further, packet ignored".format(index+1))
        return False

    if index != prev_index:
        LACP_indices.append(index+1)
        prev_index = index
    for interface in interfaces:
        if get_src_eth_mac(pkt) == interface.mac:
            return True
        elif get_PDU(pkt)['Partner_port'] == interface.port and interface.port != '':
            return True
        elif get_src_eth_mac(pkt) == interface.partnerMac and interface.partnerMac != '':
            return True
    #log.debug("Packet no. : {} is of not interest, packet ignored".format(index+1))
    return False


def is_valid_mac(mac):
    if len(mac) >= 3:
        remove = mac[2]
    else:
        return [False, '']
    characters = mac.replace(remove, "")
    characters = list(characters)
    valid_mac = ''
    for char in characters:
        if char.isdigit():
            valid_mac = valid_mac+str(char)
        elif char.isalpha():
            char = char.upper()
            if char in ['A', 'B', 'C', 'D', 'E', 'F']:
                valid_mac = valid_mac + char
            else:
                return [False, '']
        else:
            return [False, '']
    if len(valid_mac) != 12:
        return [False, '']

    characters = list(valid_mac)
    index = 0
    valid_mac = ''
    while index != 12:
        valid_mac = valid_mac + characters[index]
        valid_mac = valid_mac + characters[index+1]
        valid_mac = valid_mac + str(' ')
        index = index+2
    valid_mac = valid_mac[:-1]
    return [True, valid_mac]


def is_valid_port(port):
    if len(port) > 3:
        remove = port[2]
    else:
        return [False, port]

    characters = port.replace(remove, "")
    characters = list(characters)
    valid_port = ''
    for char in characters:
        if char.isdigit():
            valid_port = valid_port + str(char)
        elif char.isalpha():
            char = char.upper()
            if char in ['A', 'B', 'C', 'D', 'E', 'F']:
                valid_port = valid_port + char
            else:
                return [False, '']
        else:
            return [False, '']
    if len(valid_port) != 4:
        return [False, '']

    valid_port = valid_port[:2]+" "+valid_port[2:]
    return [True, valid_port]

def pkt_info(pkt, index):
    info = 'pkt #'
    info = info+str(index+1)
    return info


