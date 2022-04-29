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

def get_PDU(p):
    PDU={}
    printed = 0
    p = scapy.hexstr(p)
    if (p[36:48] == '81 00 00 01 '):  # ignoring 802.1q header
        p = p[:37] + p[49:372]
    else:
        p = p[:372]

    for j in LACPDU:
        PDU.update({j:p[printed:printed + LACPDU[j][0] * 3 - 1]})
        printed = printed + LACPDU[j][0] * 3
    return PDU

def print_PDU_info(p): # p means packet
    PDU=get_PDU(p)
    for j in PDU:
        print(j,": ",PDU[j])

def get_actor_state(p):
    state=get_PDU(p)['Actor_state']
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
    partner_state={}
    for bit in range(8):
        partner_state.update({State_fields[bit]:int(state[bit])})
    return partner_state


def print_actor_state(p):
    state=get_actor_state(p)
    for bit in state:
        print(bit,':',state_values[bit][state[bit]])

def print_partner_state(p):
    state = get_partner_state(p)
    for bit in state:
        print(bit, ':', state_values[bit][state[bit]])

def get_sender_address(p):
    p=scapy.hexstr(p)
    if (p[36:48] == '81 00 00 01 '):  # ignoring 802.1q header
        p = p[:37] + p[49:372]
    p=p[6*3:6*3+17]
    return p

def validate_packet(p):
    flag=True

    if (get_PDU(p)['type']!= '88 09'):
        log.error('Protocol type is modified to {}'.format(get_PDU(p)['type']))
        flag = False

    if (get_PDU(p)['subtype']!= '01'):
        log.error('Protocol subtype is modified to {}'.format(get_PDU(p)['subtype']))
        flag = False

    if (get_PDU(p)['Version_number']!= '01'):
        log.error('Protocol version number is modified to {}'.format(get_PDU(p)['Version_number']))
        flag = False

    if(get_PDU(p)['Actor_TLV_type']!='01'):
        log.error('Actor_TLV_type is modified to {}'.format(get_PDU(p)['Actor_TLV_type']))
        flag=False

    if (get_PDU(p)['Actor_information_length']!= '14'):
        log.error('Actor_information_length is modified to {}'.format(get_PDU(p)['Actor_information_length']))
        flag = False

    if (get_PDU(p)['Partner_TLV_type']!= '02'):
        log.error('Partner_TLV_type is modified to {}'.format(get_PDU(p)['Partner_TLV_type']))
        flag = False

    if (get_PDU(p)['Partner_information_length']!= '14'):
        log.error('Partner_information_length is modified to {}'.format(get_PDU(p)['Partner_information_length']))
        flag = False
    return flag



