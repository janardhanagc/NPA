import LACP_PDU_structure
import logging as log
from datetime import datetime
from Interface import *

rx_timer_list = set()   # comment - not used anywhere
tx_timer_list = set()

global TZ

periodic = {'long': 30, 'short': 1}


def timer_list_insert(timer_list, interface):
    timer_list.add(interface)


def timer_list_remove(timer_list, interface):
    timer_list.remove(interface)


def check_tx_time_out(current_time):
    to_be_removed = list()
    for interface in tx_timer_list:
        if (interface.last_sent_time != 0) and (current_time-interface.last_sent_time > 3*interface.partner_timeout):
            log.error('Tx-{} : packet not sent in last 3 timeout(3*{}s)'.format(interface.mac, interface.partner_timeout))
            log.info('Tx-{} : previous packet sent at {}, current time is {}'.format(interface.mac,
                                                    ts_to_str(interface.last_sent_time), ts_to_str(current_time)))
            to_be_removed.append(interface)

        elif (interface.last_sent_time != 0) and (current_time-interface.last_sent_time > 2*interface.partner_timeout):
            log.warning('Tx-{} : packet not sent in last 2 timeout(2*{}s)'.format(interface.mac, interface.partner_timeout))
            log.info('Tx-{} : previous packet sent at {}, current time is {}'.format(interface.mac,
                                                    ts_to_str(interface.last_sent_time), ts_to_str(current_time)))
    for interface in to_be_removed:
        timer_list_remove(tx_timer_list, interface)


def check_rx_time_out(current_time, interfaces):
    alive_interfaces = [interface for interface in interfaces if interface.defaulted is False]
    for interface in alive_interfaces:
        if interface.mux_sm.is_waiting and current_time - interface.mux_sm.wait_while_timer_stamp > 2:
            interface.mux_sm.Ready = True
            interface.mux_sm.actor_state['synchronization']=1
            interface.mux_sm.wait_while_timer_stamp = 0

        if (interface.last_received_time != 0) and (current_time-interface.last_received_time > 3*interface.actor_timeout):
            log.error('Rx-{} : packet not received in last 3 timeout(3*{})s'.format(interface.mac, interface.actor_timeout))
            log.info('Rx-{} : previous packet received at {}, current time is {}'.format(interface.mac,
                                                    ts_to_str(interface.last_received_time), ts_to_str(current_time)))
            interface.defaulted = True
            interface.actor_state['defaulted'] = 1
            log.error('Actor state is Defaulted and selected may be UNSELECTED')
            # assuming oper parameters are different from admin parameters
            interface.mux_sm.stepback()

        elif (interface.last_received_time != 0) and (current_time-interface.last_received_time > 2*interface.actor_timeout
                                                    and interface.Rx_warned is False):
            log.warning('Rx-{} : packet not received in last 2 timeout(2*{}s)'.format(interface.mac, interface.actor_timeout))
            log.info('Rx-{} : previous packet received at {}, current time is {}'.format(interface.mac,
                                                    ts_to_str(interface.last_received_time), ts_to_str(current_time)))
            interface.Rx_warned = True


def ts_to_str(ts):
    precision = str(ts)[str(ts).index('.'):]
    time_string = datetime.fromtimestamp(ts, TZ).strftime('%d-%m-%y %H:%M:%S')
    return time_string+precision

# Compare the packet sent with expected value
def validate_tx_packet(interface, pkt):
    mac=LACP_PDU_structure.get_sender_address(pkt)
    expected_actor = interface.mux_sm.actor_state
    actual_actor = LACP_PDU_structure.get_actor_state(pkt)
    if expected_actor != actual_actor:
        if expected_actor['time_out'] != actual_actor['time_out']:
            old_time=list(periodic.keys())[expected_actor['time_out']]
            new_time=list(periodic.keys())[actual_actor['time_out']]
            log.warning('Actor time_out changed from {} timeout to {} timeout'.format(old_time,new_time))
        else:
            log.error('Unexpected packet sent')
    log.info('Tx-{} : Actor state expected to be sent: {}'.format(mac,interface.mux_sm.actor_state))
    log.info('Tx-{} :         Actor state actual sent: {}'.format(mac,LACP_PDU_structure.get_actor_state(pkt)))
    return

# Update last_sent_time and timeout and validate packet sent content
def run_tx_sm(index, current_time_stamp, pkt, interfaces, query):
    time_out = LACP_PDU_structure.get_actor_state(pkt)['time_out']
    actor_mac = LACP_PDU_structure.get_sender_address(pkt)
    interface = Interface.find_interface_from_mac(interfaces, actor_mac)
    if interface:
        # check if this is first packet seen in pcap
        if interface.last_sent_time == 0:
            interface.port = LACP_PDU_structure.get_PDU(pkt)['Actor_port']
            log.info(
                'Tx-{} : packet no. : {} - 1st packet sent at {}'.format(interface.mac, index + 1,
                                                                     ts_to_str(current_time_stamp)))
            interface.last_sent_time = current_time_stamp
            interface.actor_timeout = periodic[list(periodic.keys())[time_out]]
            timer_list_insert(tx_timer_list, interface)
            return

        # Not the first packet
        validate_tx_packet(interface, pkt)

        if query == 1:
            log.info('Tx-{} : packet no. : {} - previous packet sent at {}'.format(interface.mac, index + 1,
                                                                ts_to_str(interface.last_sent_time)))
            log.info(
                '   {} : packet no. : {} - current packet sent at {}'.format(interface.mac, index + 1,
                                                                ts_to_str(current_time_stamp)))
            log.info(
                '   {} : packet no. : {} - Jitter: {jit:.4f} '.format(interface.mac, index + 1,
                                                                 jit=current_time_stamp - interface.last_sent_time))
            log.info('   {} : packet no. : {} - partner expected new packet at every {} second interval'
                     .format(interface.mac, index + 1, interface.partner_timeout))
        else:
            log.info('Tx-{} : packet no. : {} - sent packet at {}'.format(interface.mac, index+1,
                                                                     ts_to_str(current_time_stamp)))
        interface.mux_sm.actor_state['time_out'] = time_out
        interface.actor_timeout = periodic[list(periodic.keys())[time_out]]
        interface.last_sent_time = current_time_stamp
        timer_list_insert(tx_timer_list, interface)


def run_rx_sm(index, current_time_stamp, pkt, interfaces, query):

    time_out = LACP_PDU_structure.get_actor_state(pkt)['time_out']
    partner_port = LACP_PDU_structure.get_PDU(pkt)['Partner_port']
    interface = LacpInterface.find_interface_from_port(interfaces, partner_port)

    if interface is None:
        log.info('Rx-Packet received, but actor cannot be mapped at this instant, packet ignored')
        return
    if interface.last_received_time == 0:
        log.info(
                'Rx-{} : packet no. : {} - 1st packet received at {}'.format(interface.mac, index + 1,
                                                                         ts_to_str(current_time_stamp)))
        interface.last_received_time = current_time_stamp
        interface.partner_timeout = periodic[list(periodic.keys())[time_out]]
        interface.defaulted = False
        interface.actor_state['defaulted'] = 0
        return

    interface.actor_state['defaulted'] = 0
    interface.Rx_warned = False

    if interface.defaulted is True:
        log.info('Rx-{} : packet no. : {} - new packet received at {}'.format(interface.mac, index + 1,
                                                                          ts_to_str(current_time_stamp)))
        interface.last_received_time = current_time_stamp
        interface.partner_timeout = periodic[list(periodic.keys())[time_out]]
        interface.defaulted = False
        interface.mux_sm.actor_state['expired']=0
        return
    if query == 1:
        log.info('Rx-{} : packet no. : {} - previous packet received at {}'.format(interface.mac, index + 1,
                                                                              ts_to_str(interface.last_received_time)))

        log.info(
            '   {} : packet no. : {} - current packet received at {}'.format(interface.mac, index + 1,
                                                                        ts_to_str(current_time_stamp)))
        log.info(
            '   {} : packet no. : {} - Jitter: {jit:.4f} '.format(interface.mac, index + 1,
                                                             jit=current_time_stamp - interface.last_received_time))
        log.info('   {} : packet no. : {} - partner expected new packet at every {} second interval'
                 .format(interface.mac, index + 1, interface.actor_timeout))
    else:
        log.info('RX-{} : packet no. : {} - received packet at {}'.format(interface.mac, index + 1,
                                                                     ts_to_str(current_time_stamp)))
    interface.mux_sm.partner_state['time_out'] = time_out
    interface.partner_timeout = periodic[list(periodic.keys())[time_out]]
    interface.last_received_time = current_time_stamp


def run_rx_tx_sm(index, current_time_stamp, pkt, interfaces, hosts, query, tz):
    global TZ
    TZ = tz
    check_tx_time_out(current_time_stamp)
    check_rx_time_out(current_time_stamp, interfaces)
    if LACP_PDU_structure.get_sender_address(pkt) in hosts:
        run_tx_sm(index, current_time_stamp, pkt, interfaces, query)
    else:
        run_rx_sm(index, current_time_stamp, pkt, interfaces, query)
