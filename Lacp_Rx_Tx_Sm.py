import LacPdu
import logging as log
from datetime import datetime
from Interface import *

rx_timer_list = set()   # not used anywhere
tx_timer_list = set()

global TZ

periodic = {'long': 30, 'short': 1}


def timer_list_insert(timer_list, interface):
    timer_list.add(interface)


def timer_list_remove(timer_list, interface):
    timer_list.remove(interface)


def check_tx_time_out(current_time):  # called to check timeout at Tx
    to_be_removed = list()
    for interface in tx_timer_list:
        if (interface.last_sent_time != 0) and (current_time-interface.last_sent_time > 3*interface.partner_timeout):
            log.error(
                'Tx - {} : previous packet sent at {}, packet not sent in last 3 timeout(3*{}s)'.format(
                    interface.mac, ts_to_str(interface.last_sent_time), interface.partner_timeout))
            to_be_removed.append(interface)

        elif (interface.last_sent_time != 0) and (current_time-interface.last_sent_time > 2*interface.partner_timeout):
            log.warning(
                'Tx - {} : previous packet sent at {}, packet not sent in last 2 timeout(2*{}s)'.format(
                    interface.mac, ts_to_str(interface.last_sent_time), interface.partner_timeout))

    for interface in to_be_removed:  # interfaces whose error is already reported are suspended temporarily from
        timer_list_remove(tx_timer_list, interface)         # checking timeout till new packet sent


def check_rx_time_out(current_time, interfaces):   # called to check timeout at Rx
    alive_interfaces = [interface for interface in interfaces if interface.mux_sm.actor_state['defaulted'] == 0]
    for interface in alive_interfaces:
        if (interface.last_received_time != 0) and (current_time-interface.last_received_time > 3*interface.actor_timeout):
            log.error('Rx - {} : previous packet received at {}, packet not received in last 3 timeout(3*{})s'.format(
                interface.mac, ts_to_str(interface.last_received_time), interface.actor_timeout))
            interface.mux_sm.actor_state['defaulted'] = 1
            interface.selected = 'UNSELECTED'
            log.error('Actor state is Defaulted and selected is UNSELECTED')
            # assuming oper parameters are different from admin parameters
            interface.mux_sm.move_to_detached()

        elif (interface.last_received_time != 0) and (current_time-interface.last_received_time > 2*interface.actor_timeout
                                                    and interface.Rx_warned is False):
            log.warning('Rx - {} : previous packet received at {}, packet not received in last 2 timeout(2*{}s)'.format(
                interface.mac, ts_to_str(interface.last_received_time), interface.actor_timeout))
            interface.Rx_warned = True


def ts_to_str(ts):  # converts timestamp to string
    precision = str(ts)[str(ts).index('.'):]
    time_string = datetime.fromtimestamp(ts, TZ).strftime('%d-%m-%y %H:%M:%S')
    return time_string+precision


# Update last_sent_time and timeout and validate packet sent content
def run_tx_sm(index, current_time_stamp, pkt, interfaces, detailed):
    time_out = LacPdu.get_actor_state(pkt)['time_out']
    actor_mac = LacPdu.get_src_eth_mac(pkt)
    interface = Interface.find_interface_from_mac(interfaces, actor_mac)
    if interface:
        # check if this is first packet seen in pcap
        if interface.last_sent_time == 0:
            interface.port = LacPdu.get_PDU(pkt)['Actor_port']
            log.info(
                'Tx - {} : packet no. : {} - 1st packet sent at {}'.format(interface.mac, index + 1,
                                                                     ts_to_str(current_time_stamp)))
            interface.last_sent_time = current_time_stamp
            interface.actor_timeout = periodic[list(periodic.keys())[time_out]]
            timer_list_insert(tx_timer_list, interface)
            return

        if detailed is True:
            log.info('Tx - {} : packet no. : {} - previous packet sent at {}'.format(interface.mac, index + 1,
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
            log.info('Tx - {} : packet no. : {} - sent packet at {}'.format(interface.mac, index+1,
                                                                     ts_to_str(current_time_stamp)))
        interface.mux_sm.actor_state['time_out'] = time_out
        interface.actor_timeout = periodic[list(periodic.keys())[time_out]]
        interface.last_sent_time = current_time_stamp
        timer_list_insert(tx_timer_list, interface)

    else:
        log.error('Tx - Packet sent, not processing as source address is missing in hosts input')

def run_rx_sm(index, current_time_stamp, pkt, interfaces, detailed):
    time_out = LacPdu.get_actor_state(pkt)['time_out']
    partner_port = LacPdu.get_PDU(pkt)['Partner_port']
    sender = LacPdu.get_src_eth_mac(pkt)
    interface = LacpInterface.find_actor_interface(interfaces, partner_port, sender)
    if interface is None:
        log.error('Rx - Packet received, but actor cannot be mapped at this instant, packet ignored')
        return
    if interface.last_received_time == 0:
        log.info(
                'Rx - {} : packet no. : {} - 1st packet received at {}'.format(interface.mac, index + 1,
                                                                         ts_to_str(current_time_stamp)))
        interface.last_received_time = current_time_stamp
        interface.partner_timeout = periodic[list(periodic.keys())[time_out]]
        interface.mux_sm.actor_state['defaulted'] = 0
        #interface.partnerMac = sender
        return

    interface.mux_sm.actor_state['defaulted'] = 0
    interface.Rx_warned = False

    if interface.mux_sm.actor_state['defaulted'] == 1:
        log.info('Rx - {} : packet no. : {} - new packet received at {}'.format(interface.mac, index + 1,
                                                                          ts_to_str(current_time_stamp)))
        interface.last_received_time = current_time_stamp
        interface.partner_timeout = periodic[list(periodic.keys())[time_out]]
        interface.mux_sm.actor_state['defaulted']=0
        return
    if detailed is True:
        log.info('Rx - {} : packet no. : {} - previous packet received at {}'.format(interface.mac, index + 1,
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
        log.info('Rx - {} : packet no. : {} - received packet at {}'.format(interface.mac, index + 1,
                                                                     ts_to_str(current_time_stamp)))
    interface.mux_sm.partner_state['time_out'] = time_out
    interface.partner_timeout = periodic[list(periodic.keys())[time_out]]
    interface.last_received_time = current_time_stamp


def run_rx_tx_sm(index, pkt, current_time_stamp, interfaces, hostEthMacs, detailed, tz):
    global TZ
    TZ = tz
    check_tx_time_out(current_time_stamp)
    check_rx_time_out(current_time_stamp, interfaces)
    if LacPdu.is_of_interest(pkt, index, interfaces) is False:
        return
    if LacPdu.get_src_eth_mac(pkt) in hostEthMacs:
        run_tx_sm(index, current_time_stamp, pkt, interfaces, detailed)
    else:
        run_rx_sm(index, current_time_stamp, pkt, interfaces, detailed)
