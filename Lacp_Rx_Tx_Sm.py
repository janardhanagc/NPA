import LacPdu
import logging as log
from datetime import datetime
from Interface import *

rx_timer_list = set()   # not used anywhere
tx_timer_list = set()

tx_warn_interfaces = set()
rx_warn_interfaces = set()

global TZ

periodic = {'long': 30, 'short': 1}


def timer_list_insert(timer_list, interface):
    timer_list.add(interface)


def timer_list_remove(timer_list, interface):
    timer_list.remove(interface)


def check_tx_time_out(current_time):  # called to check timeout at Tx
    to_be_removed = list()
    for interface in tx_timer_list:
        if (interface.last_sent_time != 0) and (interface.rx_timeout_buffer == 0 or interface.rx_timeout_buffer +3 < current_time)\
                and (current_time - interface.last_sent_time > 3*interface.partner_timeout):
            log.error(
                'Tx - {} : previous packet sent at {}, packet not sent in last 3 timeout(3*{}s)'.format(
                    interface.mac.replace(' ', ':'), ts_to_str(interface.last_sent_time), interface.partner_timeout))
            interface.tx_timeout_buffer = 0
            to_be_removed.append(interface)
            if interface in tx_warn_interfaces:
                tx_warn_interfaces.remove(interface)
        elif (interface.last_sent_time != 0) and (interface.rx_timeout_buffer == 0 or interface.rx_timeout_buffer +3 < current_time) and\
                (current_time-interface.last_sent_time > 2*interface.partner_timeout
                                                  and interface not in tx_warn_interfaces):
            log.warning(
                'Tx - {} : previous packet sent at {}, packet not sent in last 2 timeout(2*{}s)'.format(
                    interface.mac.replace(' ', ':'), ts_to_str(interface.last_sent_time), interface.partner_timeout))
            tx_warn_interfaces.add(interface)

    for interface in to_be_removed:  # interfaces whose error is already reported are suspended temporarily from
        timer_list_remove(tx_timer_list, interface)         # checking timeout till new packet sent


def check_rx_time_out(current_time, interfaces):   # called to check timeout at Rx
    alive_interfaces = [interface for interface in interfaces if interface.mux_sm.actor_state['expired'] == 0]
    for interface in alive_interfaces:
        if (interface.last_received_time != 0 and (interface.tx_timeout_buffer == 0 or
                interface.tx_timeout_buffer+3 < current_time )and current_time-interface.last_received_time > 3*interface.actor_timeout):
            log.critical("current time is {} and buffer is {}".format(ts_to_str(float(current_time)),ts_to_str(float(interface.tx_timeout_buffer + 3))))
            log.error('Rx - {} : previous packet received at {}, packet not received in last 3 timeout(3*{})s'.format(
                interface.mac.replace(' ',':'), ts_to_str(interface.last_received_time), interface.actor_timeout))
            interface.mux_sm.actor_state['expired'] = 1
            interface.selected = 'UNSELECTED'
            log.error('Rx - {} : Actor state is Defaulted and selected is UNSELECTED'.format(
                interface.mac.replace(' ', ':')))
            # assuming oper parameters are different from admin parameters
            interface.mux_sm.move_to_detached()      # changing MUX state
            if interface in rx_warn_interfaces:
                rx_warn_interfaces.remove(interface)
            interface.rx_timeout_buffer = 0

        elif (interface.last_received_time != 0 and (interface.tx_timeout_buffer == 0 or
                interface.tx_timeout_buffer+3 < current_time ) and current_time -interface.last_received_time > 2*interface.actor_timeout
                                                    and interface not in rx_warn_interfaces):
            log.warning('Rx - {} : previous packet received at {}, packet not received in last 2 timeout(2*{}s)'.format(
                interface.mac.replace(' ',':'), ts_to_str(interface.last_received_time), interface.actor_timeout))
            rx_warn_interfaces.add(interface)


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
        interface.tx_timeout_buffer = -3
        if interface.last_sent_time == 0:
            actor_port = LacPdu.get_PDU(pkt)['Actor_port']
            if interface.port != " " and interface.port != actor_port:
                log.warning("{} : MAC - {} : User entered actor port number as '0x{}' and is updating to {} based on "
                           "packet sent".format(LacPdu.pkt_info(pkt, index), interface.mac.replace(' ',':'),
                                                interface.port.replace(' ',''), actor_port))
            interface.port = actor_port  # updating actor port number
            log.info(
                'Tx - {} : MAC - {} : 1st packet sent at {}'.format(LacPdu.pkt_info(pkt,index), interface.mac.replace(' ',':'),
                                                                     ts_to_str(current_time_stamp)))
            interface.last_sent_time = current_time_stamp
            interface.actor_timeout = periodic[list(periodic.keys())[time_out]]
            timer_list_insert(tx_timer_list, interface)
            return

        if detailed is True:
            log.info('Tx - {} : MAC - {} : previous packet sent at {}'.format(LacPdu.pkt_info(pkt,index), interface.mac.replace(' ',':'),
                                                                ts_to_str(interface.last_sent_time)))
            log.info(
                'Tx - {} : MAC - {} : current packet sent at {}'.format(LacPdu.pkt_info(pkt,index), interface.mac.replace(' ',':'),
                                                                ts_to_str(current_time_stamp)))
            log.info(
                'Tx - {} : MAC - {} : Jitter: {jit:.4f} '.format(LacPdu.pkt_info(pkt,index), interface.mac.replace(' ',':'),
                                                                 jit=current_time_stamp - interface.last_sent_time))
            log.info('Tx - {} : MAC - {} : partner expected new packet at every {} second interval'
                     .format(LacPdu.pkt_info(pkt, index), interface.mac.replace(' ',':'), interface.partner_timeout))
        else:
            log.info('Tx - {} : MAC - {} : sent packet at {}'.format(LacPdu.pkt_info(pkt,index), interface.mac.replace(' ',':'),
                                                                     ts_to_str(current_time_stamp)))

        if interface.mux_sm.current_state.value != ['distributing'] and interface.mux_sm.actor_state['time_out'] != time_out:
            log.warning('{} : MAC - {} : expected time_out - {}, actual sent is {}'.format(LacPdu.pkt_info(pkt, index),
                            interface.mac.replace(" ",":"), LacPdu.state_values['time_out'][interface.mux_sm.actor_state['time_out']],
                                                        LacPdu.state_values['time_out'][time_out]))
        elif interface.mux_sm.actor_state['time_out'] != time_out:
            log.info('{} : MAC - {} : expected time_out - {}, actual sent is {}'.format(LacPdu.pkt_info(pkt, index),
                            interface.mac.replace(" ",":"), LacPdu.state_values['time_out'][interface.mux_sm.actor_state['time_out']],
                                                            LacPdu.state_values['time_out'][time_out]))

        if interface.mux_sm.actor_state['time_out'] == 0 and time_out == 1:
            interface.tx_timeout_buffer = current_time_stamp
            log.critical("buffering {}".format(ts_to_str(interface.tx_timeout_buffer)))



        interface.mux_sm.actor_state['time_out'] = time_out
        interface.actor_timeout = periodic[list(periodic.keys())[time_out]]
        interface.last_sent_time = current_time_stamp
        timer_list_insert(tx_timer_list, interface)

    else:
        log.error('Tx - {} : Packet sent, not processing as source address is missing in hosts input'.
                  format(LacPdu.pkt_info(pkt, index)))


def run_rx_sm(index, current_time_stamp, pkt, interfaces, detailed):
    time_out = LacPdu.get_actor_state(pkt)['time_out']
    partner_port = LacPdu.get_PDU(pkt)['Partner_port']
    sender = LacPdu.get_src_eth_mac(pkt)
    interface = LacpInterface.find_actor_interface(interfaces, partner_port, sender)
    if interface is None:
        log.error('Rx - {} : Packet received, but actor cannot be mapped at this instant, packet ignored'.
                  format(LacPdu.pkt_info(pkt, index)))
        return

    interface.tx_timeout_buffer = -3

    if interface.last_received_time == 0:
        log.info(
                'Rx - {} : MAC - {} : 1st packet received at {}'.format(LacPdu.pkt_info(pkt, index), interface.mac.replace(' ',':'),
                                                                         ts_to_str(current_time_stamp)))
        interface.last_received_time = current_time_stamp
        interface.partner_timeout = periodic[list(periodic.keys())[time_out]]
        interface.mux_sm.actor_state['expired'] = 0
        if interface.partnerMac == " " or interface.partnerMac != sender:
            log.warning("Rx - {}: MAC - {} :Partner Mac changed from {} to {}".format(LacPdu.pkt_info(pkt, index),
                                                                        interface.mac.replace(' ',':'), interface.partnerMac, sender))
            interface.partnerMac = sender
        return

    interface.mux_sm.actor_state['expired'] = 0

    if interface.mux_sm.actor_state['expired'] == 1:
        log.info('Rx - {} : MAC - {} : new packet received at {}'.format(LacPdu.pkt_info(pkt,index), interface.mac.replace(' ',':'),
                                                                          ts_to_str(current_time_stamp)))
        interface.last_received_time = current_time_stamp
        interface.partner_timeout = periodic[list(periodic.keys())[time_out]]
        interface.mux_sm.actor_state['expired']=0
        return
    if detailed is True:
        log.info('Rx - {} : MAC - {} : previous packet received at {}'.format(LacPdu.pkt_info(pkt, index),
                                                            interface.mac.replace(' ',':'), ts_to_str(interface.last_received_time)))

        log.info(
            'Rx - {} : MAC - {} : current packet received at {}'.format(LacPdu.pkt_info(pkt, index), interface.mac.replace(' ',':'),
                                                                        ts_to_str(current_time_stamp)))
        log.info(
            'Rx - {} : MAC - {} : Jitter: {jit:.4f} '.format(LacPdu.pkt_info(pkt, index), interface.mac.replace(' ',':'),
                                                             jit=current_time_stamp - interface.last_received_time))
        log.info('Rx - {} : MAC - {} : partner expected new packet at every {} second interval'
                 .format(LacPdu.pkt_info(pkt, index), interface.mac.replace(' ',':'), interface.actor_timeout))
    else:
        log.info('Rx - {} : MAC - {} : received packet at {}'.format(LacPdu.pkt_info(pkt, index), interface.mac.replace(' ',':'),
                                                                     ts_to_str(current_time_stamp)))

    log.critical("".format(interface.mux_sm.partner_state))
    if interface.mux_sm.partner_state['time_out'] == 0 and time_out == 1:
        interface.rx_timeout_buffer = current_time_stamp
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
    log.debug('Analysis of {} starts here'.format(LacPdu.pkt_info(pkt, index)))

    if LacPdu.get_src_eth_mac(pkt) in hostEthMacs:
        run_tx_sm(index, current_time_stamp, pkt, interfaces, detailed)
    else:
        run_rx_sm(index, current_time_stamp, pkt, interfaces, detailed)
