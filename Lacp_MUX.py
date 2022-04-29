import LACP_PDU_structure
import statemachine as sm
import logging as log


def find_int_mac(interfaces, mac):
    for interface in interfaces:
        if interface.mac == mac:
            return interface
    return None


def find_int_port(interfaces, port):
    for interface in interfaces:
        if interface.port == port:
            return interface
    return None


class MuxMachine(sm.StateMachine):
    Ready = False
    wait_while_timer_stamp = 0
    actor_state = dict()
    partner_state = dict()
    detached = sm.State("Detached", initial=True)
    waiting = sm.State("Waiting")
    attached = sm.State("Attached")
    collecting = sm.State("Collecting")
    distributing = sm.State("Distributing")

    # defining Transitions
    to_detach = detached.from_(attached, waiting)
    to_waiting = detached.to(waiting)
    to_attached = attached.from_(collecting, waiting)
    to_collecting = collecting.from_(attached, distributing)
    to_distributing = collecting.to(distributing)

    def on_enter_detached(self):
        log.info('Detach_Mux_From_Aggregator')
        self.actor_state['synchronization'] = 0
        log.info('Disable_Distributing')
        self.actor_state['distributing'] = 0
        self.actor_state['collecting'] = 0
        log.info('Disable_Collecting')
        log.info('Need To Transmit is TRUE')
        self.Ready=False
        self.wait_while_timer_stamp=0

    def on_enter_waiting(self):
        log.info("Wait while Timer started")

    def on_enter_attached(self):
        log.info('Attach_Mux_To_Aggregator')
        self.actor_state['synchronization'] = 1
        self.actor_state['collecting'] = 0
        log.info('Disable_Collecting')
        log.info('Need to Transmit is TRUE')

    def on_enter_collecting(self):
        log.info('Enable_collecting')
        self.actor_state['collecting'] = 1
        log.info('Disable_Distributing')
        self.actor_state['distributing'] = 0
        log.info('Need to Transmit is TRUE')

    def on_enter_distributing(self):
        self.actor_state['distributing'] = 1
        log.info('Enable_Distributing')

    def stepback(self):
        if self.is_distributing:
            self.to_collecting()
        elif self.is_collecting:
            self.to_attached()
        elif self.is_attached:
            self.to_detach()
        elif self.is_waiting:
            self.to_detach()


def detect_PDU_info_changes(p1, p2):
    if p1['Actor_system_priority'] != p2['Actor_system_priority']:
        log.info('Actor_system_priority changed from {} to {}'.format(p1['Actor_system_priority'],
                                                                      p2['Actor_system_priority']))

    if p1['Actor_system'] != p2['Actor_system']:
        log.debug('Actor_system_ID changed from {} to {}'.format(p1['Actor_system'], p2['Actor_system']))

    if p1['Actor_key'] != p2['Actor_key']:
        log.debug('Actor_key changed from {} to {}'.format(p1['Actor_key'], p2['Actor_key']))

    if p1['Actor_port_priority'] != p2['Actor_port_priority']:
        log.debug('Actor_port_priority changed from {} to {}'.format(p1['Actor_port_priority'],
                                                                     p2['Actor_port_priority']))

    if p1['Actor_port'] != p2['Actor_port']:
        log.debug('Actor_port changed from {} to {}'.format(p1['Actor_port'], p2['Actor_port']))

    if p1['Partner_system_priority'] != p2['Partner_system_priority']:
        log.debug('Partner_system_priority changed from {} to {}'.format(p1['Partner_system_priority'],
                                                                         p2['Partner_system_priority']))

    if p1['Partner_system'] != p2['Partner_system']:
        log.debug('Partner_system_ID changed from {} to {}'.format(p1['Partner_system'], p2['Partner_system']))

    if p1['Partner_key'] != p2['Partner_key']:
        log.debug('Partner_key changed from {} to {}'.format(p1['Partner_key'], p2['Partner_key']))

    if p1['Partner_port_priority'] != p2['Partner_port_priority']:
        log.debug('Partner_port_priority changed from {} to {}'.format(p1['Partner_port_priority'],
                                                                       p2['Partner_port_priority']))

    if p1['Partner_port'] != p2['Partner_port']:
        log.debug('Partner_port changed from {} to {}'.format(p1['Partner_port'], p2['Partner_port']))
    return


def dependency_check(int_mux_sm, pkt, direction):
    if direction == 'received':
        Ac_state = int_mux_sm.actor_state
        Pa_state = LACP_PDU_structure.get_actor_state(pkt)
        if Pa_state['collecting'] == 1 and Ac_state['synchronization'] == 0:
            log.error('Partner cannot move to collecting state when Actor is Out of Sync')
            log.info('Partner state:', Pa_state)
            log.info('Actor state:', Ac_state)

        if Pa_state['distributing'] == 1 and Ac_state['collecting'] == 0:
            log.error('Partner cannot move to distributing state when Actor is not collecting')
            log.info('Partner state:', Pa_state)
            log.info('Actor state:', Ac_state)

    if direction == 'sent':
        Ac_state = LACP_PDU_structure.get_actor_state(pkt)
        Pa_state = LACP_PDU_structure.get_partner_state(pkt)
        if Ac_state['collecting'] == 1 and Pa_state['synchronization'] == 0:
            log.error('Actor cannot move to collecting state when Actor is Out of Sync')
            log.info('Actor state:', Ac_state)
            log.info('partner state:', Pa_state)

        if Ac_state['distributing'] == 1 and Pa_state['collecting'] == 0:
            log.error('Partner cannot move to distributing state when Actor is not collecting')
            log.info('Actor state:', Ac_state)
            log.info('Partner state:', Pa_state)


def check_actor_info(old_actor_state, new_actor_state):  # called when new packet received
    if old_actor_state != new_actor_state:
        log.warning('The partner modified actor information')
        log.info('The actor state sent before was - ', old_actor_state)
        log.info('The actor state received now was - ', new_actor_state)


def check_partner_info(old_partner_state, new_partner_state):  # called when new packet sent
    if old_partner_state != new_partner_state:
        log.warning('The actor modified partner information')
        log.info('The actor state received before was - ', old_partner_state)
        log.info('The partner state sent now was - ', new_partner_state)


def sync_col_dist_check(p):
    actor_state = LACP_PDU_structure.get_actor_state(p)
    partner_state = LACP_PDU_structure.get_partner_state(p)
    to_be_ignored = ['activity', 'time_out', 'aggregation', 'defaulted', 'expired']
    [actor_state.pop(bit) for bit in to_be_ignored]
    [partner_state.pop(bit) for bit in to_be_ignored]
    actor_string = ''
    partner_string = ''
    for i in actor_state.values():
        actor_string = actor_string + str(i)
    error_index_a = -1
    if actor_string != '111':
        error_index_a = actor_string.find('1', actor_string.find('0'))
    for i in partner_state.values():
        partner_string = partner_string + str(i)
    error_index_p = -1
    if partner_string != '111':
        error_index_p = partner_string.find('1', partner_string.find('0'))

    if error_index_a != -1:
        log.critical(
            'Actor - not ' + list(actor_state.keys())[error_index_a - 1] + ' but ' + list(actor_state.keys())[
                error_index_a])
    if error_index_p != -1:
        log.critical(
            'Partner - not' + list(partner_state.keys())[error_index_p - 1] + ' but ' + list(partner_state.keys())[
                error_index_p])

    return error_index_p != -1 and error_index_a != -1


def run_mux_machine(pkt, hosts, interfaces):
    actor_state = LACP_PDU_structure.get_actor_state(pkt)
    partner_state = LACP_PDU_structure.get_partner_state(pkt)

    if LACP_PDU_structure.get_sender_address(pkt) in hosts:
        log.info('MUX - packet sent from {}'.format(LACP_PDU_structure.get_sender_address(pkt)))
        interface = find_int_mac(interfaces, LACP_PDU_structure.get_sender_address(pkt))
        if interface is None:
            log.error('packet sent, actor not found in interface inputs')
            return
        log.info('{} : Actor was in {} state\nPDU info:\n  actor state : {}\npartner state : {}'.format(interface.mac,
                                                    interface.mux_sm.current_state.value, actor_state, partner_state))

        if len(interface.mux_sm.actor_state) == 0:
            interface.mux_sm.actor_state = actor_state
            interface.port = LACP_PDU_structure.get_PDU(pkt)['Actor_port']
        if len(interface.last_pdu_rx) != 0:
            check_partner_info(LACP_PDU_structure.get_actor_state(interface.last_pdu_rx), partner_state)

        dependency_check(interface.mux_sm, pkt, 'sent')
        if len(interface.last_pdu_tx) != 0:
            detect_PDU_info_changes(LACP_PDU_structure.get_PDU(interface.last_pdu_tx), LACP_PDU_structure.get_PDU(pkt))

        if interface.mux_sm.is_detached:
            log.info('Selected may be SELECTED or STANDBY, moving to waiting')
            interface.mux_sm.to_waiting()
            interface.mux_sm.wait_while_timer_stamp = interface.last_sent_time
        elif interface.mux_sm.is_waiting and actor_state['synchronization'] == 1:
            log.info('Actor Ready is True')
            interface.mux_sm.to_attached()
        elif interface.mux_sm.is_waiting and actor_state['synchronization'] == 0:
            if interface.mux_sm.Ready is True:
                log.error('Actor selected is UNSELECTED or STANDBY')
                interface.mux_sm.to_detach()
        elif interface.mux_sm.is_attached and actor_state['synchronization'] == 0:
            log.error('Actor selected is UNSELECTED or STANDBY')
            interface.mux_sm.to_detach()
        elif interface.mux_sm.is_distributing and actor_state['distributing'] == 0:
            log.error('Actor selected is UNSELECTED or STANDBY')
            interface.mux_sm.to_collecting()
        elif interface.mux_sm.is_collecting and actor_state['collecting'] == 0:
            log.error('Actor selected is UNSELECTED or STANDBY')
            interface.mux_sm.to_attached()

        log.info('Actor is in {}'.format(interface.mux_sm.current_state.value))
        interface.last_pdu_tx = pkt

    else:
        interface = find_int_port(interfaces, LACP_PDU_structure.get_PDU(pkt)['Partner_port'])
        if interface is None:
            log.error(
                'No suitable actor found - packet sent by{}'.format(LACP_PDU_structure.get_sender_address(pkt)))
            return
        log.info('MUX - packet received in {}'.format(interface.mac))
        log.info('{} : Actor was in {} state\nPDU info:\n  actor state : {}\npartner state : {}'.format(interface.mac,
                                                    interface.mux_sm.current_state.value, partner_state, actor_state))
        check_actor_info(LACP_PDU_structure.get_actor_state(interface.last_pdu_tx), partner_state)
        dependency_check(interface.mux_sm, pkt, 'received')
        if len(interface.last_pdu_rx) != 0:
            detect_PDU_info_changes(LACP_PDU_structure.get_PDU(interface.last_pdu_rx), LACP_PDU_structure.get_PDU(pkt))
            interface.partner_state = partner_state

        if interface.mux_sm.is_attached and actor_state['synchronization'] == 1:
            log.info('Partner.sync is TRUE')
            interface.mux_sm.to_collecting()
        elif interface.mux_sm.is_collecting and actor_state['synchronization'] == 0:
            log.error('Partner.sync is FALSE, Partner selected might become UNSELECTED or STANDBY')
            interface.mux_sm.to_attached()
        elif interface.mux_sm.is_collecting and actor_state['synchronization'] == 1 and actor_state['collecting'] == 1:
            log.info('Partner.collecting is TRUE')
            interface.mux_sm.to_distributing()
        elif interface.mux_sm.is_distributing and actor_state['collecting'] == 0:
            log.error('Partner.collecting is False')
            interface.mux_sm.to_collecting()
        elif interface.mux_sm.is_distributing and actor_state['synchronization'] == 0:
            log.info('Partner.sync is FALSE')
            interface.mux_sm.to_collecting()
        log.info('Actor is in {} state'.format(interface.mux_sm.current_state.value))
        interface.last_pdu_rx = pkt

    log.debug('------------------------------------------------------------------------------------------------')