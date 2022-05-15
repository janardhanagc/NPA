import LacPdu
import statemachine as sm
import logging as log


# searches and return the interface bearing mac address passed
def find_int_mac(interfaces, mac):
    for interface in interfaces:
        if interface.mac == mac:
            return interface
    return None


# returns interface which is actually received the packet
# partner port in PDU is actor port for local host
def find_actor_interface(interfaces, actor_port, sender):  # partner port in PDU is actual actor port of some interface
    for interface in interfaces:
        if interface.partnerMac == ' ':     # for first packet received when partnerMac not available
            if actor_port == interface.port:
                return interface
        elif interface.partnerMac == sender:  # from second packet onwards, port number may change
            return interface
    return None


class MuxMachine(sm.StateMachine):
    Ready = False
    wait_while_timer_stamp = 0
    actor_state = dict({'defaulted': 0})
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
        self.Ready = False
        self.wait_while_timer_stamp = 0

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

    def move_to_detached(self):     # useful when defaulted and selected is UNSELECTED
        if self.is_distributing:
            log.error('Actor moving back to collecting state')
            self.to_collecting()
        if self.is_collecting:
            log.error('Actor moving back to attached state')
            self.to_attached()
        if self.is_attached:
            log.error('Actor moving back to detached state')
            self.to_detach()
        if self.is_waiting:
            log.error('Actor moving back to detached state')
            self.to_detach()

    def jump_to_state(self, actor_state):   # useful when pcap starts when actor in dist / col / attached state
        log.info("Initializing Actor state.......")
        if actor_state['distributing'] == 1:
            if self.is_detached:
                self.to_waiting()
            self.to_attached()
            self.to_collecting()
            self.to_distributing()
        elif actor_state['collecting'] == 1:
            if self.is_detached:
                self.to_waiting()
            self.to_attached()
            self.to_distributing()
        elif actor_state['synchronization'] == 1:
            if self.is_detached:
                self.to_waiting()
            self.to_attached()
        self.actor_state = actor_state
        self.Ready = True
        log.info("Actor is initialized to {} state based on actor state of PDU sent".format(self.current_state.value))

    def compare_state(self, actor_state, index, interface):
        to_be_ignored = ["activity", "time_out", "aggregation", "defaulted", "expired"]
        for each in to_be_ignored:
            actor_state.pop(each)
        state = ''
        for bit in list(actor_state.values()):
            state = state+str(bit)
        if state == '100' and self.current_state.value == 'Detached':
            log.error("MUX - {} : expected state is {} state, but packet {} content says actor is in ATTACHED state".
                      format(interface.mac, index+1, self.current_state.value.upper()))
        elif state == '110':
            log.error("MUX - {} : expected state is {} state, but packet {} content says actor is in COLLECTING state".
                      format(interface.mac, index+1, self.current_state.value.upper()))
        elif state == '111':
            log.error("MUX - {} : expected state is {} state, but packet {} content says actor is in DISTRIBUTING state".
                      format(interface.mac, index+1, self.current_state.value.upper()))
        return

# reports any changes in actor or partner information present among last two packet sent / received
# it checks for system ID, priority, key, port, port priority of both actor and partner
def detect_agent_info_changes(pkt_old, pkt_new, interface, direction):
    if direction == 'sent':
        agent = 'Actor'
    else:
        agent = 'Partner'
    old_agent_info = LacPdu.get_info_of(agent, pkt_old)
    new_agent_info = LacPdu.get_info_of(agent, pkt_new)
    agent = agent + '_'  # to match with actual keys used in LacPDU
    pkt_old = LacPdu.get_PDU(pkt_old)
    pkt_new = LacPdu.get_PDU(pkt_new)
    for key in LacPdu.agent_keys:
        if old_agent_info[agent+key] != pkt_new[agent+key]:
            log.warning("{} changed from {} to {}".format(agent+key, old_agent_info[agent+key], new_agent_info[agent+key]))
            if key == 'port' and agent == 'Actor_':
                setattr(interface,'port', new_agent_info[agent+key])
            elif key == 'port' and agent == 'Partner_':
                setattr(interface, 'port', new_agent_info[agent+key])
    return


# Actor cannot move to collecting before partner is in synchronization,
# actor cannot move to distributing before actor is in collecting.
# The above transitions are checked when either actor or partner sends packet
def dependency_check(interface, pkt, index, direction):
    if direction == 'received':
        Ac_state = interface.mux_sm.actor_state
        Pa_state = LacPdu.get_actor_state(pkt)
        if Pa_state['collecting'] == 1 and Ac_state['synchronization'] == 0:
            log.error('MUX - {} : packet {} : Partner cannot move to collecting state when Actor is Out of Sync'.
                      format(interface.mac, index+1))
            log.info('Partner state: {}'.format(Pa_state))
            log.info('Actor state: {}'.format(Ac_state))

        if Pa_state['distributing'] == 1 and Ac_state['collecting'] == 0:
            log.error('MUX - {} : packet {} : Partner cannot move to distributing state when Actor is not collecting'.
                      format(interface.mac, index+1))
            log.info('Partner state:'.format(Pa_state))
            log.info('Actor state:'.format(Ac_state))

    if direction == 'sent':
        Ac_state = LacPdu.get_actor_state(pkt)
        if interface.mux_sm.actor_state['defaulted'] == 1:
            Pa_state = LacPdu.get_partner_state(pkt)
        else:
            Pa_state = LacPdu.get_partner_state(interface.last_pkt_rx)
        if Ac_state['collecting'] == 1 and Pa_state['synchronization'] == 0:
            log.error('MUX - {} : packet {} : Actor cannot move to collecting state when Actor is Out of Sync'.
                      format(interface.mac, index+1))
            log.info('Actor state: {}'.format(Ac_state))
            log.info('partner state: {}'.format(Pa_state))

        if Ac_state['distributing'] == 1 and Pa_state['collecting'] == 0:
            log.error('MUX - {} : packet {} : Partner cannot move to distributing state when Actor is not collecting'.
                      format(interface.mac, index+1))
            log.info('Actor state: {}'.format(Ac_state))
            log.info('Partner state: {}'.format(Pa_state))


# the partner has to save the actor state from PDU received and send back without modification in its partner field
# if partner modified actor info or fails to copy down latest actor state properly, this function catches those errors.
def check_actor_info(old_pkt, new_pkt):  # called when new packet received
    old_Actor = LacPdu.get_info_of('Actor', old_pkt)
    new_Actor = LacPdu.get_info_of('Partner', new_pkt)
    for key in LacPdu.agent_keys:
        if old_Actor['Actor_'+key] != new_Actor['Partner_'+key]:
            log.warning('Partner modified Actor_{} information sent. Actual sent was {}, received back was {}'.
                        format(key, old_Actor['Actor_'+key], new_Actor['Partner_'+key]))
    old_actor_state = LacPdu.get_actor_state(old_pkt)
    new_actor_state = LacPdu.get_partner_state(new_pkt)
    if old_actor_state != new_actor_state:
        log.warning('The partner modified actor state information')
        log.info('The actor state  sent before was - {}'.format(old_actor_state))
        log.info('The partner state received now was - {}'.format(new_actor_state))


# the actor has to save the actor state from PDU received and send back without modification in its partner field
# if actor modified partner info or fails to copy down latest partner state properly, this function catches those errors.
def check_partner_info(old_pkt, new_pkt):  # called when new packet sent
    old_partner = LacPdu.get_info_of('Actor', old_pkt)
    new_partner = LacPdu.get_info_of('Partner', new_pkt)
    for key in LacPdu.agent_keys:
        if old_partner['Actor_'+key] != new_partner['Partner_'+key]:
            log.warning('Actor modified Partner_{} information received. Actual received was {}, sent back was {}'.
                        format(key,old_partner['Actor_'+key], new_partner['Partner_'+key]))
    old_partner_state = LacPdu.get_actor_state(old_pkt)
    new_partner_state = LacPdu.get_partner_state(new_pkt)
    if old_partner_state != new_partner_state:
        log.warning('The actor modified partner state information')
        log.info('The actor state received before was - {}'.format(old_partner_state))
        log.info('The partner state sent now was - {}'.format(new_partner_state))


# the valid transitions in the MUX are sync->col->dist.
# if packet corrupted and alters the transition rule, error will be caught. (ex: sync:1, col:0, dist:1) is illegal
def sync_col_dist_check(pkt):
    actor_state = LacPdu.get_actor_state(pkt)
    partner_state = LacPdu.get_partner_state(pkt)
    to_be_ignored = ['activity', 'time_out', 'aggregation', 'defaulted', 'expired']
    [actor_state.pop(bit) for bit in to_be_ignored]
    [partner_state.pop(bit) for bit in to_be_ignored]
    actor_string = ''
    partner_string = ''
    for i in actor_state.values():                  # sync, col, dist values are converted into string
        actor_string = actor_string + str(i)
    error_index_a = -1
    if actor_string != '111':         # the error_index will have index of first occurrence of '1' after '0' in string
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


#  compares the packet sent and expected packet to be sent determined by simulation
#  only exception is provided in timeout
def validate_tx_packet(interface, pkt, index):
    periodic = {'long': 30, 'short': 1}
    mac = LacPdu.get_src_eth_mac(pkt)
    expected_actor = interface.mux_sm.actor_state
    actual_actor = LacPdu.get_actor_state(pkt)
    if expected_actor != actual_actor:
        if expected_actor['time_out'] != actual_actor['time_out']:
            old_time=list(periodic.keys())[expected_actor['time_out']]
            new_time=list(periodic.keys())[actual_actor['time_out']]
            log.warning('Actor time_out changed from {} timeout to {} timeout'.format(old_time,new_time))
        else:
            log.error('packet {} Unexpected packet sent'.format(index+1))
    log.info('Tx - {} : Actor state expected to be sent: {}'.format(mac,interface.mux_sm.actor_state))
    log.info('Tx - {} :         Actor state actual sent: {}'.format(mac,LacPdu.get_actor_state(pkt)))
    interface.mux_sm.compare_state(actual_actor, index, interface)
    return


def run_mux_machine(index, pkt, pkt_time, hostEthMacs, interfaces):

    for interface in interfaces:  # pkt time is used to run wait_while_timer
        if interface.mux_sm.is_waiting and pkt_time - interface.mux_sm.wait_while_timer_stamp > 2:
            interface.mux_sm.Ready = True
            interface.mux_sm.actor_state['synchronization'] = 1
            interface.mux_sm.wait_while_timer_stamp = 0
    if LacPdu.is_of_interest(pkt, index, interfaces) is False:  # checks if packet is not sent or received by
        return                                                          # interfaces interested

    actor_state = LacPdu.get_actor_state(pkt)
    partner_state = LacPdu.get_partner_state(pkt)

    sync_col_dist_check(pkt)      # checks possibility of corrupt of bits or invalid transition rule
    if LacPdu.get_src_eth_mac(pkt) in hostEthMacs:      # packet is sent from switch
        log.info('MUX - packet sent from {}'.format(LacPdu.get_src_eth_mac(pkt)))
        interface = find_int_mac(interfaces, LacPdu.get_src_eth_mac(pkt))
        if interface is None:     # This condition never encounters as hostEthMacs defined based on input hosts
            log.debug('packet sent, actor not found in interface inputs')
            return

        if interface.last_pkt_tx != '':                 # validates if current pkt is not very first packet sent
            validate_tx_packet(interface, pkt, index)

        log.info('{} : Actor was in {} state\nPDU info:\n  actor state : {}\npartner state : {}'.format(interface.mac,
                                                    interface.mux_sm.current_state.value, actor_state, partner_state))

        if len(interface.mux_sm.actor_state) == 1:  # defaulted bit is initialized in LacpInterface class
            interface.mux_sm.actor_state = actor_state      # actor state is initialized if pkt is 1st packet sent
            # interface.port = LacPdu.get_PDU(pkt)['Actor_port']  # initialization done in Rx machine
            if actor_state['synchronization'] == 1:
                interface.selected = 'SELECTED'  # synchronization means selected should be already SELECTED (check)
                interface.mux_sm.jump_to_state(actor_state)

        if len(interface.last_pkt_rx) != 0:        # checks if actor has modified any partner state information
            check_partner_info(interface.last_pkt_rx, pkt)
            dependency_check(interface, pkt,index, 'sent')   # checks if actor has made illegal transitions

        if len(interface.last_pkt_tx) != 0:  # checks for change in contents of actor/ partner information except states
            detect_agent_info_changes(interface.last_pkt_tx, pkt, interface, 'sent')

        if interface.mux_sm.is_waiting and actor_state['synchronization'] == 1:
            if interface.mux_sm.Ready is True:
                log.info('Actor is in WAITING state, Actor synchronization becomes IN SYNC implied Actor Ready is True')
            else:
                log.error('packet {} wait_while_timer not yet expired, actor unexpectedly moved to attached state'.format(index+1))
            interface.mux_sm.to_attached()
        elif interface.mux_sm.is_waiting and actor_state['synchronization'] == 0:
            if interface.mux_sm.Ready is True:
                log.error('packet {} Actor was in WAITING state, despite wait_while_timer expired, actor synchronization is False'
                          '.\nActor selected might be UNSELECTED or STANDBY, so actor is moved to DETACHED state'.format(index+1))
                interface.selected = 'UNSELECTED'
                interface.mux_sm.to_detach()
        elif interface.mux_sm.is_attached and actor_state['synchronization'] == 0:
            log.error('packet {} Actor was in ATTACHED state and actor synchronization becomes False.'
                      ' Actor selected could be UNSELECTED or STANDBY. So, actor moving to DETACHED state'.format(index+1))
            interface.selected = 'UNSELECTED'
            interface.mux_sm.to_detach()
        elif interface.mux_sm.is_attached and partner_state['synchronization'] == 1:
            log.info('packet {} Actor was in ATTACHED state. Partner synchronization is already IN SYNC. So, Actor moving to '
                     'COLLECTING state'.format(index+1))
            interface.mux_sm.to_collecting()
        elif interface.mux_sm.is_distributing and actor_state['distributing'] == 0:
            log.error('packet {} Actor was in DISTRIBUTING state and actor distributing becomes False when packet sent out.'
                      ' Actor selected could be UNSELECTED or STANDBY. So, actor moving to COLLECTING state'.format(index+1))
            interface.selected = 'UNSELECTED'
            interface.mux_sm.to_collecting()
        elif interface.mux_sm.is_collecting and actor_state['collecting'] == 0:
            log.error('packet {} Actor was in COLLECTING state and actor collecting becomes False when packet sent out.'
                      ' Actor selected could be UNSELECTED or STANDBY. So, actor moving to ATTACHED state'.format(index+1))
            interface.selected = 'UNSELECTED'
            interface.mux_sm.to_attached()
        elif interface.mux_sm.is_collecting and partner_state['collecting'] == 1:
            log.info('packet {} Actor was in COLLECTING state. Partner was already in COLLECTING state. So, Actor moving to '
                     'DISTRIBUTING state'.format(index+1))
            interface.mux_sm.to_distributing()

        log.info('Actor is in {} state'.format(interface.mux_sm.current_state.value))
        interface.last_pkt_tx = pkt

    else:
        partner_port = LacPdu.get_PDU(pkt)['Partner_port']
        sender = LacPdu.get_src_eth_mac(pkt)
        interface = find_actor_interface(interfaces, partner_port, sender)
        if interface is None:
            log.error(
                'MUX - No suitable actor found - packet sent by {}'.format(LacPdu.get_src_eth_mac(pkt)))
            return
        log.info('MUX - packet received in {}'.format(interface.mac))
        log.info('{} : Actor was in {} state\nPDU info:\n  actor state : {}\npartner state : {}'.format(interface.mac,
                                                    interface.mux_sm.current_state.value, partner_state, actor_state))
        if interface.last_pkt_tx != '':   # enters the if block if interface has sent any packet before
            check_actor_info(interface.last_pkt_tx, pkt)
            dependency_check(interface, pkt, index, 'received')
        if len(interface.last_pkt_rx) != 0:  # enters the if block if interface has received any packet before
            detect_agent_info_changes(interface.last_pkt_rx, pkt, interface, 'received')
            interface.partner_state = partner_state

        if interface.mux_sm.is_detached and interface.selected == 'SELECTED':
            log.info('Selected may be SELECTED or STANDBY, moving to waiting')
            interface.mux_sm.to_waiting()
            interface.mux_sm.wait_while_timer_stamp = interface.last_received_time
            # current pkt time is updated as last_sent_time in Rx_Tx state machine

        elif interface.mux_sm.is_attached and actor_state['synchronization'] == 1:
            log.info('Actor is in ATTACHED state and partner becomes IN SYNC. '
                     'So, Actor moving to COLLECTING state')
            interface.mux_sm.to_collecting()
        elif interface.mux_sm.is_collecting and actor_state['synchronization'] == 0:
            log.error('Actor is in COLLECTING state and partner becomes OUT OF SYNC.'
                      ' Partner selected might become UNSELECTED or STANDBY. So, actor moving back to ATTACHED state')
            interface.mux_sm.to_attached()
        elif interface.mux_sm.is_collecting and actor_state['synchronization'] == 1 and actor_state['collecting'] == 1:
            log.info('Actor is in COLLECTING state and partner collecting becomes enabled. So, Actor moving to '
                     'DISTRIBUTING state')
            interface.mux_sm.to_distributing()
        elif interface.mux_sm.is_distributing and actor_state['collecting'] == 0:
            log.error('Actor is in DISTRIBUTING state and partner collecting becomes disabled. So, Actor moving back to'
                      ' COLLECTING state ')
            interface.mux_sm.to_collecting()
        elif interface.mux_sm.is_distributing and actor_state['synchronization'] == 0:
            log.info('Actor is in DISTRIBUTING and partner becomes OUT OF SYNC. So, Actor moving back to COLLECTING'
                     ' state')
            interface.mux_sm.to_collecting()
        log.info('Actor is in {} state'.format(interface.mux_sm.current_state.value))
        interface.last_pkt_rx = pkt

    log.debug('------------------------------------------------------------------------------------------------------')