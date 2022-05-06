----------------------------- IN WRITING PHASE --------------------------

# NPA

## Interface
The class Interface provides attributes of port i.e mac ID, last sent packet, last received packet,
last packet sent time, last packet received time.</br>
The class LacpInterface which inherets from class Interface provides extra attributes related to LACP
protocol i.e port number, actor and partner timeouts, MUX machine running in each interface, defaulted status,etc

## LACP
The class LACP has following functions:</br>
_take_input_ function stores the information like .pcap file path, list of interfaces to be analyzed, 
type of output (summary / details) needed, timezone where packets are captured.

_run_analyzer_ function reads packet one by one and invokes Rx_Tx machine and MUX machine for analyzing packets.


## Lacp_Rx_Tx_Sm

The following are the functions present:

    check_tx_time_out
    check_rx_time_out
    validate_tx_packet
    run_tx_sm
    run_rx_sm
    run_rx_tx_sm

_check_tx_time_out_ function calculates the time difference between current time and last packet sent time of all
interfaces and reports if any interface timeouts in between. </br>
_check_rx_time_out_ function does same as Tx time out but with last packet received time.</br>
_validate_tx_packet_ function compares the actor state received and expected value determined by mux machine states and
reports error if mismatch is found. </br>
_run_tx_sm_ function is invoked only when a packet is sent from interface. It calculates the jitter, logs value of last
packet sent time and current time based on query requested by user. </br>
_run_rx_sm_ function is invoked only when a packet is received by interface. It does same jitter calculation function.</br>

LOGIC
1. Using current packet time, timeout of actors are checked for TX
	1. All the interfaces’ last_packet_sent time and current packet time are compared to find whether 
		timeout happened or not, warning is made if necessary
	2. Once timeout error reported, particular interface is suspended from further timeout checking till new
		packet is sent out
2. Using current packet time, timeout of actors are checked for RX
	1. All the interfaces which are not defaulted are considered for comparison of last_packet_received
	   time and current packet time to report errors
	2. If found that actor not received any packet after 3 timeouts, interface is made defaulted and selected
		will be made UNSELECTED

3. Based on sender address, packet is classified as whether packet is sent or received
4. If Packet is sent from one of the interfaces:
	1. If current packet is first packet sent out, port number is recorded, last_sent_time is updated to 
		current time and time_out value is recorded and jitter calculation is skipped
	2. If user requested that report needed is of detailed, last_packet_timestamp, 		current_packet_timestamp, jitter is logged
5. If packet is received from one of the interfaces:
	1. Actual interface where packet is received is found from sender address, partner port of packet
	2. If interface has not received any packet before, timeout is recorded, last_packet_received time is
		updated to current time and interface is made not defaulted.
	3. Jitter calculation is made and details of packet received	will be logged if user need detailed analysis.


	


## Lacp_MUX:
LOGIC:
1. Use packet timestamp to run wait_while_timer and modify Ready
2. Checks if packet is sent or received by interfaces under processing ( interested)
3. Checks if packet is corrupt at sequence (sync-col-dist)
4. Checks the direction of packet movement (sent or received)
5. If packet is sent
   1. find actual interface which sent 
   2. if interface has sent any packets before, the actor state contents of new packet are validated to
          expected state 
   3. Some transitions are dependent on partner, such transitions based on packet are validated 
   4. If current packet is first packet sent by interface, actor state will be initialised, port number will be 		recorded 
   5. Transitions baed on different conditions are done 
   6. Packet is saved in last_pdu sent

6. If packet is received
    1. Partner port and sender are recorded
    2. Interface which is actually received will be fetched based on sender address, partner port value
    3. If any packet is sent out from interface, sent content as actor state will be validated.
        Dependency check will be done
    4. If any packet is received on that interface, partner values are compared with previous packet
    5. Different Transitions possibles are done
    6. Packet is saved in last_pdu received


Supporting functions:
1. find_int_mac 
2. find_actor_interface
3. detect_PDU_info_changes
4. dependency_check
5. check_actor_info
6. check_partner_info
7. sync_col_dist_check
	
	




## PCAP Utility
The following are the utility functions related to LACP PDU
1. get_PDU(p) - outputs PDU in dictionary format, each field as key
2. print_PDU_info(p) - prints the PDU field by field
3. get_actor_state(p) - actor state of the PDU is returned in dictionary format
4. get_partner_state(p) - partner state of the PDU is returned in dictionary format
5. get_sender_address(p) - return the address of the sender of Packet
6. validate_packet(p) - Validates the packet in regard to LACP protocol - protocol type, LACP version, etc




