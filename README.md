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

The following are the important functions present:

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

## Lacp_MUX






inputs : host, filename, query, tz, outputfile
  1. Host is list of MAC IDs of interfaces at which jitter is to be calculated
  2. filename is .pcap file addr   ess which is to be processed for jitter calculation
  3. query : 1 - indicates full descriptive analysis, 0 - indicates summary
  4. tz: timezone where .pcap file is captured
  5. outputfile: name of the log file where output is to be written

FUNCTION:
1. Calculate the jitter both in the sender side and receiver side of the interface with help of timestamp of packets.
2. Report Timeouts (2 timeouts- warning) (3 timeouts-error) for each interface both in receiver and sender side.

LOGIC:
1. A class called Interface is defined which has attributes called MAC ID, port number, last packet sent time, received time, etc.
    For each entry in input host list, an object of type Interface is created.
2. A virtual clock will be running throughout the runtime of program starts from arrival of first packet
3. A thread called Timeout will be running in every interface which constantly monitors the virtual clock and last sent or received packet time and
    reports the violations accordingly.
4. When very first packet sent or recevied encountered in .pcap file, attribute like port number, sent/received time  is updated with 
    respective Interface objects.
5. Jitter is calculated and reported if query is 1, the timeout thread is responsible for reporting violations and will be running continously.

TO BE IMPROVED:
1. Since multithreading is used, the output of logfile sequence may be altered with 1 or 2 positions due to availability of CPU for different thread
2. Output is dependent on delay in arrival time since virtual clock is running and due to multithreading.
3. some variables behaviour need to be checked if packet is received before port number is assigned to corresponding interface.


## MUX simulation:
inputs: host, filename, outputfile

FUNCTION:
1. checks the packet crafting possibilities in  partner information manipulation.
2. checks decisions dependent on partner state (collecting cannot be done if partner is not sync, distributing cannot be done if partner is not collecting).
3. reports change in the actor or partner information exchanged.
4. reports if violation done in actor or partner state in sequence (synchronization, collecting, distributing).
5. Simulates the MUX machine transition in response to packets exchanged.

LOGIC:
1. A class called statemachine is created where MUX states and transitions are defined, each object will be created for each host.
2. Packet sanitization is done to check anomalies
3. Based on current state of machine, possible decisions, transitions and reasons are logged in to log file

TO BE IMPROVED:
1. If packet is received first, some behaviour is not predicted or packet is ignored right now.
2. ...





## PCAP Utility
The following are the utility functions related to LACP PDU
1. get_PDU(p) - outputs PDU in dictionary format, each field as key
2. print_PDU_info(p) - prints the PDU field by field
3. get_actor_state(p) - actor state of the PDU is returned in dictionary format
4. get_partner_state(p) - partner state of the PDU is returned in dictionary format
5. get_sender_address(p) - return the address of the sender of Packet
6. validate_packet(p) - Validates the packet in regard to LACP protocol - protocol type, LACP version, etc




