# NPA
## Jitter Calculation:
inputs : host, filename, query, tz, outputfile
  1. Host is list of MAC IDs of interfaces at which jitter is to be calculated
  2. filename is .pcap file address which is to be processed for jitter calculation
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




