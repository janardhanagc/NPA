import LacPdu


def run_selection_logic(pkt, index, hostEthMacs, interfaces):
    # to be modified
    for interface in interfaces:
        if LacPdu.get_src_eth_mac(pkt) not in hostEthMacs and LacPdu.is_of_interest(pkt,index,interfaces):
            interface.selected='SELECTED'