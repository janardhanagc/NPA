import LacPdu


def run_selection_logic(pkt, index, interfaces):
    for interface in interfaces:
        if LacPdu.is_of_interest(pkt, index, interfaces) and LacPdu.get_src_eth_mac(pkt) == interface.partnerMac:
            interface.selected = 'SELECTED'
