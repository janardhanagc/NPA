import logging
from LACP import *


class NPA:
    def take_input(self):
        raise NotImplementedError()

    def run_analyzer(self):
        raise NotImplementedError()


if __name__ == '__main__':

    # host='00 81 C4 91 DF AB'
    # filename="/Users/jgowdac/Documents/PCAP FILES/Timestamp shifted/lacp(1)_ext_ts.pcap"
    #host=['00 3A 7D 4D CD A8','00 3A 7D 4D CD A9']
    #filename="/Users/jgowdac/multi.pcap"
    #jitter_query=input('Do you require detailed analysis or summary on Jitter ?(Y for details, N for summary): ' )

    logging.basicConfig(filename='output.log', level=logging.DEBUG, format='%(levelname)s - %(message)s')
    logging.debug("Initializing...")
    npa = LacpNPA()
    logging.debug("Starting Analyzer")
    npa.run_analyzer()
