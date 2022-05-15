import logging
from LACP import *
import sys
import os

class NPA:
    def take_input(self):
        raise NotImplementedError()

    def run_analyzer(self):
        raise NotImplementedError()


if __name__ == '__main__':
    input_file = sys.argv[1]    # 0 is of pythonfile name, 1 is input,.....
    with open(input_file) as f:
        lines = f.readlines()
    if len(lines) == 0:
        print('Input file is empty')
        exit(0)
    pcap_file = lines[0][lines[0][:-1].rfind('/')+1:]
    output_file = lines[0][lines[0][:-1].rfind('/')+1:lines[0][:-1].rfind('.')]+'_output.log'
    path = lines[0][lines[0].rfind(" ")+1:lines[0][:-1].rfind('/')+1]
    subscript = 0
    while os.path.exists(path+output_file) is True:
        subscript = subscript + 1
        output_file = output_file[:output_file.rfind('_')]+'_output'+str(subscript)+'.log'
    print('\n\nAnalysis will be stored in : ', path, output_file,"\n\n",sep='')

    if len(lines[1]) == 0:
        print("Protocol not specified, analysis cannot be done")
        exit(0)
    protocol = lines[1][lines[1].rfind(' ')+1:-1]
    if protocol.upper() != 'LACP':
        print(protocol.upper(), 'is not yet developed, only LACP available')
        exit(0)
    logging.basicConfig(filename=path[:-1]+'/'+output_file, level=logging.DEBUG, format='%(levelname)s - %(message)s')
    logging.debug("Initializing...")
    npa = LacpNPA()
    logging.debug("Starting Analyzer")
    npa.run_analyzer(lines)

