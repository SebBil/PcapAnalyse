import argparse
import logging
import textwrap
from collections import Counter

import coloredlogs
import dpkt
import netifaces
import pcapy
from cryptography.x509.oid import NameOID

import Parser
from GetRootCAs import GetRootCAs
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np


class PcapAnalyzer(object):
    def __init__(self, args):
        self.logger = logging.getLogger('pcap_analysis')
        coloredlogs.install(level='INFO', logger=self.logger)
        self.cert_mgr = []
        self.interface = args.interface
        self.file = args.file
        self.list_interfaces = args.list_interfaces
        self.debug = args.debug
        self.ca_folder = args.ca_folder
        self.captured_packets = 0
        self.countries = []
        self.usedRootCAs = []
        self.usedCipherSuites = []
        self.parser = None

    def run(self):
        if self.list_interfaces:
            self.list_interfaces()
            exit()
        if self.debug:
            coloredlogs.install(level='DEBUG', logger=self.logger)

        # Read certificates in, maybe give a root ca folder in params or load it from the website into the current working directory
        sub = GetRootCAs(self.ca_folder)
        sub.get_roots(self.cert_mgr)

        if self.interface:
            self.start_listening()

        if self.file:
            self.logger.info("Start reading file...")
            self.read_file()

    def list_interfaces(self):
        """Prints out all available interfaces with IP adresses, when possible."""
        for dev in pcapy.findalldevs():
            queryname = dev
            if dev.startswith(r'\Device\NPF_'):
                queryname = dev[12:]
            try:
                self.logger.info(dev + " - " + netifaces.ifaddresses(queryname)[netifaces.AF_INET][0]['addr'])
            except Exception as e:
                self.logger.info("Error occured on listing available interfaces")
                self.logger.debug(str(e))

    def read_file(self):
        self.parser = Parser.Parser(self.cert_mgr)
        try:
            with open(self.file, 'rb') as f:
                capture = dpkt.pcap.Reader(f)

                for timestamp, packet in capture:
                    self.captured_packets += 1
                    self.parser.analyze_packet(timestamp, packet)
        except IOError:
            self.logger.warning('could not parse {0}'.format(filename))

    def start_listening(self):
        """
        Starts the listening process with an optional filter.
        """
        cap = pcapy.open_live(self.interface, 65536, 1, 0)

        self.parser = Parser.Parser(self.cert_mgr)
        try:
            # start sniffing packets
            while True:
                (header, packet) = cap.next()
                try:
                    # logger.info('%s: captured %d bytes' % (datetime.now(), header.getlen()))
                    self.captured_packets += 1
                    self.parser.analyze_packet(header, packet)
                except Exception as e:
                    self.logger.warning(str(e))
        except KeyboardInterrupt as key:
            exit()

    def plot_statistics(self):
        countries = []
        used_root_cas = []
        for _tree in self.cert_mgr:
            if len(_tree.all_nodes()) > 1:
                try:
                    used_root_cas.append((_tree.get_node(_tree.root).data.subject.rfc4514_string(),
                                          _tree.get_node(_tree.root).frequency))
                    countries.append((_tree.get_node(_tree.root).data.subject.get_attributes_for_oid(
                        NameOID.COUNTRY_NAME)[0].value,))
                except:
                    pass
                _tree.show()
        res = []
        temp = set()
        counter = Counter(countries)
        for sub in countries:
            if sub not in temp:
                res.append((counter[sub],) + sub)
                temp.add(sub)
        if len(res) > 0:
            value1, label = zip(*res)
            f = plt.figure(1)
            plt.pie(value1, labels=label, autopct='%1.0f%%')

        if len(used_root_cas) > 0:
            objects, value2 = zip(*used_root_cas)
            g = plt.figure(2)
            yvals = range(len(objects))
            plt.barh(yvals, value2, align='center', alpha=0.4)
            plt.yticks(yvals, objects)
            plt.title('Used Root Certificates Count')

        plt.show()

    def print_statistics(self):
        print("*" * 50 + " Statistics " + "*" * 50)
        print("Captured Packets:            %d" % self.captured_packets)
        print("Count Handshake Messages     %d" % self.parser.count_handshake_messages)
        print("Count Certificate Messages:  %d" % self.parser.count_certificate_messages)
        print("Count Cert match Cert        %d" % self.parser.count_cert_chains_added)
        print("*" * 50 + " Statistics " + "*" * 50)


def parse_arguments():
    """
    Parses command line arguments.
    """
    global filename
    global cap_filter
    global interface
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            '''Captures, parses and shows TLS Handshake packets and analyze the Root Certification Authorities'''))
    parser.add_argument('--list-interfaces', action='store_true',
                        help='list all available interfaces and exit')
    parser.add_argument('-i', '--interface', action='store',
                        help='the interface to listen on')
    parser.add_argument('-f', '--file', metavar='FILE', action='store',
                        help='read from file (don\'t capture live packets)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='increase output verbosity')
    parser.add_argument('-c', '--ca_folder', action='store', metavar='DIRECTORY',
                        help='the folder where the root CA certificates stored. Provide the full path!')
    return parser.parse_args()


def main():
    args = parse_arguments()

    analyzer = PcapAnalyzer(args)
    analyzer.run()

    analyzer.print_statistics()
    analyzer.plot_statistics()


if __name__ == "__main__":
    main()
