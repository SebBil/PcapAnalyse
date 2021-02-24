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
        self.usedCipherSuites = []
        self.parser = None

    def run(self):
        if self.list_interfaces:
            self.list_interfaces()
            exit()
        if self.debug:
            coloredlogs.install(level='DEBUG', logger=self.logger)

        # Read certificates in, maybe give a root ca folder in params or load it from the website into the current
        # working directory
        sub = GetRootCAs(self.ca_folder)
        sub.get_roots(self.cert_mgr)

        # Instantiate a Parser
        self.parser = Parser.Parser(self.cert_mgr, self.usedCipherSuites)

        if self.interface:
            self.start_listening()

        if self.file:
            self.read_file()

    def list_interfaces(self):
        """Prints out all available interfaces with IP addresses, when possible."""
        for dev in pcapy.findalldevs():
            query_name = dev
            if dev.startswith(r'\Device\NPF_'):
                query_name = dev[12:]
            try:
                self.logger.info(dev + " - " + netifaces.ifaddresses(query_name)[netifaces.AF_INET][0]['addr'])
            except Exception as e:
                self.logger.info("Error occurred on listing available interfaces")
                self.logger.debug(str(e))

    def read_file(self):
        self.logger.info("Start reading file '{}' ...".format(self.file))
        try:
            with open(self.file, 'rb') as f:
                capture = dpkt.pcap.Reader(f)

                for timestamp, packet in capture:
                    self.captured_packets += 1
                    self.parser.analyze_packet(timestamp, packet)
        except IOError:
            self.logger.warning('could not parse {0}'.format(self.file))

    def start_listening(self):
        """
        Starts the listening process with an optional filter.
        """
        self.logger.info("Start listening on interface '{}' ...".format(self.interface))
        cap = pcapy.open_live(self.interface, 65536, 1, 0)

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
            exit(1)

    def plot_statistics(self):
        countries = []
        used_root_cas = []
        for _tree in self.cert_mgr:
            if len(_tree.all_nodes()) > 1:
                try:
                    subj = _tree.get_node(_tree.root).data.subject
                    cn = None
                    ou = None
                    for attr in subj:
                        oid_obj = attr.oid
                        if oid_obj.dotted_string == "2.5.4.3":      # CommonName
                            cn = attr.value
                        if oid_obj.dotted_string == "2.5.4.11":     # OrganizationalUnitName
                            ou = attr.value

                    if cn is not None:
                        used_root_cas.append((cn, _tree.get_node(_tree.root).frequency))
                    elif ou is not None:
                        used_root_cas.append((ou, _tree.get_node(_tree.root).frequency))
                    else:
                        countries.append((_tree.get_node(_tree.root).data.subject.rfc4514_string(), _tree.get_node(_tree.root).frequency))
                    try:
                        countries.append((_tree.get_node(_tree.root).data.subject.get_attributes_for_oid(
                            NameOID.COUNTRY_NAME)[0].value,))
                    except Exception as ex:
                        self.logger.warning("Subject has no country listed. Error: {}".format(str(ex)))
                except Exception as e:
                    self.logger.warning(str(e))

                _tree.show()
        res_countries = []
        temp = set()
        counter = Counter(countries)
        for sub in countries:
            if sub not in temp:
                res_countries.append((counter[sub],) + sub)
                temp.add(sub)

        res_used_ciphers = []
        temp.clear()
        counter = Counter(self.usedCipherSuites)
        for sub in self.usedCipherSuites:
            if sub not in temp:
                res_used_ciphers.append((counter[sub],) + sub)
                temp.add(sub)

        if len(res_countries) > 0:
            fig1, ax1 = plt.subplots()
            value1, label = zip(*res_countries)
            ax1.set_title('Locations of the signing Root CAs')
            ax1.pie(value1, labels=label, autopct='%1.0f%%')

        if len(used_root_cas) > 0:
            fig2, ax2 = plt.subplots(figsize=(15, 5))
            plt.subplots_adjust(left=0.2)
            objects, value2 = zip(*used_root_cas)
            y_val = range(len(objects))
            ax2.barh(y_val, value2, align='center', alpha=0.4)
            ax2.set_yticks(y_val)
            ax2.set_yticklabels(objects)
            ax2.set_title('Used Root Certificates Count')
            ax2.set_xlabel('Count Root CA certificate used')

        if len(res_used_ciphers) > 0:
            fig3, ax3 = plt.subplots(figsize=(10, 5))
            value3, label = zip(*res_used_ciphers)
            ax3.pie(value3, labels=label, autopct='%1.0f%%')
            ax3.set_title('Used Cipher Suites')

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
