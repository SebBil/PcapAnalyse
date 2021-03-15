import argparse
import binascii
import logging
import os
import textwrap
from collections import Counter
from datetime import datetime

import coloredlogs
import dpkt
import netifaces
import pcapy
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from matplotlib.font_manager import FontProperties

import Parser
from GetRootCAs import GetRootCAs
import matplotlib.pyplot as plt
import matplotlib.dates as md


class PcapAnalyzer(object):
    def __init__(self, args):
        self.logger = logging.getLogger("pcap_analysis")
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
        self.start_time = None
        self.end_time = None

    def run(self):
        """
        Run Method of the Pcap Analyser, method decides with mode is running.
        Live capturing or pcap read file.
        """
        if self.debug:
            coloredlogs.install(level='DEBUG', logger=self.logger)
        if self.list_interfaces:
            self.list_possible_interfaces()
            exit()

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

    def list_possible_interfaces(self):
        """Prints out all available interfaces with IP addresses, when possible."""
        for dev in pcapy.findalldevs():
            query_name = dev
            if dev.startswith(r'\Device\NPF_'):
                query_name = dev[12:]
            try:
                self.logger.info(dev + " - " + netifaces.ifaddresses(query_name)[netifaces.AF_INET][0]['addr'])
            except Exception as e:
                # self.logger.info("Error occurred on listing available interfaces")
                self.logger.debug(str(e))

    def read_file(self):
        self.logger.info("Start reading file '{}' ...".format(self.file))
        self.start_time = datetime.now()
        try:
            with open(self.file, 'rb') as f:
                capture = dpkt.pcap.Reader(f)

                for timestamp, packet in capture:
                    self.captured_packets += 1
                    self.parser.analyze_packet(timestamp, packet)
        except FileNotFoundError:
            self.logger.warning("File {} doesn't exist. Exiting program".format(self.file))
        except Exception as e:
            print("You trying to parse pcapng file. This isn't support by PcapAnalysis\n"
                    "Try to convert your file with editcap that's included in wireshark.\n"
                    "$ .\editcap.exe -F libpcap <INPUT_FILE> <OUTPUT_FILE>\n"
                    "editcap is located in wiresharks installation folder.")
            exit(1)
        self.end_time = datetime.now()

    def start_listening(self):
        """
        Starts the listening process
        """
        self.logger.info("Start listening on interface '{}' ...".format(self.interface))
        cap = pcapy.open_live(self.interface, 65536, 1, 0)
        self.start_time = datetime.now()
        try:
            # start sniffing packets
            while True:
                (timestamp, packet) = cap.next()
                try:
                    # self.logger.info('%s: captured %d bytes' % (datetime.now(), header))
                    self.captured_packets += 1
                    self.parser.analyze_packet(timestamp, packet)
                except Exception as e:
                    self.logger.warning(str(e))
        except KeyboardInterrupt as key:
            self.logger.info("Stopping live capturing and prepare statistics...")
            pass
            # exit(1)
        self.end_time = datetime.now()

    def plot_statistics(self):
        cwd = os.getcwd()
        countries = []
        used_root_cas = []
        cumulative_time_ca = []
        for _tree in self.cert_mgr:
            if len(_tree.all_nodes()) > 1:
                subj = _tree.get_node(_tree.root).data.subject
                cn = None
                ou = None
                filename = None
                try:
                    for attr in subj:
                        oid_obj = attr.oid
                        if oid_obj == x509.NameOID.COMMON_NAME:
                            cn = attr.value
                        if oid_obj == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                            ou = attr.value

                    if cn is not None:
                        used_root_cas.append((cn, _tree.get_node(_tree.root).frequency))
                        filename = cn
                    elif ou is not None:
                        used_root_cas.append((ou, _tree.get_node(_tree.root).frequency))
                        filename = ou
                    else:
                        used_root_cas.append((_tree.get_node(_tree.root).data.subject.rfc4514_string(),
                                              _tree.get_node(_tree.root).frequency))
                        filename = _tree.get_node(_tree.root).data.subject.rfc4514_string()
                    try:
                        countries.append((_tree.get_node(_tree.root).data.subject.get_attributes_for_oid(
                            x509.NameOID.COUNTRY_NAME)[0].value,))
                    except Exception as ex:
                        self.logger.debug("Subject has no country listed.".format(str(ex)))

                    cumulative_time_ca.append(_tree.get_node(_tree.root).first_seen)
                except Exception as e:
                    self.logger.warning(str(e))

                filepath = os.path.join(cwd, f"Graphvizes")
                if not os.path.exists(filepath):
                    os.makedirs(filepath)
                filepath = os.path.join(filepath, filename)
                _tree.safe_tree_to_graphviz(filepath)

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
            plt.subplots_adjust(left=0.3)
            objects, value2 = zip(*used_root_cas)
            y_val = range(len(objects))
            ax2.barh(y_val, value2, align='center', alpha=0.4)
            ax2.set_yticks(y_val)
            ax2.set_yticklabels(objects)
            ax2.set_title('Used Root Certificates Count')
            ax2.set_xlabel('Count Root CA certificate used')

        if len(res_used_ciphers) > 0:
            fontP = FontProperties()
            fontP.set_size('small')

            fig3, ax3 = plt.subplots(figsize=(10, 5))
            value3, label = zip(*res_used_ciphers)
            patches, texts = ax3.pie(value3)
            ax3.set_title('Used Cipher Suites')
            ax3.legend(patches, label, bbox_to_anchor=(1.05, 1), loc='upper left', prop=fontP)

            plt.axis('equal')
            plt.tight_layout()

        if len(cumulative_time_ca) > 0:
            fig4, ax4 = plt.subplots(figsize=(10, 5))
            cumulative_time_ca = sorted(cumulative_time_ca)
            cumu_value = range(0, len(cumulative_time_ca), 1)
            dates = [datetime.fromtimestamp(ts) for ts in cumulative_time_ca]
            ax4.plot(dates, cumu_value, 'o-')
            plt.subplots_adjust(bottom=0.25)
            plt.xticks(rotation=25)
            xfmt = md.DateFormatter('%Y-%m-%d %H:%M:%S')
            ax4.xaxis.set_major_formatter(xfmt)
            ax4.set_xlabel('Time')
            ax4.set_ylabel('cumulative count CA certs')

        plt.show()

    def print_statistics(self):
        self.logger.info("*" * 50 + " Statistics " + "*" * 50)
        self.logger.info("Time for analysing:               {}".format(self.end_time - self.start_time))
        self.logger.info("Captured Packets:                 {}".format(self.captured_packets))
        self.logger.info("Count Handshake Messages          {}".format(self.parser.count_handshake_messages))
        self.logger.info("Count Certificate Messages:       {}".format(self.parser.count_certificate_messages))
        self.logger.info("Count Cert match Cert             {}".format(self.parser.count_cert_chains_added))
        self.logger.info("Count No Cert found               {}".format(self.parser.count_no_certificate_found))
        self.logger.info("Count Certificate Parsing errors  {}".format(self.parser.count_parsing_errors))
        self.logger.info("*" * 50 + " Statistics " + "*" * 50)

        unique_trees = set(self.parser.chains_with_no_root)
        for chain in unique_trees:
            self.logger.info("Thumbprint of the chain root cert: {}".format(
                binascii.hexlify(chain.get_node(chain.root).data.fingerprint(hashes.SHA256()))))
            chain.show()

    def print_certificate_info(self, cert):
        print(cert)


def parse_arguments():
    """
    Parses command line arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            '''Captures, parses and shows TLS Handshake packets and analyze the Certificate Chains'''))
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
