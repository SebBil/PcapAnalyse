import argparse
import binascii
import logging
import os
import shutil
import textwrap
from collections import Counter
from datetime import datetime

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
        self.count_used_root_cas = 0
        self.logger = None
        self.cert_mgr = []
        self.interface = args.interface
        self.file = args.file
        self.list_interfaces = args.list_interfaces
        # self.info = args.info
        self.ca_folder = args.ca_folder
        self.captured_packets = 0
        self.usedCipherSuites = []
        self.parser = None
        self.start_time = None
        self.end_time = None
        self.cumulative_root_intermediate_ca = 0
        self.root_ca_with_no_skid = None
        self.root_ca_not_valid = None
        self.root_ca_count = None

    def init_logging_read_file(self):
        self.logger = logging.getLogger("PcapAnalyzer")
        self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)

        # creating log directory if not exist
        cwd = os.getcwd()
        log_dir = os.path.join(cwd, f"log")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        if self.file:
            log_file = os.path.join(log_dir, self.file.split('\\')[-1].split('.')[0] + f".log")
        else:
            log_file = os.path.join(log_dir, datetime.now().strftime('PcapAnalyzer_%H_%M_%d_%m_%Y.log'))

        fh = logging.FileHandler(log_file, 'w', 'utf-8')

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # creating a formatter
        formatter = logging.Formatter('%(asctime)s  %(name)s  %(levelname)s: %(message)s')

        # setting handler format
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        # add the handlers to the logger
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def run(self):
        """
        Run Method of the Pcap Analyser, method decides which mode is running.
        Live capturing or pcap read file.
        """
        if self.list_interfaces:
            self.list_possible_interfaces()
            exit()

        self.init_logging_read_file()
        # Read certificates in, maybe give a root ca folder in params or
        # load it from the website into the current working directory
        sub = GetRootCAs(self.ca_folder)
        self.root_ca_count, self.root_ca_with_no_skid, self.root_ca_not_valid = sub.get_roots(self.cert_mgr)

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
                print(dev + " - " + netifaces.ifaddresses(query_name)[netifaces.AF_INET][0]['addr'])
            except Exception as e:
                pass
                # self.logger.info("Error occurred on listing available interfaces")
                # print(str(e))

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
            exit(-1)
        except Exception as e:
            if 'NoneType' in str(e):
                pass
            else:
                print("You trying to parse pcapng file. This isn't support by PcapAnalysis\n"
                    "Try to convert your file with editcap that's included in wireshark.\n"
                    "$ .\editcap.exe -F libpcap <INPUT_FILE> <OUTPUT_FILE>\n"
                    "editcap is located in wiresharks installation folder.")
                exit(1)
        self.end_time = datetime.now()
        self.logger.info("End of File reached, analyse certificate chains...")

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
                    self.captured_packets += 1
                    self.parser.analyze_packet(timestamp, packet)
                except Exception as e:
                    self.logger.warning(str(e))
        except KeyboardInterrupt as key:
            self.logger.info("Stopping live capturing and prepare statistics...")
        self.end_time = datetime.now()

    def plot_statistics(self):
        cwd = os.getcwd()
        countries = []
        used_root_cas = []
        cumulative_time_ca = []
        for _tree in self.cert_mgr:
            if len(_tree.all_nodes()) > 1:
                self.count_used_root_cas += 1
                self.cumulative_root_intermediate_ca += len(_tree.all_nodes())
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
                        self.logger.info("Subject has no country listed.".format(str(ex)))

                    cumulative_time_ca.append(_tree.get_node(_tree.root).first_seen)
                except Exception as e:
                    self.logger.warning(str(e))

                filepath = os.path.join(cwd, self.file.split('\\')[-1].split('.')[0] + f"_Graphvizes")
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

        self.logger.info(res_used_ciphers)
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
            value3, labels = zip(*res_used_ciphers)
            max_len = max(len(l) for l in labels)
            percent = []
            for i in value3:
                percent.append(i*100/sum(value3))
            labels = ['{0} {1:1.2f}%'.format(l.ljust(40), s) for l, s in zip(labels, percent)]
            ax3.pie(value3)
            ax3.set_title('Used Cipher Suites')
            ax3.legend(labels, bbox_to_anchor=(1.05, 1), loc='upper left', prop=fontP)

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

        # self.produce_svg()
        self.print_statistics()
        plt.show()

    def print_statistics(self):
        self.logger.info("*" * 20 + " Statistics " + "*" * 20)
        self.logger.info("Time for analysing:               {}".format(self.end_time - self.start_time))
        self.logger.info("Captured Packets:                 {}".format(self.captured_packets))
        self.logger.info("Count Handshake Messages          {}".format(self.parser.count_handshake_messages))
        self.logger.info("Count Certificate Messages:       {}".format(self.parser.count_certificate_messages))
        # self.logger.info("Count Cert match Cert             {}".format(self.parser.count_cert_chains_added))
        # self.logger.info("Count No Cert found               {}".format(self.parser.count_no_certificate_found))
        self.logger.info("Count Certificate Parsing errors: {}".format(self.parser.count_parsing_errors))
        self.logger.info("Loaded Root CA certificates       {}".format(self.root_ca_count))
        self.logger.info("Count Root CA with no SKID:       {}".format(self.root_ca_with_no_skid))
        self.logger.info("Count Root CA not valid cert:     {}".format(self.root_ca_not_valid))
        self.logger.info("Count Root and Intermediate CA    {}".format(self.cumulative_root_intermediate_ca))
        self.logger.info("*" * 20 + " Statistics " + "*" * 20)

        unique_trees = dict()
        for cert in self.parser.cert_with_no_parent:
            thumbprint = binascii.hexlify(cert.fingerprint(hashes.SHA256()))
            if thumbprint not in unique_trees:
                unique_trees[thumbprint] = cert

        self.logger.info("*"*20 + "Certificates that are not added" + "*"*20)
        for thumbprint, cert in unique_trees.items():
            self.logger.warning("Cert subject: {}".format(cert.subject.rfc4514_string()))
            self.logger.warning("|----Thumbprint of the cert: {}".format(thumbprint.decode()))
            # self.logger.warning("|----SKID: ".format())
            # self.logger.warning("|----AKID: ")
            # tree.show()
        self.logger.info("*"*20 + "Certificates that are not added" + "*"*20)

    def produce_svg(self):
        # check if dot.exe is in path
        command = 'dot.exe'
        if shutil.which(command) is None:
            self.logger.info("No graphics can be created. Missing dot executeable")
            return

        cwd = os.getcwd()
        filepath = os.path.join(cwd, self.file.split('\\')[-1].split('.')[0] + f"_Graphvizes")
        self.logger.info("Graphviz is installed. Create svg from dot files in folder '{}".format(filepath))
        files = os.listdir(filepath)
        for file in files:
            abs_path = os.path.join(filepath, file)
            cmd = 'dot -Tsvg "{}" -o "{}.svg"'.format(abs_path, abs_path)
            os.system(cmd)


def parse_arguments():
    """
    Parses command line arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            '''
            ################
            # PcapAnalyzer #
            ################
            Captures, parses and shows TLS Handshake packets and analyze the Certificate Chains
            Out of the certificate chains the PcapAnalyzer create some interesting graphics that shows
            the used root and intermediate certificates, the used cipher suites and a cumulative line
            when the certificates first seen in a plot from matplotlib.
            '''
        ))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--list-interfaces', action='store_true',
                        help='list all available interfaces and exit')
    group.add_argument('-i', '--interface', action='store',
                        help='the interface to listen on')
    group.add_argument('-f', '--file', metavar='FILE', action='store',
                        help='read from file (don\'t capture live packets)')
    parser.add_argument('-c', '--ca_folder', action='store', metavar='DIRECTORY',
                        help='the folder where the root CA certificates stored. Provide the full path!')
    return parser.parse_args()


def main():
    args = parse_arguments()

    analyzer = PcapAnalyzer(args)
    analyzer.run()

    # analyzer.print_statistics()
    analyzer.plot_statistics()
    analyzer.produce_svg()


if __name__ == "__main__":
    main()
