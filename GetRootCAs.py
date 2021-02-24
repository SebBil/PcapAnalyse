import binascii
import logging
import os
from urllib.parse import urlparse, parse_qs
import datetime

import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes

import RootCATree
import CertNode

logger = logging.getLogger()


class GetRootCAs(object):

    def __init__(self, folder):
        self.logger = logging.getLogger('pcap_analysis.get_root_cas')
        self.root_ca_folder = folder
        self.root_ca_download_url = r'https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT'

    def get_roots(self, cert_mgr):
        if self.root_ca_folder is None:
            self.logger.info("No certificates folder given, set to RootCAs in the current working directory")
            self.root_ca_folder = r'RootCAs'
            self._get_all_roots_from_web()

            cwd = os.getcwd()
            ca_folder_path = os.path.join(cwd, self.root_ca_folder)
            self._load_root_cas(ca_folder_path, cert_mgr)
        else:
            self._load_root_cas(self.root_ca_folder, cert_mgr)

    def _get_all_roots_from_web(self):
        """
        Load the regular Website of the sample included CA Certificates for Microsoft so we get all trusted roots
        and safe this certificates to an RootCAs folder in the working directory
        Sample Websites:https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT

        :param path:
        :param url:
        :return:
        """
        # self.logger.info("[*] Trying to download and safe the certificates... ")
        resp = requests.get(self.root_ca_download_url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        links = soup.find_all('a', href=True)
        count = 1
        cwd = os.getcwd()
        ca_folder_path = os.path.join(cwd, self.root_ca_folder)

        if not os.path.exists(ca_folder_path):
            os.makedirs(ca_folder_path)
        if os.listdir(ca_folder_path):
            self.logger.info("Directory: %s is not emtpy. %s files" % (ca_folder_path, len(os.listdir(ca_folder_path))))
            remove = 'z'
            while remove not in ['y', 'n']:
                remove = input("Should it cleared now to update all certificates? [y/n]: ")
                if 'y' == remove:
                    for f in os.listdir(ca_folder_path):
                        os.remove(os.path.join(ca_folder_path, f))
                    self.logger.info("Removed all file in Directory: %s" % ca_folder_path)
                if 'n' == remove:
                    pass
        links_len = len(links)
        for link in links:
            self.logger.info("[*] Trying to download {} of {} from {}".format(count, links_len, link['href']))
            cert = requests.get(link['href'])
            parsed = urlparse(link['href'])
            filename = ''.join((parse_qs(parsed.query)["d"][0], ".crt"))
            abs_path = os.path.join(ca_folder_path, filename)
            # print(cert.content)
            with open(abs_path, 'wb') as f:
                f.write(cert.content)
            count += 1

    def _load_root_cas(self, path, cert_mgr):
        system = os.walk(path, topdown=True)
        count = 0
        self.logger.info("Start reading Certificates from {}".format(path))
        for root, dir, files in system:
            self.logger.info("Try to read Certificates from %s" % root)
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    crt = open(file_path).read()
                    cert = x509.load_pem_x509_certificate(crt.encode(), default_backend())
                    _tree = RootCATree.RootCATree(node_class=CertNode.CertNode)
                    _tree.create_node(tag=cert.subject.rfc4514_string(),
                                      identifier=binascii.hexlify(cert.fingerprint(hashes.SHA256())),
                                      data=cert)

                    # append only if the cert is valid and not disabled
                    in_time = self.time_in_range(cert.not_valid_before, cert.not_valid_after, datetime.datetime.now())

                    if in_time:
                        cert_mgr.append(_tree)
                        count += 1
                        self.logger.info("Successfully load %d of %d Certificates" % (count, len(files)))
                    else:
                        self.logger.info("Certificate '{}' is no valid anymore".format(cert.fingerprint(hashes.SHA256())))
                        self.logger.debug("Not valid before: {}".format(cert.not_valid_before))
                        self.logger.debug("Current GMT Time: {}".format(
                            datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))
                        self.logger.debug("Not valid after:  {}".format(cert.not_valid_after))
                except Exception as e:
                    self.logger.warning(str(e))

        self.logger.info("***************** Finished. Read all Root CA's from {} *****************".format(path))

    def time_in_range(self, start, end, x):
        """ Return true if x is in the range [start, end]"""
        if start <= end:
            return start <= x <= end
        else:
            return start <= x or x <= end
