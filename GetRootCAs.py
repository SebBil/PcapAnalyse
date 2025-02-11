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
        self.logger = logging.getLogger("PcapAnalyzer." + __name__)
        self.root_ca_folder = folder
        self.no_skid = 0
        self.not_valid = 0
        self.count = 0
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

        return self.count, self.no_skid, self.not_valid

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
            self.logger.info("[*] Directory: %s is not emtpy. %s files" % (ca_folder_path, len(os.listdir(ca_folder_path))))

            remove = 'z'
            while remove not in ['y', 'n']:
                remove = input("Should it cleared now to update all certificates? [y/n]: ")
                if 'y' == remove:
                    for f in os.listdir(ca_folder_path):
                        os.remove(os.path.join(ca_folder_path, f))
                    self.logger.info("[*] Removed all file in Directory: %s" % ca_folder_path)
                if 'n' == remove:
                    pass
        links_len = len(links)
        for link in links:
            self.logger.info("[*] Trying to download {} of {} from {}".format(count, links_len, link['href']))
            cert = requests.get(link['href'])
            parsed = urlparse(link['href'])
            filename = ''.join((parse_qs(parsed.query)["d"][0], ".crt"))
            abs_path = os.path.join(ca_folder_path, filename)
            with open(abs_path, 'wb') as f:
                f.write(cert.content)
            count += 1

    def _load_root_cas(self, path, cert_mgr):
        """
        Load all root certificates from the the given folder and save them into the RootCATree structure
        :param path:
        :param cert_mgr:
        :return:
        """
        system = os.walk(path, topdown=True)

        self.logger.info("[*] Start reading Certificates from {}".format(path))
        for root, dir, files in system:
            self.logger.info("[*] Try to load Certificates from folder: {}".format(root))
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
                    in_time = self._time_in_range(cert.not_valid_before, cert.not_valid_after, datetime.datetime.now())
                    self.logger.info("[+] Certificate {} loaded".format(binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode()))
                    try:
                        self.logger.info("[*] Check certificates authority key identifier and subject key identifier")
                        # check if the ca has the subject key identifier which is mandatory for a ca certificate
                        skid = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
                        akid = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier

                        if skid != akid:
                            self.logger.error("[!] SKID and AKID doesn't match!! Something bad happens to this cert")
                            self.logger.error("[!] Check certificate: {}".format(cert.subject.rfc4514_string()))
                            input("Enter for continue...")

                    except Exception as ex:
                        if 'authorityKeyIdentifier' in str(ex):
                            self.logger.info("[-] Certificate '{}' No Authority Identifier found".format(binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode(), str(ex)))
                            pass
                        elif 'subjectKeyIdentifier' in str(ex):
                            self.no_skid += 1
                            self.logger.error("[-] Certificate '{}' No Subject Identifier found. CA Cert must have a this".format(binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode()))
                            # input("The certificate subject: {}\nThis certificate will not included!\nPress key to continue...".format(cert.subject.rfc4514_string()))
                            continue
                    self.logger.info("[+] Subject key identifier exist")
                    self.logger.info("[*] Check certificate validity")
                    if in_time:
                        cert_mgr.append(_tree)
                        self.count += 1
                        self.logger.info("[+] Certificate is valid")
                        self.logger.info("[+] Successfully {} load {} of {} Certificates".format(cert.subject.rfc4514_string(), self.count, len(files)))
                    else:
                        self.not_valid += 1
                        self.logger.info("[-] Certificate '{}' is no valid anymore".format(binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode()))
                        self.logger.info("[*] Not valid before: {}".format(cert.not_valid_before))
                        self.logger.info("[*] Not valid after:  {}".format(cert.not_valid_after))
                        self.logger.info("[*] Current GMT Time: {}".format(
                            datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))
                except Exception as e:
                    self.logger.warning(str(e))

        self.logger.info("***************** Finished. Read all Root CA's from {} *****************".format(path))

    def _time_in_range(self, start, end, x):
        """ Return true if x is in the range [start, end]"""
        if start <= end:
            return start <= x <= end
        else:
            return start <= x or x <= end
