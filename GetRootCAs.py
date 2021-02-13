import binascii
import logging
import os

import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes

import RootCATree

logger = logging.getLogger()


class GetRootCAs(object):

    @staticmethod
    def get_all_roots_from_web(url, path):
        """
        Load the regular Website of the sample included CA Certificates for Microsoft so we get all trusted roots
        and safe this certificates to an RootCAs folder in the working directory
        Sample Websites:https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT

        :param path:
        :param url:
        :return:
        """
        logger.info("[-] Trying to download and safe the certificates... ")
        resp = requests.get(url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        links = soup.find_all('a')
        count = 0
        cwd = os.getcwd()
        ca_folder = os.path.join(cwd, path)

        if not os.path.exists(ca_folder):
            os.makedirs(ca_folder)
        if os.listdir(ca_folder):
            logger.info("Directory: %s is not emtpy. %s files" % (ca_folder, len(os.listdir(ca_folder))))
            remove = 'z'
            while remove not in ['y', 'n']:
                remove = input("Should it cleared now to update all certificates? [y/n]: ")
                if 'y' == remove:
                    for f in os.listdir(ca_folder):
                        os.remove(os.path.join(ca_folder, f))
                    logger.info("Removed all file in Directory: %s" % ca_folder)
                if 'n' == remove:
                    pass

    @staticmethod
    def get_all_roots_from_folder(path, cert_mgr):
        system = os.walk(path, topdown=True)
        count = 0
        for root, dir, files in system:
            logger.info("Try to read Certificates from %s" % root)
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    crt = open(file_path).read()
                    cert = x509.load_pem_x509_certificate(crt.encode(), default_backend())
                    _tree = RootCATree.RootCATree(node_class=RootCATree.CertNode)
                    _tree.create_node(tag=cert.subject.rfc4514_string(),
                                      identifier=binascii.hexlify(cert.fingerprint(hashes.SHA256())),
                                      data=cert)
                    cert_mgr.append(_tree)
                    count += 1
                    logger.info("Successfully load %d of %d Certificates" % (count, len(files)))
                except Exception as e:
                    logger.warning(str(e))

        logger.info("***************** Finished. Read all Root CA's from {} *****************".format(path))