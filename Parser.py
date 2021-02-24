import binascii
import logging
import socket
import struct
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import dpkt

import Constants
import RootCATree


class Parser(object):
    def __init__(self, crt_m, used_cs):
        self.root_ca_tree_list = crt_m
        self.used_cipher_suites = used_cs
        self.streambuffer = {}
        self.encrypted_streams = []
        self.count_certificate_messages = 0
        self.count_cert_chains_added = 0
        self.count_handshake_messages = 0
        self.logger = logging.getLogger('pcap_analysis.parser')

    def analyze_packet(self, ts, pkt):
        """
        Main analysis loop for pcap.
        """
        eth = dpkt.ethernet.Ethernet(pkt)
        if isinstance(eth.data, dpkt.ip.IP):
            self.parse_ip_packet(eth.data)

    def parse_ip_packet(self, ip):
        """
        Parses IP packet.
        """
        if isinstance(ip.data, dpkt.tcp.TCP) and len(ip.data.data):
            self.parse_tcp_packet(ip)

    def parse_tcp_packet(self, ip):
        """
        Parses TCP packet.
        """
        connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src), ip.data.sport, socket.inet_ntoa(ip.dst),
                                              ip.data.dport)
        if ip.data.data[0] in {20, 21, 22}:
            stream = ip.data.data
        else:
            if connection in self.streambuffer:
                self.logger.debug('[*] Added sequence number {0:12d} to buffer'.format(ip.data.seq))
                stream = self.streambuffer[connection] + ip.data.data
                del self.streambuffer[connection]
                if len(stream) > 10000:
                    self.logger.debug('[*] Flushed buffer ({0} bytes)'.format(len(stream)))
            else:
                if ip.data.data[0] == 23 and connection in self.encrypted_streams:
                    self.logger.debug('[+] Encrypted data between {0}'.format(connection))
                return
        self.parse_tls_records(ip, stream)

    def add_to_buffer(self, ip, partial_stream):
        """
        Adds partial_stream of ip to global stream buffer.
        """
        connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                              ip.data.sport,
                                              socket.inet_ntoa(ip.dst),
                                              ip.data.dport)
        self.streambuffer[connection] = partial_stream
        self.logger.debug(
            '[*] Added {0} bytes (seq {1}) to streambuffer for {2}'.format(len(partial_stream), ip.data.seq, connection))

    def parse_tls_records(self, ip, stream):
        """
        Parses TLS Records.
        """
        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
        except dpkt.ssl.SSL3Exception as exception:
            self.logger.debug('[-] Exception (tls_multi_factory) while parsing TLS records: {0}'.format(exception))
            return
        connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src), ip.data.sport, socket.inet_ntoa(ip.dst),
                                              ip.data.dport)

        if bytes_used != len(stream):
            self.add_to_buffer(ip, stream[bytes_used:])
        for record in records:
            self.logger.debug('[*] Captured TLS record type {0}'.format(record.type))
            if record.type == 22:
                self.parse_tls_handshake(ip, record.data, record.length)
            if record.type == 21:
                self.logger.info('[+] TLS Alert message in connection: {0}'.format(connection))
            if record.type == 20:
                self.logger.info('[+] Change cipher - encrypted messages from now on for {0}'.format(connection))
                self.encrypted_streams.append(connection)
            sys.stdout.flush()

    def unpacker(self, type_string, packet):
        """
        Returns network-order parsed data and the packet minus the parsed data.
        """
        if type_string.endswith('H'):
            length = 2
        if type_string.endswith('B'):
            length = 1
        if type_string.endswith('P'):  # 2 bytes for the length of the string
            length, packet = self.unpacker('H', packet)
            type_string = '{0}s'.format(length)
        if type_string.endswith('p'):  # 1 byte for the length of the string
            length, packet = self.unpacker('B', packet)
            type_string = '{0}s'.format(length)
        data = struct.unpack('!' + type_string, packet[:length])[0]
        if type_string.endswith('s'):
            data = ''.join(data.hex())
        return data, packet[length:]

    def parse_tls_handshake(self, ip, data, record_length):
        """
        Parses TLS Handshake message contained in data according to their type.
        """
        connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src), ip.data.sport, socket.inet_ntoa(ip.dst),
                                              ip.data.dport)

        if connection in self.encrypted_streams:
            self.logger.info('[+] Encrypted handshake message between {0}'.format(connection))
            return
        else:
            total_len_consumed = 0
            while total_len_consumed < record_length:
                payload = data[total_len_consumed:]
                try:
                    handshake_type = ord(payload[:1])
                    if handshake_type == 4:
                        self.logger.debug('[#] New Session Ticket is not implemented yet')
                        return
                    elif handshake_type == 22:
                        jump_bytes = payload[1:4]
                        jump_bytes = int.from_bytes(jump_bytes, 'big')
                        total_len_consumed += jump_bytes + 4
                        continue
                    else:
                        handshake = dpkt.ssl.TLSHandshake(payload)
                except Exception as exception:
                    self.logger.debug('[-] Exception while parsing TLS handshake record: {0}'.format(exception))
                    return
                client = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
                server = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)

                total_len_consumed += handshake.length + 4
                self.count_handshake_messages += 1

                if handshake.type == 0:
                    self.logger.info('[+] Hello Request {0} <- {1}'.format(client, server))
                if handshake.type == 1:
                    self.logger.info('[+] ClientHello {0} -> {1}'.format(client, server))
                if handshake.type == 2:
                    self.logger.info('[+] ServerHello {1} <- {0}'.format(client, server))
                    self.parse_server_hello(handshake.data)
                if handshake.type == 11:
                    self.logger.info('[+] Certificate {0} <- {1}'.format(client, server))
                    self.parse_server_certificate(handshake.data, client, server)
                if handshake.type == 12:
                    self.logger.info('[+] ServerKeyExchange {1} <- {0}'.format(server, client))
                if handshake.type == 13:
                    self.logger.info('[+] CertificateRequest {1} <- {0}'.format(client, server))
                if handshake.type == 14:
                    self.logger.info('[+] ServerHelloDone {1} <- {0}'.format(client, server))
                if handshake.type == 15:
                    self.logger.info('[+] CertificateVerify {0} -> {1}'.format(client, server))
                if handshake.type == 16:
                    self.logger.info('[+] ClientKeyExchange {0} -> {1}'.format(client, server))
                if handshake.type == 20:
                    self.logger.info('[+] Finished {0} -> {1}'.format(client, server))

    def parse_server_hello(self, handshake):
        """
        Parses server hello handshake.
        """
        payload = handshake.data
        session_id, payload = self.unpacker('p', payload)
        self.logger.debug('[*]   Session ID: {}'.format(session_id))
        cipher_suite, payload = self.unpacker('H', payload)
        cipher_name = Constants.CIPHER_SUITES.get(cipher_suite)
        self.logger.debug('[*]   Used Cipher: {} - {}'.format(hex(cipher_suite), cipher_name))
        self.used_cipher_suites.append((cipher_name, ))

    def parse_server_certificate(self, tls_cert_msg, client, server):
        """
        Parses the certificate message
        """
        connection_key = "{}-{}".format(client, server)

        assert isinstance(tls_cert_msg, dpkt.ssl.TLSCertificate)
        self.count_certificate_messages += 1
        _tree = RootCATree.RootCATree(node_class=RootCATree.CertNode)
        pre = None
        for crt in reversed(tls_cert_msg.certificates):
            try:
                cert = x509.load_der_x509_certificate(crt, default_backend())

                _tree.create_node(tag=cert.subject.rfc4514_string(),
                                  identifier=binascii.hexlify(cert.fingerprint(hashes.SHA256())),
                                  data=cert,
                                  parent=pre)
                pre = binascii.hexlify(cert.fingerprint(hashes.SHA256()))
            except Exception as e:
                self.logger.warning("[-] Shit happens: Error: {}".format(e))
                self.logger.warning("[-] Error occurred on connection: {}".format(connection_key))
                self.logger.warning("[-] Skip this certificate chain...")
                return

        # _tree.show()
        nodes = _tree.all_nodes()
        found = False
        for num, ca_tree in enumerate(self.root_ca_tree_list):
            self.logger.debug("[+] Try find subtree in {} of {}".format(num + 1, len(self.root_ca_tree_list)))
            found = ca_tree.search_add_nodes(nodes)
            if found:
                # self.logger.info("Found tree and successfully added certificate chain")
                self.count_cert_chains_added += 1
                break

        if not found:
            self.logger.warning("[!] No Root certificate found")
            _tree.show()
