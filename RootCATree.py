import logging

from treelib import Tree, exceptions
from cryptography import x509


class RootCATree(Tree):
    def __init__(self, node_class=None):
        super().__init__(node_class=node_class)
        self.logger = logging.getLogger("pcap_analysis.root_ca_tree")

    def create_node(self, tag=None, identifier=None, parent=None, data=None):
        node = self.node_class(tag=tag, identifier=identifier, data=data)
        self.add_node(node, parent)
        return node

    def search_nodes(self, nodes, ts):
        self.logger.debug("[*] Searching in ca tree:")

        for ca_tree_node in self.all_nodes():
            try:
                search_sid = nodes[0].data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
                cur_ca_sid = ca_tree_node.data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
                search_aid = nodes[0].data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier

            except Exception as e:
                if 'authorityKeyIdentifier' in str(e):
                    # check subject identifiers equals, if so the root certificate is send with
                    if cur_ca_sid == search_sid:
                        self.insert_into_tree(ca_tree_node, nodes, ts)
                        # self.show()
                        return True
                    else:
                        continue
                else:
                    self.logger.debug("[-] {}".format(str(e)))
                    self.logger.debug("[-] No valid authority key identifier found in extensions.")
                    self.logger.debug("[*] Certificate: {}".format(ca_tree_node.tag))
                    continue

            if search_aid == cur_ca_sid or search_sid == cur_ca_sid:
                self.insert_into_tree(ca_tree_node, nodes, ts)
                return True
        return False

    def insert_into_tree(self, ca_tree_node, nodes, ts):
        self.logger.info("[+] Right CA tree found. Try adding nodes")
        self.logger.info(ca_tree_node.data.subject.rfc4514_string())
        if ca_tree_node.frequency == 0:
            ca_tree_node.first_seen = ts
        ca_tree_node.frequency += 1
        parent = ca_tree_node
        for node in nodes:
            try:
                self.add_node(node=node, parent=parent.identifier)
                self.logger.info("[+] Successfully added node: {}".format(node.tag))
            except exceptions.DuplicatedNodeIdError as duplicate:
                self.logger.debug("[*] Node already exists: {}".format(node.tag))
                pass
            except Exception as e:
                self.logger.warning("[-] Adding node not successfully: {}".format(str(e)))
            parent = node

    def safe_tree_to_graphviz(self, filename):
        try:
            self.to_graphviz(filename=filename, shape='oval')
        except Exception as e:
            self.logger.warning("Failed to create file '{}'".format(filename))
            self.logger.warning("Error message: {}".format(str(e)))

        # self.show()
