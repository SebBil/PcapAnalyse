import logging
from treelib import Tree, exceptions
from cryptography import x509


class RootCATree(Tree):
    def __init__(self, node_class=None):
        super().__init__(node_class=node_class)
        self.logger = logging.getLogger('pcap_analysis.root_ca_tree')

    def create_node(self, tag=None, identifier=None, parent=None, data=None):
        node = self.node_class(tag=tag, identifier=identifier, data=data)
        self.add_node(node, parent)
        return node

    def search_add_nodes(self, nodes):
        self.logger.debug("[*] Searching in ca tree:")
        # self.show()

        for ca_tree_node in self.all_nodes():
            try:
                search_aid = nodes[0].data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
                cur_ca_sid = ca_tree_node.data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
            except Exception as e:
                self.logger.debug("[-] Root CA Node: {}".format(ca_tree_node.tag))
                self.logger.debug("[-] Error: {}".format(str(e)))
                self.logger.debug("[-] skipping this root ca")
                continue
            if ca_tree_node.identifier == nodes[0].identifier or search_aid == cur_ca_sid:
                self.logger.info("[+] Right CA tree found. Try adding nodes")

                self.logger.info(ca_tree_node.data.subject.rfc4514_string())
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

                # self.show()
                return True
        return False

    def plot_tree(self):
        pass


