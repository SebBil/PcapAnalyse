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
        # self.show()

        for ca_tree_node in self.all_nodes():
            try:
                search_aid = nodes[0].data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
                cur_ca_sid = ca_tree_node.data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
            except Exception as e:
                self.logger.debug("[-] No valid authority key identifier found in extensions. Check thumbprint...")
                self.logger.debug("[*] Certificate: {}".format(ca_tree_node.tag))
                # Check thumbprint
                search_thumb = nodes[0].identifier
                current_thumb = ca_tree_node.identifier
                if search_thumb == current_thumb:
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
                    # self.show()
                    return True
                continue

            if search_aid == cur_ca_sid:
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

                # self.show()
                return True
        return False

    def safe_tree_to_graphviz(self, filename):
        try:
            self.to_graphviz(filename=filename, shape='oval')
        except Exception as e:
            self.logger.warning("Failed to create file '{}'".format(filename))

        # self.show()
