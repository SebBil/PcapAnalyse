import codecs
import logging

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

from treelib import Tree, exceptions
from cryptography import x509


class RootCATree(Tree):
    def __init__(self, node_class=None):
        super().__init__(node_class=node_class)
        self.logger = logging.getLogger("PcapAnalyzer." + __name__)

    def create_node(self, tag=None, identifier=None, parent=None, data=None):
        node = self.node_class(tag=tag, identifier=identifier, data=data)
        self.add_node(node, parent)
        return node

    def check_if_is_root_ca(self, root, search, ts):
        try:
            cur_root_ca_sid = root.data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
            search_sid = search.data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
            if cur_root_ca_sid == search_sid:
                self.logger.info("[+] Identical root found: {}".format(root.tag))
                self.logger.info("[*] Adding frequency and timestamp if not seen before")
                if root.frequency == 0:
                    root.first_seen = ts
                root.frequency += 1
                return True
        except:
            self.logger.info("Check if is root ca failed.")

    def search_nodes(self, search_node, ts):
        for node in self.all_nodes():
            cur_root_ca_sid = node.data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
            search_aid = search_node.data.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
            if search_aid == cur_root_ca_sid:
                self.logger.info("[*] Found Parent node: {}".format(node.tag))
                self.insert_into_tree(node, search_node, ts)
                return True

    def insert_into_tree(self, parent_node, add_node, ts):
        if parent_node.frequency == 0:
            parent_node.first_seen = ts
        parent_node.frequency += 1
        self.logger.info("[*] Try to insert child")
        try:
            self.add_node(node=add_node, parent=parent_node.identifier)
            self.logger.info("[+] Successfully added node: {}".format(add_node.tag))
        except exceptions.DuplicatedNodeIdError as duplicate:
            self.logger.info("[*] Node already exists: {}".format(add_node.tag))
        except Exception as e:
            self.logger.warning("[-] Adding node not successfully: {}".format(str(e)))

    def safe_tree_to_graphviz(self, filename, shape='oval', graph='digraph'):
        """Exports the tree in the dot format of the graphviz software"""
        nodes, connections = [], []
        if self.nodes:
            for n in self.expand_tree(mode=self.WIDTH):
                nid = self[n].identifier
                _tag = self[n].tag.split(',')
                s = '\n'
                s = s.join(_tag)
                state = '"{0}" [label="{1}", shape={2}]'.format(
                    nid, s, shape)
                nodes.append(state)

                for c in self.children(nid):
                    cid = c.identifier
                    connections.append('"{0}" -> "{1}"'.format(nid, cid))

        # write nodes and connections to dot format
        is_plain_file = filename is not None
        if is_plain_file:
            f = codecs.open(filename, 'w', 'utf-8')
        else:
            f = StringIO()

        f.write(graph + ' tree {\n')
        for n in nodes:
            f.write('\t' + n + '\n')

        if len(connections) > 0:
            f.write('\n')

        for c in connections:
            f.write('\t' + c + '\n')

        f.write('}')

        if not is_plain_file:
            print(f.getvalue())

        f.close()
