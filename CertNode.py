from treelib import Node


class CertNode(Node):
    def __init__(self, tag, identifier, data):
        super().__init__(tag=tag, identifier=identifier, data=data)
        self.frequency = 0
        self.first_seen = None