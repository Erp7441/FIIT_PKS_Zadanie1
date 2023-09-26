import pcap

from FrameFactory import FrameFactory

class Pcap:

    def __init__(self, path: str):
        file = pcap.pcap(name=path)

        self.name = "PKS2023/24"
        self.pcap_name = file.name
        self.packets = []

        for index, entry in enumerate(file):
            # Entry [0] is timestamp
            # Entry [1] are bytes
            self.packets.append(FrameFactory.create_frame(index, entry[0], entry[1]))


        @classmethod
        def to_yaml(cls, representer, node):
            tag = getattr(cls, 'yaml_tag')
            attribs = {}
            for x in dir(node):
                if x.startswith('_'):
                    continue
                v = getattr(node, x)
                if callable(v):
                    continue
                attribs[x] = v
            return representer.represent_mapping(tag, attribs)