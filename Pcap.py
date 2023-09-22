from scapy.all import rdpcap

from FrameFactory import FrameFactory


class Pcap:
    def __init__(self, path: str):
        file = rdpcap(path)  # ! TODO:: replace with npcap


        self.name = "PKS2023/24"
        self.pcap_name = file.listname
        self.packets = []

        for index, entry in enumerate(file.res):
            self.packets.append(FrameFactory.create_frame(index, entry))


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