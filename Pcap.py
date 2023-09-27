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