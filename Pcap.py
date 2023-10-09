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

        # self.ipv4_senders = " "
        # self.max_send_packets_by = " "

    def find_ipv4_senders(self):
        pass

    def find_max_send_packets(self):
        best_sender = self.ipv4_senders[0]
        for sender in self.ipv4_senders:
            if sender["count"] > best_sender["count"]:
                best_sender = sender
        return best_sender