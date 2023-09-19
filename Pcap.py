from scapy.all import rdpcap
from FrameFactory import FrameFactory




class Pcap:
    def __init__(self, path: str):
        file = rdpcap(path) #! TODO:: replace with npcap
        self.name = file.listname
        self.stats = file.stats
        self.frames = []

        for index, entry in enumerate(file.res):
            self.frames.append(FrameFactory.create_frame(index, entry))

    def print_frames(self):
        pass

            # TODO:: Remove legacy code
            # packet_bytes = packet.original.hex()
            #
            # print("ID:", index)
            # print("Length:", int(len(packet)/2)) #?
            # print("Wire Length:", packet.wirelen)
            #
            #
            # print("Frame type:", packet_bytes[24:28])
            #
            # print("Source MAC:", packet_bytes[0:12])
            # print("Destination MAC:", packet_bytes[12:24])
            # print ("Packet content: ", packet_bytes)


