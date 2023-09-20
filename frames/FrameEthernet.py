from frames.Frame import Frame
from utils.ethertypes.EtherTypes import EtherTypes

class FrameEthernet(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type = "Ethernet II"

        packet_bytes = packet.original.hex()
        self.ether_type = EtherTypes.find_str(packet_bytes[24:28])