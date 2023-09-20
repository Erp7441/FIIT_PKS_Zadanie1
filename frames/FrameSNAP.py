from frames.FrameLCC import FrameLCC


class FrameSNAP(FrameLCC):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type += " SNAP"

        packet_bytes = packet.original.hex()
        self.vendor = packet_bytes[34:40]
        self.ether_type = packet_bytes[40:44]
