from frames.FrameEOT import FrameEOT


class FrameLCC(FrameEOT):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type += " LCC"

        packet_bytes = packet.original.hex()
        self.dsap = packet_bytes[28:30]
        self.ssap = packet_bytes[30:32]
        self.control = packet_bytes[32:34]