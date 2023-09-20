from frames.FrameEOT import FrameEOT


class FrameRAW(FrameEOT):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type += " RAW"
        self.type = "Novell" + self.type

        packet_bytes = packet.original.hex()
        self.checksum = packet_bytes[28:32]