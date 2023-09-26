from frames.FrameEOT import FrameEOT
from handlers.ByteHandler import ByteHandler

class FrameRAW(FrameEOT):
    def __init__(self, frame_number, src, dest, length, wire_length, packet, timestamp):
        super().__init__(frame_number, src, dest, length, wire_length, packet, timestamp)
        self.frame_type += " RAW"
        self.frame_type = "Novell" + self.type

        packet_bytes = packet.hex()
        self.checksum = ByteHandler.load_bytes_range(packet_bytes, 14, 16)