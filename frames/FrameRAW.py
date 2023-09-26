from frames.FrameEOT import FrameEOT
from handlers.ByteHandler import ByteHandler
from utils.Constants import Constants


class FrameRAW(FrameEOT):
    def __init__(self, frame_number, src, dest, length, wire_length, packet, timestamp):
        super().__init__(frame_number, src, dest, length, wire_length, packet, timestamp)
        self.frame_type = Constants.FRAME_TYPE_EOTT_RAW

        packet_bytes = packet.hex()
        self.checksum = ByteHandler.load_bytes_range(packet_bytes, 14, 16)
