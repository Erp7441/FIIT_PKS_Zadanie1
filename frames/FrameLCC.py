from frames.FrameEOT import FrameEOT
from utils.bytehandler.ByteHandler import ByteHandler


class FrameLCC(FrameEOT):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type += " LCC"

        packet_bytes = packet.original.hex()
        self.dsap = ByteHandler.load_bytes(packet_bytes, 14)
        self.ssap = ByteHandler.load_bytes(packet_bytes, 15)
        self.control = ByteHandler.load_bytes(packet_bytes, 16)
