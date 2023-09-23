from frames.FrameLCC import FrameLCC
from utils.bytehandler.ByteHandler import ByteHandler
from utils.typehandler.TypeHandler import TypeHandler


class FrameSNAP(FrameLCC):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.frame_type += " & SNAP"

        packet_bytes = packet.original.hex()
        self.vendor = TypeHandler.find_vendor_str(ByteHandler.load_bytes_range(packet_bytes, 17, 19))

        try:
            self.pid = TypeHandler.find_pid_str(ByteHandler.load_bytes_range(packet_bytes, 20, 21))
        except (IndentationError, KeyError):
            # TODO:: ISL frame handling?
            pass

