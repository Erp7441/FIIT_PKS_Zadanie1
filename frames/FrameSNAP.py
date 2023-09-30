from frames.FrameLCC import FrameLCC
from handlers.FrameHandler import FrameHandler
from handlers.typehandler.TypeHandler import TypeHandler
from utils.Constants import Constants


class FrameSNAP(FrameLCC):
    def __init__(self, frame_number, src, dest, length, wire_length, packet, timestamp):
        super().__init__(frame_number, src, dest, length, wire_length, packet, timestamp)
        self.frame_type = Constants.FRAME_TYPE_EOTT_SNAP

        packet_bytes = packet.hex()

        # TODO:: remove?
        # self.vendor = TypeHandler.find_vendor_str(ByteHandler.load_bytes_range(packet_bytes, 17, 19))

        try:
            self.pid = TypeHandler.find_pid_str(FrameHandler.parse_pid(packet_bytes))
        except (IndentationError, KeyError):
            pass
