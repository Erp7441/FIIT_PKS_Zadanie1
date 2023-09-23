from frames.Frame import Frame
from handlers.ByteHandler import ByteHandler
from handlers.typehandler.TypeHandler import TypeHandler


class FrameEthernet(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.frame_type = "ETHERNET II"

        packet_bytes = packet.original.hex()
        self.ether_type = TypeHandler.find_ether_type_str(ByteHandler.load_bytes_range(packet_bytes, 12, 13))
