from frames.Frame import Frame
from utils.typehandler.TypeHandler import TypeHandler
from utils.bytehandler.ByteHandler import ByteHandler


class FrameEthernet(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type = "Ethernet II"

        packet_bytes = packet.original.hex()
        self.ether_type = TypeHandler.find_ether_type_str(ByteHandler.load_bytes_range(packet_bytes, 12, 13))
