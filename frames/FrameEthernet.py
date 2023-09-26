from frames.Frame import Frame
from handlers.ByteHandler import ByteHandler
from handlers.typehandler.TypeHandler import TypeHandler
from utils.Constants import Constants

class FrameEthernet(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet, timestamp):
        super().__init__(frame_number, src, dest, length, wire_length, packet, timestamp)
        self.frame_type = Constants.FRAME_TYPE_ETHERNET_II

        packet_bytes = packet.hex()
        self.ether_type = TypeHandler.find_ether_type_str(ByteHandler.load_bytes_range(packet_bytes, 12, 13))
