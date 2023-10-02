from frames.Frame import Frame
from utils.Constants import Constants


class FrameEthernet(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet, timestamp):
        super().__init__(frame_number, src, dest, length, wire_length, packet, timestamp)
        self.frame_type = Constants.FRAME_TYPE_ETHERNET_II

        # TODO:: Reenable ethertype for 2nd checkpoint
        #packet_bytes = packet.hex()
        #self.ether_type = TypeHandler.find_ether_type_str(ByteHandler.load_bytes_range(packet_bytes, 12, 13))
