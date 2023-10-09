from frames.Frame import Frame
from utils.Constants import Constants
from handlers.FrameHandler import FrameHandler
from handlers.typehandler.TypeHandler import TypeHandler


class FrameEthernet(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet, timestamp):
        super().__init__(frame_number, src, dest, length, wire_length, packet, timestamp)
        self.frame_type = Constants.FRAME_TYPE_ETHERNET_II

        packet_bytes = packet.hex()

        self.ether_type = TypeHandler.find_ether_type_str(FrameHandler.parse_type(packet_bytes))

        if self.ether_type != "IPv6":
            self.src_ip = FrameHandler.parse_src_ip(packet_bytes)
            self.dst_ip = FrameHandler.parse_dst_ip(packet_bytes)

        if self.ether_type == "ARP":
            self.arp_opcode = TypeHandler.find_opcode_str(FrameHandler.parse_arp_opcode(packet_bytes))
        elif self.ether_type == "IPv4":
            self.protocol = TypeHandler.find_ipv4_str(FrameHandler.parse_protocol(packet_bytes))
            self.src_port = FrameHandler.parse_src_port(packet_bytes)
            self.dst_port = FrameHandler.parse_dst_port(packet_bytes)

            app_protocol = FrameHandler.parse_app_protocol(packet_bytes)
            if app_protocol is not None:
                self.app_protocol = app_protocol




            # TODO:: Reenable ethertype for 2nd checkpoint
        #packet_bytes = packet.hex()
        #self.ether_type = TypeHandler.find_ether_type_str(ByteHandler.load_bytes_range(packet_bytes, 12, 13))
