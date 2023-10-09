from frames.Frame import Frame
from utils.Constants import Constants
from handlers.FrameHandler import FrameHandler


class FrameEthernet(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet, timestamp):
        super().__init__(frame_number, src, dest, length, wire_length, packet, timestamp)
        self.frame_type = Constants.FRAME_TYPE_ETHERNET_II

        packet_bytes = packet.hex()

        self.ether_type = FrameHandler.parse_type(packet_bytes)

        if self.ether_type != "IPv6" and self.ether_type != "LLDP" and self.ether_type != "ETCP":
            self.src_ip = FrameHandler.parse_src_ip(packet_bytes)
            self.dst_ip = FrameHandler.parse_dst_ip(packet_bytes)

        if self.ether_type == "ARP":
            self.arp_opcode = FrameHandler.parse_arp_opcode(packet_bytes)
        elif self.ether_type == "IPv4":
            self.protocol = FrameHandler.parse_protocol(packet_bytes)

            # Transport protocol header bytes
            header_bytes = packet_bytes[
                FrameHandler.parse_ethernet_ii_header_length() +
                FrameHandler.parse_ipv4_header_length(packet_bytes)::
            ]

            # TCP / UDP stuff
            if self.protocol == "TCP" or self.protocol == "UDP":
                self.src_port = FrameHandler.parse_src_port(header_bytes)
                self.dst_port = FrameHandler.parse_dst_port(header_bytes)

                app_protocol = FrameHandler.parse_app_protocol(packet_bytes, header_bytes)
                if app_protocol is not None:
                    self.app_protocol = app_protocol

            # ICMP stuff
            if self.protocol == "ICMP":
                self.icmp_type = FrameHandler.parse_icmp_type(header_bytes)

                # TODO:: Mam to mat?
                # self.icmp_id = FrameHandler.parse_icmp_id(header_bytes)
                # self.icmp_seq = FrameHandler.parse_icmp_seq(header_bytes)
