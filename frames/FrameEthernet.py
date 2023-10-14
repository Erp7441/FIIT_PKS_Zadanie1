from frames.Frame import Frame
from utils.Constants import Constants
from handlers.FrameHandler import FrameHandler


class FrameEthernet(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet, timestamp):
        super().__init__(frame_number, src, dest, length, wire_length, packet, timestamp)
        self.frame_type = Constants.FRAME_TYPE_ETHERNET_II

        packet_bytes = packet.hex()

        # TODO:: Move what you can to Frame class?

        self.ether_type = FrameHandler.parse_type(packet_bytes)

        if (
            self.ether_type != "IPv6" and
            self.ether_type != "LLDP" and
            self.ether_type != "ECTP" and
            self.ether_type != "Unknown"
        ):
            self.src_ip = FrameHandler.parse_src_ip(packet_bytes)
            self.dst_ip = FrameHandler.parse_dst_ip(packet_bytes)

        if self.ether_type == "ARP":
            self.arp_opcode = FrameHandler.parse_arp_opcode(packet_bytes)
            if self.arp_opcode == "REQUEST":
                self.lookup = FrameHandler.parse_arp_target_ip(self.hexa_frame)
            elif self.arp_opcode == "REPLY":
                self.ip_mac_pair = FrameHandler.parse_arp_ip_mac_src_pair(self.hexa_frame)

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

                if self.protocol == "TCP":
                    self.flags = FrameHandler.parse_tcp_flags(header_bytes)
                    self.seq_num = FrameHandler.parse_tcp_sequence_number(header_bytes)
                    self.ack_num = FrameHandler.parse_tcp_acknowledgment_number(header_bytes)

            # ICMP stuff
            if self.protocol == "ICMP":
                self.icmp_type = FrameHandler.parse_icmp_type(header_bytes)

    def add_icmp_complete_fields(self):
        if self.protocol == "ICMP":
            # TODO:: Add time exceeded?

            if self.icmp_type == "ECHO REPLY" or self.icmp_type == "ECHO REQUEST":
                packet_bytes = str(self.hexa_frame).replace(' ', '').replace('\n', '')
                header_bytes = packet_bytes[
                    FrameHandler.parse_ethernet_ii_header_length() +
                    FrameHandler.parse_ipv4_header_length(packet_bytes)::
                ]

                self.icmp_id = FrameHandler.parse_icmp_id(header_bytes)
                self.icmp_seq = FrameHandler.parse_icmp_seq(header_bytes)

    def get_icmp_id(self):
        if self.protocol == "ICMP":
            # TODO:: Add time exceeded?

            if self.icmp_type == "ECHO REPLY" or self.icmp_type == "ECHO REQUEST":
                packet_bytes = str(self.hexa_frame).replace(' ', '').replace('\n', '')
                header_bytes = packet_bytes[
                    FrameHandler.parse_ethernet_ii_header_length() +
                    FrameHandler.parse_ipv4_header_length(packet_bytes)::
                ]

                return FrameHandler.parse_icmp_id(header_bytes)

    def compare_protocol(self, protocol):
        if self.protocol == "ICMP":
            return self.protocol == protocol
        return self.app_protocol == protocol
