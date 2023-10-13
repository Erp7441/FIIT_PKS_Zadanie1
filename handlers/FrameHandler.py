from handlers.ByteHandler import ByteHandler
from handlers.typehandler.TypeHandler import TypeHandler
from handlers.FormatHandler import FormatHandler

import re

class FrameHandler:

    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def parse_dsap(packet_bytes):
        return ByteHandler.load_bytes(packet_bytes, 14)

    @staticmethod
    def parse_ssap(packet_bytes):
        return ByteHandler.load_bytes(packet_bytes, 15)

    @staticmethod
    def parse_control(packet_bytes):
        return ByteHandler.load_bytes(packet_bytes, 16)

    @staticmethod
    def parse_type(packet_bytes, number=False):
        if number:
            return ByteHandler.load_bytes_range(packet_bytes, 12, 13)
        return TypeHandler.find_ether_type_str(ByteHandler.load_bytes_range(packet_bytes, 12, 13))

    @staticmethod
    def parse_src_mac(packet_bytes):
        return ByteHandler.load_bytes_range(packet_bytes, 6, 11)

    @staticmethod
    def parse_dst_mac(packet_bytes):
        return ByteHandler.load_bytes_range(packet_bytes, 0, 5)

    @staticmethod
    def parse_pid(packet_bytes):
        return ByteHandler.load_bytes_range(packet_bytes, 20, 21)

    @staticmethod
    def parse_ipx_header(packet_bytes):
        return [ByteHandler.load_bytes(packet_bytes, 14), ByteHandler.load_bytes(packet_bytes, 15)]

    @staticmethod
    def parse_src_ip(packet_bytes):
        if FrameHandler.parse_type(packet_bytes) == "ARP":
            return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(packet_bytes, 28, 31))
        elif FrameHandler.parse_type(packet_bytes) == "IPv4":
            return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(packet_bytes, 26, 29))
        elif FrameHandler.parse_type(packet_bytes) == "IPv6":
            return FormatHandler.format_ipv6(ByteHandler.load_bytes_range(packet_bytes, 22, 37))

    @staticmethod
    def parse_dst_ip(packet_bytes):
        if FrameHandler.parse_type(packet_bytes) == "ARP":
            return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(packet_bytes, 38, 41))
        elif FrameHandler.parse_type(packet_bytes) == "IPv4":
            return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(packet_bytes, 30, 33))
        elif FrameHandler.parse_type(packet_bytes) == "IPv6":
            return FormatHandler.format_ipv6(ByteHandler.load_bytes_range(packet_bytes, 38, 53))

    @staticmethod
    def parse_protocol(packet_bytes):
        if FrameHandler.parse_type(packet_bytes) == "IPv4":
            return TypeHandler.find_ipv4_str(ByteHandler.load_bytes(packet_bytes, 23))

    @staticmethod
    def parse_src_port(header_bytes):
        return int(ByteHandler.load_bytes_range(header_bytes, 0, 1), 16)

    @staticmethod
    def parse_dst_port(header_bytes):
        return int(ByteHandler.load_bytes_range(header_bytes, 2, 3), 16)

    @staticmethod
    def parse_app_protocol(packet_bytes, header_bytes):
        port = str(FrameHandler.parse_dst_port(header_bytes))
        transport_protocol = FrameHandler.parse_protocol(packet_bytes)
        app_protocol = None
        if transport_protocol == "TCP":
            app_protocol = TypeHandler.find_tcp_str(port)
        elif transport_protocol == "UDP":
            app_protocol = TypeHandler.find_udp_str(port)

        port = str(FrameHandler.parse_src_port(header_bytes))
        if app_protocol == "Unknown":
            if transport_protocol == "TCP":
                app_protocol = TypeHandler.find_tcp_str(port)
            elif transport_protocol == "UDP":
                app_protocol = TypeHandler.find_udp_str(port)
        return app_protocol

    @staticmethod
    def parse_arp_opcode(packet_bytes, number=False):
        if FrameHandler.parse_type(packet_bytes) == "ARP":
            if number:
                return ByteHandler.load_bytes_range(packet_bytes, 20, 21)
            return TypeHandler.find_opcode_str(ByteHandler.load_bytes_range(packet_bytes, 20, 21))

    @staticmethod
    def parse_icmp_type(packet_bytes):
        return TypeHandler.find_icmp_type_str(ByteHandler.load_bytes(packet_bytes, 0))

    @staticmethod
    def parse_icmp_id(packet_bytes):
        return int(ByteHandler.load_bytes_range(packet_bytes, 4, 5), 16)

    @staticmethod
    def parse_icmp_seq(packet_bytes):
        return int(ByteHandler.load_bytes_range(packet_bytes, 6, 7), 16)

    @staticmethod
    def parse_ipv4_header_length(packet_bytes):
        return int(ByteHandler.load_bytes(packet_bytes, 14)[1], 16) * 8

    @staticmethod
    def parse_ethernet_ii_header_length():
        return 28

    @staticmethod
    def parse_tcp_flags(header_bytes):
        flags = ByteHandler.load_bytes_range(header_bytes, 12, 13)
        flags = re.findall("(..)", flags)[1]
        return TypeHandler.find_tcp_flags_str(flags)

    @staticmethod
    def parse_tcp_sequence_number(header_bytes):
        return ByteHandler.load_bytes_range(header_bytes, 4, 7)

    @staticmethod
    def parse_tcp_acknowledgment_number(header_bytes):
        return ByteHandler.load_bytes_range(header_bytes, 8, 11)

    @staticmethod
    def parse_tftp_opcode(hexa_frame):
        bytes_str = str(hexa_frame).replace(' ', '').replace('\n', '')
        return ByteHandler.load_bytes_range(bytes_str, 42, 43)

    @staticmethod
    def parse_arp_target_ip(hexa_frame):
        bytes_str = str(hexa_frame).replace(' ', '').replace('\n', '')
        return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(bytes_str, 38, 41))

    @staticmethod
    def parse_arp_target_mac(hexa_frame):
        bytes_str = str(hexa_frame).replace(' ', '').replace('\n', '')
        return FormatHandler.format_mac(ByteHandler.load_bytes_range(bytes_str, 32, 37))

    @staticmethod
    def parse_arp_source_ip(hexa_frame):
        bytes_str = str(hexa_frame).replace(' ', '').replace('\n', '')
        return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(bytes_str, 28, 31))

    @staticmethod
    def parse_arp_source_mac(hexa_frame):
        bytes_str = str(hexa_frame).replace(' ', '').replace('\n', '')
        return FormatHandler.format_mac(ByteHandler.load_bytes_range(bytes_str, 22, 27))

    @staticmethod
    def parse_arp_ip_mac_src_pair(hexa_frame):
        return FrameHandler.parse_arp_source_ip(hexa_frame), FrameHandler.parse_arp_source_mac(hexa_frame)

    @staticmethod
    def parse_arp_ip_mac_dst_pair(hexa_frame):
        return FrameHandler.parse_arp_target_ip(hexa_frame), FrameHandler.parse_arp_target_mac(hexa_frame)