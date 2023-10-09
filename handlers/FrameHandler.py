from handlers.ByteHandler import ByteHandler
from handlers.typehandler.TypeHandler import TypeHandler
from handlers.FormatHandler import FormatHandler


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
    def parse_type(packet_bytes):
        return ByteHandler.load_bytes_range(packet_bytes, 12, 13)

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
        if TypeHandler.find_ether_type_str(FrameHandler.parse_type(packet_bytes)) == "ARP":
            return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(packet_bytes, 28, 31))
        elif TypeHandler.find_ether_type_str(FrameHandler.parse_type(packet_bytes)) == "IPv4":
            return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(packet_bytes, 26, 29))
        elif TypeHandler.find_ether_type_str(FrameHandler.parse_type(packet_bytes)) == "IPv6":
            return FormatHandler.format_ipv6(ByteHandler.load_bytes_range(packet_bytes, 22, 37))


    @staticmethod
    def parse_dst_ip(packet_bytes):
        if TypeHandler.find_ether_type_str(FrameHandler.parse_type(packet_bytes)) == "ARP":
            return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(packet_bytes, 38, 41))
        elif TypeHandler.find_ether_type_str(FrameHandler.parse_type(packet_bytes)) == "IPv4":
            return FormatHandler.format_ipv4(ByteHandler.load_bytes_range(packet_bytes, 30, 33))
        elif TypeHandler.find_ether_type_str(FrameHandler.parse_type(packet_bytes)) == "IPv6":
            return FormatHandler.format_ipv6(ByteHandler.load_bytes_range(packet_bytes, 38, 53))

    @staticmethod
    def parse_protocol(packet_bytes):
        if TypeHandler.find_ether_type_str(FrameHandler.parse_type(packet_bytes)) == "IPv4":
            return ByteHandler.load_bytes(packet_bytes, 23)

    @staticmethod
    def parse_src_port(packet_bytes):
        transport_protocol = TypeHandler.find_ipv4_str(FrameHandler.parse_protocol(packet_bytes))
        if transport_protocol != "ICMP" and transport_protocol != "IGMP" and transport_protocol != "PIM":
            return int(ByteHandler.load_bytes_range(packet_bytes, 34, 35), 16)

    @staticmethod
    def parse_dst_port(packet_bytes):
        transport_protocol = TypeHandler.find_ipv4_str(FrameHandler.parse_protocol(packet_bytes))
        if transport_protocol != "ICMP" and transport_protocol != "IGMP" and transport_protocol != "PIM":
            return int(ByteHandler.load_bytes_range(packet_bytes, 36, 37), 16)

    @staticmethod
    def parse_app_protocol(packet_bytes):
        port = str(FrameHandler.parse_dst_port(packet_bytes))
        transport_protocol = TypeHandler.find_ipv4_str(FrameHandler.parse_protocol(packet_bytes))
        app_protocol = None
        if transport_protocol == "TCP":
            app_protocol = TypeHandler.find_tcp_str(port)
        elif transport_protocol == "UDP":
            app_protocol = TypeHandler.find_udp_str(port)

        port = str(FrameHandler.parse_src_port(packet_bytes))
        if app_protocol == "Unknown":
            if transport_protocol == "TCP":
                app_protocol = TypeHandler.find_tcp_str(port)
            elif transport_protocol == "UDP":
                app_protocol = TypeHandler.find_udp_str(port)
        return app_protocol




    @staticmethod
    def parse_arp_opcode(packet_bytes):
        if TypeHandler.find_ether_type_str(FrameHandler.parse_type(packet_bytes)) == "ARP":
            return ByteHandler.load_bytes_range(packet_bytes, 20, 21)