from handlers.ByteHandler import ByteHandler


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
