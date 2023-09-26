from handlers.FormatHandler import FormatHandler


class Frame:
    def __init__(self, frame_number, src_mac, dest_mac, length, wire_length, packet, timestamp):
        self.frame_number = frame_number + 1
        self.len_frame_pcap = length
        self.len_frame_medium = wire_length
        self.src_mac = FormatHandler.format_mac(src_mac)
        self.dst_mac = FormatHandler.format_mac(dest_mac)
        self.hexa_frame = FormatHandler.format_hex_field(packet.hex())
        self.timestamp = timestamp

    def print(self):
        pass
