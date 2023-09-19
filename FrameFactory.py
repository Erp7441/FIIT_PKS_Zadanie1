from FrameEOT import FrameEOT
from FrameEthernet import FrameEthernet


class FrameFactory:
    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def create_frame(frame_number, packet):
        frame_type = FrameFactory.extract_ether_frame_type(packet)

        # Handling undefined frame types
        if not frame_type:
            return

        # 0 index is source, 1 index is dest
        macs = FrameFactory.extract_mac_addresses(packet)

        length = FrameFactory.get_frame_length(packet)
        wire_length = FrameFactory.get_frame_length(packet, True)

        if frame_type == "Ethernet II":
            return FrameEthernet(frame_number, macs[0], macs[1], length, wire_length, packet)
        elif frame_type == "802.3":
            # TODO:: LLC, etc...
            return FrameEOT(frame_number, macs[0], macs[1], length, wire_length, packet)

    @staticmethod
    def create_eot_llc_frame(self):
        # TODO:: Implement
        pass

    @staticmethod
    def extract_mac_addresses(packet):
        packet_bytes = packet.original.hex()
        source_mac = packet_bytes[0:12]
        destination_mac = packet_bytes[12:24]
        return source_mac, destination_mac

    @staticmethod
    def extract_ether_frame_type(packet):
        packet_bytes = packet.original.hex()
        type_bytes = packet_bytes[24:28]
        type_bytes = int(type_bytes, 16)

        if type_bytes >= 1536:
            # Ethernet II packet
            return "Ethernet II"
        elif type_bytes <= 1500:
            # 802.3 packet
            return "802.3"
        else:
            # Values between 1501 and 1535 are considered undefined
            return None

    @staticmethod
    def get_frame_length(packet, wire=False):
        if not wire:
            return int(len(packet) / 2)
        else:
            # Return packet length on wire
            return packet.wirelen
