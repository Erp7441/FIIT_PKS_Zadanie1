from frames.FrameEthernet import FrameEthernet
from frames.FrameLCC import FrameLCC
from frames.FrameRAW import FrameRAW
from frames.FrameSNAP import FrameSNAP
from utils.bytehandler.ByteHandler import ByteHandler


class FrameFactory:
    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def create_frame(frame_number, packet):
        frame_type = FrameFactory.extract_ether_frame_type(packet)

        # Handling undefined frame utils
        if not frame_type:
            return

        # 0 index is source, 1 index is dest
        macs = FrameFactory.extract_mac_addresses(packet)

        length = FrameFactory.get_frame_length(packet)  # TODO:: check length
        wire_length = FrameFactory.get_frame_length(packet, True)

        # Ethernet II Frame
        if frame_type == "Ethernet II":
            return FrameEthernet(frame_number, macs[0], macs[1], length, wire_length, packet)
        # 802.3 Frame
        elif frame_type == "802.3":
            return FrameFactory.create_eot_frame(frame_number, macs[0], macs[1], length, wire_length, packet)

    @staticmethod
    def create_eot_frame(frame_number, src, dest, length, wire_length, packet):
        packet_bytes = packet.original.hex()

        # LLC SNAP
        if FrameFactory.check_snap(packet_bytes):
            return FrameSNAP(frame_number, src, dest, length, wire_length, packet)
        # 802 RAW
        elif FrameFactory.check_raw(packet_bytes):
            return FrameRAW(frame_number, src, dest, length, wire_length, packet)
        # LLC
        else:
            return FrameLCC(frame_number, src, dest, length, wire_length, packet)

    @staticmethod
    def extract_mac_addresses(packet):
        packet_bytes = packet.original.hex()
        source_mac = ByteHandler.load_bytes_range(packet_bytes, 0, 5)
        destination_mac = ByteHandler.load_bytes_range(packet_bytes, 6, 11)
        return source_mac, destination_mac

    @staticmethod
    def extract_ether_frame_type(packet):
        packet_bytes = packet.original.hex()
        type_bytes = ByteHandler.load_bytes_range(packet_bytes, 12, 13)
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

    @staticmethod
    def check_snap(packet_bytes):
        dsap = ByteHandler.load_bytes(packet_bytes, 14)
        ssap = ByteHandler.load_bytes(packet_bytes, 15)
        control = ByteHandler.load_bytes(packet_bytes, 16)
        return (dsap.upper() == "AA") and (ssap.upper() == "AA") and (control == "03")

    @staticmethod
    def check_raw(packet_bytes):
        ipx_header_p1 = ByteHandler.load_bytes(packet_bytes, 14)
        ipx_header_p2 = ByteHandler.load_bytes(packet_bytes, 15)
        return (ipx_header_p1 == "ff") and (ipx_header_p2 == "ff")
