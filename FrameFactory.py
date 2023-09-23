from frames.FrameEthernet import FrameEthernet
from frames.FrameLCC import FrameLCC
from frames.FrameRAW import FrameRAW
from frames.FrameSNAP import FrameSNAP
from handlers.FrameHandler import FrameHandler


class FrameFactory:
    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def create_frame(frame_number, packet):
        frame_type = FrameFactory.extract_ether_frame_type(packet)

        # Handling undefined frame handlers
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
        source_mac = FrameHandler.parse_src_mac(packet_bytes)
        destination_mac = FrameHandler.parse_dst_mac(packet_bytes)
        return source_mac, destination_mac

    @staticmethod
    def extract_ether_frame_type(packet):
        packet_bytes = packet.original.hex()
        type_bytes = FrameHandler.parse_type(packet_bytes)
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
            return len(packet)

    @staticmethod
    def check_snap(packet_bytes):
        dsap = FrameHandler.parse_dsap(packet_bytes)
        ssap = FrameHandler.parse_ssap(packet_bytes)
        control = FrameHandler.parse_control(packet_bytes)
        return (dsap.upper() == "AA") and (ssap.upper() == "AA") and (control == "03")

    @staticmethod
    def check_raw(packet_bytes):
        ipx_header = FrameHandler.parse_ipx_header(packet_bytes)
        return (ipx_header[0].upper() == "FF") and (ipx_header[1].upper() == "FF")
