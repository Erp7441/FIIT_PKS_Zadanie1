from frames.FrameEthernet import FrameEthernet
from frames.FrameLCC import FrameLCC
from frames.FrameRAW import FrameRAW
from frames.FrameSNAP import FrameSNAP
from handlers.FrameHandler import FrameHandler
from utils.Constants import Constants


class FrameFactory:
    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def create_frame(frame_number, timestamp, packet):
        frame_type = FrameFactory._extract_ether_frame_type(packet)

        # Handling undefined frame handlers
        if not frame_type:
            return

        # 0 index is source, 1 index is dest
        macs = FrameFactory._extract_mac_addresses(packet)

        length = FrameFactory._get_frame_length(packet)
        wire_length = FrameFactory._get_frame_length(packet, True)

        # Ethernet II Frame
        if frame_type == Constants.FRAME_TYPE_ETHERNET_II:
            return FrameEthernet(frame_number, macs[0], macs[1], length, wire_length, packet, timestamp)
        # 802.3 Frame
        elif frame_type == Constants.FRAME_TYPE_EOTT:
            return FrameFactory._create_eot_frame(frame_number, macs[0], macs[1], length, wire_length, packet, timestamp)

    @staticmethod
    def _create_eot_frame(frame_number, src, dest, length, wire_length, packet, timestamp):
        packet_bytes = packet.hex()

        # TODO:: Implement ISL check Destination Address (DA) Field
        # ISL:: The 'DA' field is a 40 bit destination address field that contains a multicast address usually set to
        # "01-00-0C-00-00" or "03-00-0C-00-00". This address is used to signal to the receiver that the packet is in ISL format.

        # LLC SNAP
        if FrameFactory._check_snap(packet_bytes):
            return FrameSNAP(frame_number, src, dest, length, wire_length, packet, timestamp)
        # 802 RAW
        elif FrameFactory._check_raw(packet_bytes):
            return FrameRAW(frame_number, src, dest, length, wire_length, packet, timestamp)
        # LLC
        else:
            return FrameLCC(frame_number, src, dest, length, wire_length, packet, timestamp)

    @staticmethod
    def _extract_mac_addresses(packet):
        packet_bytes = packet.hex()
        source_mac = FrameHandler.parse_src_mac(packet_bytes)
        destination_mac = FrameHandler.parse_dst_mac(packet_bytes)
        return source_mac, destination_mac

    @staticmethod
    def _extract_ether_frame_type(packet):
        packet_bytes = packet.hex()
        type_bytes = FrameHandler.parse_type(packet_bytes, True)
        type_bytes = int(type_bytes, 16)

        if type_bytes >= 1536:
            # Ethernet II packet
            return Constants.FRAME_TYPE_ETHERNET_II
        elif type_bytes <= 1500:
            # 802.3 packet
            return Constants.FRAME_TYPE_EOTT
        else:
            # Values between 1501 and 1535 are considered undefined
            return None

    @staticmethod
    def _get_frame_length(packet, wire=False):
        if not wire:
            return len(packet)
        elif len(packet) < 60 and wire:
            return 64
        else:
            return len(packet) + 4

    @staticmethod
    def _check_snap(packet_bytes):
        dsap = FrameHandler.parse_dsap(packet_bytes)
        ssap = FrameHandler.parse_ssap(packet_bytes)
        control = FrameHandler.parse_control(packet_bytes)
        return (dsap.upper() == "AA") and (ssap.upper() == "AA") and (control == "03")

    @staticmethod
    def _check_raw(packet_bytes):
        ipx_header = FrameHandler.parse_ipx_header(packet_bytes)
        return (ipx_header[0].upper() == "FF") and (ipx_header[1].upper() == "FF")
