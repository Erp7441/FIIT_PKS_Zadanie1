from frames.FrameLCC import FrameLCC
from utils.vendors.Vendors import Vendors
from utils.ethertypes.EtherTypes import EtherTypes


class FrameSNAP(FrameLCC):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type += " SNAP"

        packet_bytes = packet.original.hex()
        self.vendor = Vendors.find_str(packet_bytes[34:40])

        # TODO:: ISL frame handling
        # TODO:: Add VLAN trunking protocol (VTP), and BPDU, PAgP, UDLD
        try:
            #self.pid = EtherTypes.find_str(packet_bytes[92:96])
            self.pid = EtherTypes.find_str(packet_bytes[40:44])
        except KeyError:
            self.pid = "Spanning Tree Protocol"
