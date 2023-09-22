from frames.FrameLCC import FrameLCC
from utils.typehandler.TypeHandler import TypeHandler
from utils.bytehandler.ByteHandler import ByteHandler


class FrameSNAP(FrameLCC):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type += " & SNAP"

        packet_bytes = packet.original.hex()
        self.vendor = TypeHandler.find_vendor_str(packet_bytes[34:40])

        # TODO:: ISL frame handling
        # TODO:: Add VLAN trunking protocol (VTP), and BPDU, PAgP, UDLD
        self.pid = ByteHandler.load_bytes_range(packet_bytes, 20, 21)
        #TypeHandler.find_pid_str()
