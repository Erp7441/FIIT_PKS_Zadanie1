from frames.FrameEOT import FrameEOT
from handlers.ByteHandler import ByteHandler
from handlers.typehandler.TypeHandler import TypeHandler

class FrameLCC(FrameEOT):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.frame_type += " LCC"

        packet_bytes = packet.original.hex()

        try:
            dsap = ByteHandler.load_bytes(packet_bytes, 14)
            ssap = ByteHandler.load_bytes(packet_bytes, 15)
            self.sap = TypeHandler.find_sap_str(dsap, ssap)
        except KeyError:
            pass # TODO:: Handle exception?

        # control = ByteHandler.load_bytes(packet_bytes, 16) TODO:: Remove unused variable


