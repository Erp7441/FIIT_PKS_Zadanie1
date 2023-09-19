from FrameEOT import FrameEOT


class FrameLCC(FrameEOT):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type += " LCC"