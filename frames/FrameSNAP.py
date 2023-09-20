from frames.FrameLCC import FrameLCC


class FrameSNAP(FrameLCC):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type += " SNAP"