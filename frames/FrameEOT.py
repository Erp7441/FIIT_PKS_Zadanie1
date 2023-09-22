from frames.Frame import Frame

class FrameEOT(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type = "IEEE 802.3"