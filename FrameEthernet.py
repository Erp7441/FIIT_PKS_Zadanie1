from Frame import Frame

class FrameEthernet(Frame):
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        super().__init__(frame_number, src, dest, length, wire_length, packet)
        self.type = "Ethernet II"