class Frame:
    def __init__(self, frame_number, src, dest, length, wire_length, packet):
        self.frame_number = frame_number
        self.src = src
        self.dest = dest
        self.length = length
        self.wire_length = wire_length
        self.packet = packet

    def print(self):
        pass
