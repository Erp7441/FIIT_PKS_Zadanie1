class ByteHandler:

    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def load_bytes(field, index: int):
        index *= 2
        end = index + 2
        return field[index:end]

    @staticmethod
    def load_bytes_range(field, start: int, end: int):
        return field[start*2:(end+1)*2]
