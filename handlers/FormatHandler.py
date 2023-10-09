import re

import ruamel.yaml.scalarstring

from handlers.ByteHandler import ByteHandler


class FormatHandler:
    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def format_mac(string: str):
        if len(string) != 12:
            return string

        substring = re.findall("(..)", string)
        string = ':'.join(substring).upper()

        return string

    @staticmethod
    def format_hex_field(hex_field):
        count = int(len(hex_field) / 2)

        formatted_field = ""

        for i in range(0, count):
            if i != 0 and i % 16 == 0:
                formatted_field += '\n'
            elif i != 0:
                formatted_field += ' '
            formatted_field += str(ByteHandler.load_bytes(hex_field, i))

        formatted_field += "\n\n"

        return ruamel.yaml.scalarstring.PreservedScalarString(formatted_field)

    @staticmethod
    def format_ipv4(hex_string):
        if hex_string is None or len(hex_string) != 8:
            return None

        substring = re.findall("(..)", hex_string)

        for i, string in enumerate(substring):
            substring[i] = str(int(string, 16))
        hex_string = '.'.join(substring)

        return hex_string

    @staticmethod
    def format_ipv6(hex_string):
        pass