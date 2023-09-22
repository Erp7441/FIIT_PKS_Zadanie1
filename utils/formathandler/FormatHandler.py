import re

import ruamel.yaml.scalarstring

from utils.bytehandler.ByteHandler import ByteHandler


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

        # dump = hexdump(hex_field, dump=True)
        # split = dump.split("\n")
        # formatted_field = []
        #
        # for part in split:
        #     formatted_field.append(re.search("([ ]{2}.*[ ]{2})", part).group().strip())
        #
        # formatted_field = "\n".join(formatted_field)
        # return formatted_field

# TODO:: remove legacy code


