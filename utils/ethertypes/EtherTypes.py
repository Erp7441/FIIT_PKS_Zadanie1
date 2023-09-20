import json
import os


# Source of the values
# https://en.wikipedia.org/wiki/EtherType
# Section "Values"

class EtherTypes:
    def __new__(cls):
        raise TypeError("Static only class!")

    dict = json.load(
        open(
            os.path.dirname(os.path.realpath(__file__)) +
            "\\EtherTypes.json"
        )
    )

    @staticmethod
    def find_str(hex: str):
        return EtherTypes.dict["hex_to_str"]["0x" + hex.upper()]

    @staticmethod
    def find_hex(str: str):
        return EtherTypes.dict["str_to_hex"][str]
