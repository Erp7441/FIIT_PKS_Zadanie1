import json
import os


# Source of the values
# https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-3
# Section "Values"

class Vendors:
    def __new__(cls):
        raise TypeError("Static only class!")

    dict = json.load(
        open(
            os.path.dirname(os.path.realpath(__file__)) +
            "\\Vendors.json"
        )
    )

    @staticmethod
    def find_str(hex: str):
        return Vendors.dict["hex_to_str"][hex.upper()]

    @staticmethod
    def find_hex(str: str):
        return Vendors.dict["str_to_hex"][str]
