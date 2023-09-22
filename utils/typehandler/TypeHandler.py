import json
import os

cwd = os.path.dirname(os.path.realpath(__file__))


class TypeHandler:
    def __new__(cls):
        raise TypeError("Static only class!")

    ether_dict = json.load(open(cwd + "\\EtherTypes.json"))
    sap_dict = json.load(open(cwd + "\\SAPs.json"))
    vendors_dict = json.load(open(cwd + "\\Vendors.json"))
    pids_dict = json.load(open(cwd + "\\PIDs.json"))
    ipv4_dict = json.load(open(cwd + "\\IPV4s.json"))
    tcp_dict = json.load(open(cwd + "\\TCPs.json"))
    udp_dict = json.load(open(cwd + "\\UDPs.json"))

    @staticmethod
    def find_ether_type_str(hex: str):
        return TypeHandler.ether_dict["hex_to_str"]["0x" + hex.upper()]

    @staticmethod
    def find_ether_type_hex(str: str):
        return TypeHandler.ether_dict["str_to_hex"][str]

    @staticmethod
    def find_sap_str(hex: str):
        return TypeHandler.sap_dict["hex_to_str"]["0x" + hex.upper()]

    @staticmethod
    def find_sap_hex(str: str):
        return TypeHandler.sap_dict["str_to_hex"][str]

    @staticmethod
    def find_vendor_str(hex: str):
        return TypeHandler.vendors_dict["hex_to_str"][hex.upper()]

    @staticmethod
    def find_vendor_hex(str: str):
        return TypeHandler.vendors_dict["str_to_hex"][str]

    @staticmethod
    def find_pid_str(hex: str):
        return TypeHandler.pids_dict["hex_to_str"]["0x" + hex.upper()]

    @staticmethod
    def find_pid_hex(str: str):
        return TypeHandler.pids_dict["str_to_hex"][str]

    @staticmethod
    def find_ipv4_str(hex: str):
        return TypeHandler.ipv4_dict["hex_to_str"]["0x" + hex.upper()]

    @staticmethod
    def find_ipv4_hex(str: str):
        return TypeHandler.ipv4_dict["str_to_hex"][str]

    @staticmethod
    def find_tcp_str(hex: str):
        return TypeHandler.tcp_dict["hex_to_str"]["0x" + hex.upper()]

    @staticmethod
    def find_tcp_hex(str: str):
        return TypeHandler.tcp_dict["str_to_hex"][str]

    @staticmethod
    def find_udp_str(hex: str):
        return TypeHandler.udp_dict["hex_to_str"]["0x" + hex.upper()]

    @staticmethod
    def find_udp_hex(str: str):
        return TypeHandler.udp_dict["str_to_hex"][str]