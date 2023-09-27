import json
import os

cwd = os.path.dirname(os.path.realpath(__file__))


class TypeHandler:
    def __new__(cls):
        raise TypeError("Static only class!")

    ether_dict = json.load(open(cwd + "/types/EtherTypes.json"))
    sap_dict = json.load(open(cwd + "/types/SAPs.json"))
    vendors_dict = json.load(open(cwd + "/types/Vendors.json"))
    pids_dict = json.load(open(cwd + "/types/PIDs.json"))
    ipv4_dict = json.load(open(cwd + "/types/IPV4s.json"))
    tcp_dict = json.load(open(cwd + "/types/TCPs.json"))
    udp_dict = json.load(open(cwd + "/types/UDPs.json"))

    @staticmethod
    def find_ether_type_str(hex_string: str):
        try:
            return TypeHandler.ether_dict["hex_to_str"]["0x" + hex_string.upper()]
        except KeyError:
            pass  # trace-27.pcap --> 1532 frame Value "Unknown"

    @staticmethod
    def find_ether_type_hex(string: str):
        return TypeHandler.ether_dict["str_to_hex"][string]

    @staticmethod
    def find_sap_str(dsap: str, ssap: str):
        if dsap != ssap:
            return None
        return TypeHandler.sap_dict["hex_to_str"]["0x" + dsap.upper()]

    @staticmethod
    def find_sap_hex(string: str):
        return TypeHandler.sap_dict["str_to_hex"][string]

    @staticmethod
    def find_vendor_str(hex_string: str):
        return TypeHandler.vendors_dict["hex_to_str"][hex_string.upper()]

    @staticmethod
    def find_vendor_hex(string: str):
        return TypeHandler.vendors_dict["str_to_hex"][string]

    @staticmethod
    def find_pid_str(hex_string: str):
        return TypeHandler.pids_dict["hex_to_str"]["0x" + hex_string.upper()]

    @staticmethod
    def find_pid_hex(string: str):
        return TypeHandler.pids_dict["str_to_hex"][string]

    @staticmethod
    def find_ipv4_str(hex_string: str):
        return TypeHandler.ipv4_dict["hex_to_str"]["0x" + hex_string.upper()]

    @staticmethod
    def find_ipv4_hex(string: str):
        return TypeHandler.ipv4_dict["str_to_hex"][string]

    @staticmethod
    def find_tcp_str(hex_string: str):
        return TypeHandler.tcp_dict["hex_to_str"]["0x" + hex_string.upper()]

    @staticmethod
    def find_tcp_hex(string: str):
        return TypeHandler.tcp_dict["str_to_hex"][string]

    @staticmethod
    def find_udp_str(hex_string: str):
        return TypeHandler.udp_dict["hex_to_str"]["0x" + hex_string.upper()]

    @staticmethod
    def find_udp_hex(string: str):
        return TypeHandler.udp_dict["str_to_hex"][string]
