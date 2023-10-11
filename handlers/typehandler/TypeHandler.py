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
    tcp_flags_dict = json.load(open(cwd + "/types/TCP_FLAGS.json"))
    udp_dict = json.load(open(cwd + "/types/UDPs.json"))
    opcode_dict = json.load(open(cwd + "/types/Opcodes.json"))
    icmp_type_dict = json.load(open(cwd + "/types/ICMP_TYPEs.json"))

    @staticmethod
    def find_ether_type_str(hex_string: str):
        return TypeHandler.ether_dict["hex_to_str"].get("0x" + hex_string.upper(), "Unknown")
        # trace-27.pcap --> 1532 frame Value "Unknown"

    @staticmethod
    def find_ether_type_hex(string: str):
        return TypeHandler.ether_dict["str_to_hex"].get(string, "Unknown")

    @staticmethod
    def find_sap_str(dsap: str, ssap: str):
        if dsap != ssap:
            return None
        return TypeHandler.sap_dict["hex_to_str"].get("0x" + dsap.upper(), "Unknown")

    @staticmethod
    def find_sap_hex(string: str):
        return TypeHandler.sap_dict["str_to_hex"].get(string, "Unknown")

    @staticmethod
    def find_vendor_str(hex_string: str):
        return TypeHandler.vendors_dict["hex_to_str"].get(hex_string.upper(), "Unknown")

    @staticmethod
    def find_vendor_hex(string: str):
        return TypeHandler.vendors_dict["str_to_hex"].get(string, "Unknown")

    @staticmethod
    def find_pid_str(hex_string: str):
        return TypeHandler.pids_dict["hex_to_str"].get("0x" + hex_string.upper(), "Unknown")

    @staticmethod
    def find_pid_hex(string: str):
        return TypeHandler.pids_dict["str_to_hex"].get(string, "Unknown")

    @staticmethod
    def find_ipv4_str(hex_string: str):
        return TypeHandler.ipv4_dict["hex_to_str"].get("0x" + hex_string.upper(), "Unknown")

    @staticmethod
    def find_ipv4_hex(string: str):
        return TypeHandler.ipv4_dict["str_to_hex"].get(string, "Unknown")

    @staticmethod
    def find_tcp_flags_str(hex_string: str):
        return TypeHandler.tcp_flags_dict["hex_to_str"].get("0x" + hex_string.upper(), "Unknown")

    @staticmethod
    def find_tcp_flags_hex(string: str):
        return TypeHandler.tcp_flags_dict["str_to_hex"].get(string, "Unknown")

    @staticmethod
    def find_tcp_dec(string: str):
        return TypeHandler.tcp_dict["str_to_dec"].get(string, "Unknown")

    @staticmethod
    def find_tcp_str(dec_string: str):
        return TypeHandler.tcp_dict["dec_to_str"].get(dec_string, "Unknown")

    @staticmethod
    def find_udp_dec(string: str):
        return TypeHandler.udp_dict["str_to_dec"].get(string, "Unknown")

    @staticmethod
    def find_udp_str(dec_string: str):
        return TypeHandler.udp_dict["dec_to_str"].get(dec_string, "Unknown")

    @staticmethod
    def find_opcode_str(hex_string: str):
        return TypeHandler.opcode_dict["hex_to_str"].get("0x" + hex_string.upper(), "Unknown")

    @staticmethod
    def find_opcode_hex(string: str):
        return TypeHandler.opcode_dict["str_to_hex"].get(string, "Unknown")

    @staticmethod
    def find_icmp_type_str(hex_string: str):
        return TypeHandler.icmp_type_dict["hex_to_str"].get("0x" + hex_string.upper(), "Unknown")

    @staticmethod
    def find_icmp_type_hex(string: str):
        return TypeHandler.icmp_type_dict["str_to_hex"].get(string, "Unknown")
