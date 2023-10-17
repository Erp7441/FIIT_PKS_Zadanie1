from ruamel.yaml import YAML

from Pcap import Pcap
from utils.Args import Args


# Strips ending "..." and new lines from a data stream
def strip_end(stream):
    if stream.endswith("\n...\n"):
        return str(stream[:-5])

    return str(stream)


class YAMLHandler:

    def __new__(cls):
        raise TypeError("Static only class!")

    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)

    @staticmethod
    def export_pcap(pcap_file: Pcap, path_to_yaml_file: str):

        # Converts packets and pcap classes to dictionaries for neat YAML parsing
        packets = pcap_file.packets
        packets_dict_list = []

        # Pcap file packets
        for packet in packets:
            packets_dict_list.append(packet.__dict__)

        try:
            YAMLHandler._sort_communications(pcap_file)
        except AttributeError:
            pass

        # Copying values so reference gets lost
        pcap_file_dict = pcap_file.__dict__.copy()

        # Sorting the dict keys to match YAML schema
        packets_dict_list = YAMLHandler._sort_dictionary(packets_dict_list)

        if packets_dict_list is not None and len(packets_dict_list) > 0:
            pcap_file_dict["packets"] = packets_dict_list
        else:
            pcap_file_dict.pop("packets")

        # Opening file
        with open(path_to_yaml_file, "w") as file:
            if Args.cdp:
                try:
                    # Removni z pcap file dict ipv4 senders max send packets by a daj tam number_frames
                    pcap_file_dict.pop("ipv4_senders")
                    pcap_file_dict.pop('max_send_packets_by')
                    pcap_file_dict["number_frames"] = len(pcap_file_dict["packets"])
                except KeyError:
                    pass

            # Dumping YAML
            YAMLHandler.yaml.dump(pcap_file_dict, file, transform=strip_end)
            file.close()

        YAMLHandler._format_yaml(path_to_yaml_file)

    @staticmethod
    def _format_yaml(path_to_yaml_file: str):

        # Handling formatting details
        with open(path_to_yaml_file, "r+") as file:
            data = file.read()
            data = data.replace("hexa_frame: |-", "hexa_frame: |")
            data = data.replace("hexa_frame: |+", "hexa_frame: |")
            data = data.replace("  - node:", "\n  - node:")
            data = data.replace("ipv4_senders:\n\n", "ipv4_senders:\n")
            data = data.replace("max_send_packets_by:", "\nmax_send_packets_by:")
            data = data.replace("\ncomplete_comms:", "\n\ncomplete_comms:")
            file.close()

        with open(path_to_yaml_file, "w") as file:
            file.write(data)

    # Reordering attributes
    @staticmethod
    def _sort_dictionary(packets_dict_list):

        # List of attributes to be printed into YAML
        order = [
            "frame_number",
            "len_frame_pcap",
            "len_frame_medium",
            "frame_type",
            "src_mac",
            "dst_mac",
            "ether_type",
            "arp_opcode",
            "src_ip",
            "dst_ip",
            "flags_mf",
            "frag_offset",
            "protocol",
            "src_port",
            "dst_port",
            "app_protocol",
            "icmp_type",
            "icmp_id",
            "icmp_seq",
            "sap",
            "pid",
            "hexa_frame"
        ]

        new_packet_dict_list = []
        for packet in packets_dict_list:
            new_packet = dict()
            for name in order:
                try:
                    new_packet[name] = packet[name]
                except KeyError:
                    continue

            new_packet_dict_list.append(new_packet)

        return new_packet_dict_list

    @staticmethod
    def _sort_communications(pcap_file):
        try:
            # Comm and partial comm section packets
            for entry in pcap_file.complete_comms:
                comm_packet_dict = []
                for packet in entry["packets"]:
                    if type(packet) is list:
                        for subentry in packet:
                            comm_packet_dict.append(subentry.__dict__)
                    else:
                        comm_packet_dict.append(packet.__dict__)
                entry["packets"] = YAMLHandler._sort_dictionary(comm_packet_dict)
        except AttributeError:
            pass

        try:
            # Comm and partial comm section packets
            for entry in pcap_file.partial_comms:
                comm_packet_dict = []
                for packet in entry["packets"]:
                    if type(packet) is list:
                        for subentry in packet:
                            comm_packet_dict.append(subentry.__dict__)
                    else:
                        comm_packet_dict.append(packet.__dict__)
                entry["packets"] = YAMLHandler._sort_dictionary(comm_packet_dict)
        except AttributeError:
            pass
