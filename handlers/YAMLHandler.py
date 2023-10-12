from ruamel.yaml import YAML

from Pcap import Pcap


# TODO:: Remove?
# Strips ending "..." and new lines from a data stream
def strip_end(stream):
    if stream.endswith('\n'):
        return str(stream[:-5])


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

        # Comm and partial comm section packets
        for entry in pcap_file.communication:
            comm_packet_dict = []
            for packet in entry["packets"]:
                comm_packet_dict.append(packet.__dict__)
            entry["packets"] = YAMLHandler.sort_dictionary(comm_packet_dict)

        partial_comm_packet_dict = []
        for packet in pcap_file.partial_communication["packets"]:
            partial_comm_packet_dict.append(packet.__dict__)
        pcap_file.partial_communication["packets"] = YAMLHandler.sort_dictionary(partial_comm_packet_dict)

        # Copying values so reference gets lost
        pcap_file_dict = pcap_file.__dict__.copy()

        # Sorting the dict keys to match YAML schema
        packets_dict_list = YAMLHandler.sort_dictionary(packets_dict_list)

        pcap_file_dict["packets"] = packets_dict_list

        # Opening file
        with open(path_to_yaml_file, "w") as file:
            # Dumping YAML
            YAMLHandler.yaml.dump(pcap_file_dict, file, transform=strip_end)
            file.close()

        YAMLHandler.format_yaml(path_to_yaml_file)

    @staticmethod
    def format_yaml(path_to_yaml_file: str):

        # Handling "|"
        with open(path_to_yaml_file, "r+") as file:
            data = file.read()
            data = data.replace("hexa_frame: |-", "hexa_frame: |")
            data = data.replace("hexa_frame: |+", "hexa_frame: |")
            data = data.replace("  - node:", "\n  - node:")
            data = data.replace("ipv4_senders:\n\n", "ipv4_senders:\n")
            data = data.replace("max_send_packets_by:", "\nmax_send_packets_by:")
            data = data.replace("\ncommunication:", "\n\ncommunication:")
            file.close()

        with open(path_to_yaml_file, "w") as file:
            file.write(data)

    # Reordering attributes
    @staticmethod
    def sort_dictionary(packets_dict_list):
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
