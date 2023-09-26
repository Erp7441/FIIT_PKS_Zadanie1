from ruamel.yaml import YAML

from Pcap import Pcap


# Strips ending "..." and new lines from a data stream
def strip_end(stream):
    if stream.endswith('...\n'):
        return str(stream[:-5])


class YAMLHandler:

    def __new__(cls):
        raise TypeError("Static only class!")

    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)

    # TODO:: remove legacy code
    # Register classes
    # yaml.register_class(Pcap)
    # yaml.register_class(Frame)
    # yaml.register_class(FrameEthernet)
    # yaml.register_class(FrameEOT)
    # yaml.register_class(FrameRAW)
    # yaml.register_class(FrameLCC)
    # yaml.register_class(FrameSNAP)
    # yaml.explicit_start = False
    # yaml.Representer = RoundTripRepresenter
    # yaml.compact(seq_seq=False, seq_map=False)
    # yaml.preserve_quotes = False

    @staticmethod
    def export_pcap(pcap_file: Pcap, path_to_yaml_file: str):

        # Converts packets and pcap classes to dictionaries for neat YAML parsing
        packets = pcap_file.packets
        packets_dict_list = []

        for packet in packets:
            packets_dict_list.append(packet.__dict__)

        pcap_file_dict = pcap_file.__dict__.copy()
        packets_dict_list = YAMLHandler.sort_dictionary(packets_dict_list)
        pcap_file_dict["packets"] = packets_dict_list

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
