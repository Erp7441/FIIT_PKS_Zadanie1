import pcap

from FrameFactory import FrameFactory
from frames.FrameEthernet import FrameEthernet
from handlers.typehandler.TypeHandler import TypeHandler
from protocols.ARP import ARP
from protocols.ICMP import ICMP
from protocols.TCP import TCP
from protocols.UDP import UDP
from utils.Args import Args


class Pcap:

    def __init__(self, path: str):
        file = pcap.pcap(name=path)

        self.name = "PKS2023/24"
        self.pcap_name = file.name
        self.packets = []

        for index, entry in enumerate(file):
            # Entry [0] is timestamp
            # Entry [1] are bytes
            self.packets.append(FrameFactory.create_frame(index, entry[0], entry[1]))

        self.ipv4_senders = self._find_ipv4_senders()
        self.max_send_packets_by = self._find_max_send_packets()

    def _find_ipv4_senders(self):
        ipv4_senders = dict()

        for packet in self.packets:
            ip = Pcap.extract_packet_src_ip(packet)

            if ip is not None:
                present = ipv4_senders.get(ip, None)
                if present is None:
                    ipv4_senders[ip] = 1
                else:
                    ipv4_senders[ip] += 1

        formatted_senders = []
        for sender in list(ipv4_senders.keys()):
            formatted_sender = {
                "node": sender,
                "number_of_sent_packets": ipv4_senders[sender]
            }
            formatted_senders.append(formatted_sender)

        return formatted_senders

    @staticmethod
    def extract_packet_src_ip(packet):
        # Only for IPv4 packets
        if type(packet) == FrameEthernet and packet.ether_type == "IPv4":
            return packet.src_ip
        return None

    def _find_max_send_packets(self):
        best_senders = [self.ipv4_senders[0]]
        for i, sender in enumerate(self.ipv4_senders):
            if self.ipv4_senders[i]["number_of_sent_packets"] > best_senders[0]["number_of_sent_packets"]:
                best_senders = [sender]
            if (
                    self.ipv4_senders[i]["number_of_sent_packets"] == best_senders[0]["number_of_sent_packets"]
                    and sender != best_senders[0]
            ):
                best_senders.append(sender)

        best_sender_ips = []
        for best_sender in best_senders:
            best_sender_ips.append(best_sender["node"])

        return best_sender_ips

    @staticmethod
    def _get_protocol_type(protocol: str):
        if protocol == "ARP" or protocol == "ICMP":
            return protocol

        tcp = TypeHandler.find_tcp_dec(protocol)
        udp = TypeHandler.find_udp_dec(protocol)

        if tcp != "Unknown" and udp != "Unknown":
            return "BOTH"  # Handle individually
        elif tcp != "Unknown":
            return "TCP"
        elif udp != "Unknown":
            return "UDP"
        else:
            return None

    def filter_out(self, protocol: str, cdp=False):
        if protocol is None and cdp:
            # Filtruj CDP
            new_packet_list = []
            for packet in self.packets:
                try:
                    if packet.pid == "CDP":
                        new_packet_list.append(packet)
                except AttributeError:
                    pass

            self.packets = new_packet_list
            return True

        # Validating
        protocol_type = Pcap._get_protocol_type(protocol)
        if protocol_type is None:
            return False  # Invalid protocol

        # Filtering
        new_packet_list = []
        for packet in self.packets:
            try:
                if packet.compare_protocol(protocol):
                    new_packet_list.append(packet)
            except AttributeError:
                pass

        comm_dict = None
        if protocol_type == "TCP" or protocol_type == "BOTH":
            self.packets = new_packet_list
            comm_dict = TCP.find_tcp_conversations(new_packet_list)
        elif protocol_type == "UDP" or protocol_type == "BOTH":
            comm_dict = UDP.find_udp_conversations(self, protocol)
        elif protocol_type == "ICMP":
            self.packets = new_packet_list
            comm_dict = ICMP.find_icmp_conversations(new_packet_list)
        elif protocol_type == "ARP":
            comm_dict = ARP.find_arp_conversations(self)

        if len(comm_dict['Complete']) > 0:
            self.complete_comms = comm_dict["Complete"]
        if len(comm_dict['Incomplete']) > 0:
            self.partial_comms = comm_dict["Incomplete"]

        return True
