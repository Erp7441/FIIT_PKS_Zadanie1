import pcap

from FrameFactory import FrameFactory
from frames.FrameEthernet import FrameEthernet
from handlers.FrameHandler import FrameHandler
from handlers.typehandler.TypeHandler import TypeHandler


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

        self.ipv4_senders = self.find_ipv4_senders()
        self.max_send_packets_by = self.find_max_send_packets()

    def find_ipv4_senders(self):
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

    def find_max_send_packets(self):
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
    def get_protocol_type(protocol: str):
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

    def filter_out(self, protocol: str):
        # Validating
        protocol_type = Pcap.get_protocol_type(protocol)
        if protocol_type is None:
            return False  # Invalid protocol

        # Filtering
        new_packet_list = []
        for packet in self.packets:
            try:
                if packet.app_protocol == protocol:
                    new_packet_list.append(packet)
            except AttributeError:
                pass

        self.packets = new_packet_list

        self.find_tcp_conversations()  # TODO:: Find suitable placement for method call

        return True

    def find_tcp_conversations(self):
        tcp_packets = []
        for packet in self.packets:
            if packet.protocol == "TCP":
                tcp_packets.append(packet)

        tcp_conversations = []
        for packet in tcp_packets:
            tcp_conversations.append (Pcap.find_tcp_conversation(tcp_packets, packet))

        sorted_convos = Pcap.sort_tcp_conversations(tcp_conversations)
        pass  # TODO:: activate method

    @staticmethod
    def find_tcp_conversation(tcp_packets, packet):
        ip = [packet.src_ip, packet.dst_ip]
        ports = [packet.src_port, packet.dst_port]

        tcp_conversation = []

        for tcp_packet in tcp_packets:
            if (
                (tcp_packet.src_ip in ip and tcp_packet.dst_ip in ip) and
                (tcp_packet.src_port in ports and tcp_packet.dst_port in ports)
            ):
                tcp_conversation.append(tcp_packet)

        for packet in tcp_conversation:
            tcp_packets.remove(packet)

        return tcp_conversation

    # TODO:: Implement methods
    @staticmethod
    def sort_tcp_conversations(tcp_converstations: list):

        for conversation in tcp_converstations:
            check = Pcap.check_tcp_conversation_completeness(conversation)

        pass

    @staticmethod
    def check_tcp_conversation_completeness(conversation):
        establish = ["SYN", "SYN ACK", "ACK"]
        terminate = ["FIN", "FIN ACK", "ACK"]
        for packet in conversation:
            pass
