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

        comm_dict = self.find_tcp_conversations()
        self.communication, self.partial_communication = comm_dict["Complete"], comm_dict["Incomplete"]
        # TODO:: Add UDP
        # TODO:: Add ICMP
        # TODO:: Add ARP

        return True

    def find_tcp_conversations(self):
        tcp_packets = []
        for packet in self.packets:
            if packet.protocol == "TCP":
                tcp_packets.append(packet)

        tcp_conversations = []
        for num, packet in enumerate(tcp_packets):
            tcp_conversations.append (Pcap.find_tcp_conversation(tcp_packets, packet, num))

        return Pcap.sort_tcp_conversations(tcp_conversations)

    @staticmethod
    def find_tcp_conversation(tcp_packets, packet, num):
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

        return {
            "number_comm": num,
            "src_comm": packet.src_ip,
            "dst_comm": packet.dst_ip,
            "packets": tcp_conversation
        }

    @staticmethod
    def sort_tcp_conversations(tcp_conversations: list):

        conversation_dict = {
            "Complete": [],
            "Incomplete": []
        }

        for conversation in tcp_conversations:
            if Pcap.check_tcp_conversation_completeness(conversation["packets"]):
                conversation_dict["Complete"].append(conversation)
            else:
                conversation_dict["Incomplete"].append(conversation)

        conversation_dict["Incomplete"] = conversation_dict["Incomplete"][0]
        return conversation_dict

    @staticmethod
    def check_tcp_conversation_completeness(conversation):
        completeness = 0
        data = fin_sent = False

        for i, packet in enumerate(conversation):
            if i == 0 and packet.flags == "SYN":
                completeness += 1
            elif i == 1 and packet.flags == "SYN ACK":
                completeness += 2
            elif i == 2 and packet.flags == "ACK":
                completeness += 4
            elif i > 2 and not data:
                data = True
                completeness += 8
            elif i > 2:
                if "FIN" in packet.flags and not fin_sent:
                    completeness += 16
                    fin_sent = True
                elif "RST" in packet.flags:
                    completeness += 32

        return completeness == 31 or completeness == 47 or completeness == 63
