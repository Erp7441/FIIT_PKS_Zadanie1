import pcap

from FrameFactory import FrameFactory
from frames.FrameEthernet import FrameEthernet


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
