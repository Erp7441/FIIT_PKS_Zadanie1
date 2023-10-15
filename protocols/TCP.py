class TCP:
    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def find_tcp_conversations(packets):
        tcp_packets = []
        for packet in packets:
            if packet.ether_type == "IPv4" and packet.protocol == "TCP":
                tcp_packets.append(packet)

        tcp_conversations = []
        for num, packet in enumerate(tcp_packets):
            tcp_conversations.append(TCP._find_tcp_conversation(tcp_packets, packet, num))

        return TCP._sort_tcp_conversations(tcp_conversations)

    @staticmethod
    def _find_tcp_conversation(tcp_packets, packet, num):
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
            "number_comm": num + 1,
            "src_comm": packet.src_ip,
            "dst_comm": packet.dst_ip,
            "packets": tcp_conversation
        }

    @staticmethod
    def _sort_tcp_conversations(tcp_conversations: list):

        conversation_dict = {
            "Complete": [],
            "Incomplete": []
        }

        for conversation in tcp_conversations:
            if TCP._check_tcp_conversation_completeness(conversation["packets"]):
                conversation_dict["Complete"].append(conversation)
            else:
                conversation_dict["Incomplete"].append(conversation)

        if len(conversation_dict["Incomplete"]) > 0:
            conversation_dict["Incomplete"] = conversation_dict["Incomplete"][0]
        return conversation_dict

    @staticmethod
    def _check_tcp_conversation_completeness(conversation):
        completeness = 0
        data = fin_sent = False

        for i, packet in enumerate(conversation):
            if i == 0 and packet.flags == "SYN":
                completeness += 1
            elif i == 1 and packet.flags == "SYN ACK":
                completeness += 2
            elif i == 2 and packet.flags == "ACK":
                completeness += 4
            elif i > 2 and not data and "FIN" not in packet.flags and "RST" not in packet.flags:
                data = True
                completeness += 8
            elif i > 2:
                if "FIN" in packet.flags and not fin_sent:
                    completeness += 16
                    fin_sent = True
                elif "RST" in packet.flags:
                    completeness += 32

        return completeness == 31 or completeness == 47 or completeness == 63
