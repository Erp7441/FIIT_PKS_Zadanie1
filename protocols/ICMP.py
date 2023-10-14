class ICMP:

    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def find_icmp_conversations(packets):
        icmp_conversations = []
        processed = []
        for num, packet in enumerate(packets):
            if packet in processed:
                continue

            conv = ICMP._find_icmp_conversation(packets, packet, num)
            if conv is not None:
                icmp_conversations.append(conv)
                processed += conv["packets"]

        return ICMP._sort_icmp_conversations(icmp_conversations)

    @staticmethod
    def _find_icmp_conversation(icmp_packets, packet, num):
        ip = [packet.src_ip, packet.dst_ip]

        icmp_conversation = []

        for icmp_packet in icmp_packets:
            if (
                    (
                            (icmp_packet.src_ip in ip and icmp_packet.dst_ip in ip)
                            and (packet.get_icmp_id() == icmp_packet.get_icmp_id())
                    )
                    or
                    (
                            (icmp_packet.icmp_type == "TIME EXCEEDED") and
                            (
                                    icmp_packet.get_icmp_expired_inner_src_ip() in ip
                                    and icmp_packet.get_icmp_expired_inner_dst_ip() in ip
                            )
                    )
            ):
                icmp_conversation.append(icmp_packet)

        return {
            "number_comm": num,
            "src_comm": packet.src_ip,
            "dst_comm": packet.dst_ip,
            "packets": icmp_conversation
        }

    @staticmethod
    def _sort_icmp_conversations(icmp_conversations: list):

        conversation_dict = {
            "Complete": [],
            "Incomplete": []
        }

        for conversation in icmp_conversations:
            icmp_info = ICMP._get_icmp_pairs_and_info(conversation["packets"])
            if icmp_info['Complete']:
                conversation["packets"] = icmp_info["Pairs"]
                conversation_dict["Complete"].append(conversation)

                for pair in conversation["packets"]:
                    pair[0].add_icmp_complete_fields()
                    pair[1].add_icmp_complete_fields()
            else:
                conversation_dict["Incomplete"].append(conversation)

        if len(conversation_dict["Incomplete"]) > 0:
            conversation_dict["Incomplete"] = conversation_dict["Incomplete"][0]
        return conversation_dict

    @staticmethod
    def _get_icmp_pairs_and_info(packets):
        icmp_pairs = []
        icmp_unpaired = []
        processed = []

        for i, packet in enumerate(packets):
            if packet in processed:
                continue
            elif packet.icmp_type == "ECHO REQUEST" and packets[i + 1].icmp_type == "ECHO REPLY":
                icmp_pairs.append([packet, packets[i + 1]])
                processed += [packet, packets[i + 1]]
            else:
                icmp_unpaired.append(packet)

        return {
            "Pairs": icmp_pairs,
            "Complete": len(icmp_unpaired) == 0
        }