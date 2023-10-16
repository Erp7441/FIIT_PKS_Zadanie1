from FrameFactory import FrameFactory
from handlers.FrameHandler import FrameHandler


class ICMP:

    def __new__(cls):
        raise TypeError("Static only class!")

    @staticmethod
    def find_icmp_conversations(packets):
        # TODO:: Disable or enable?
        # packets = ICMP._find_and_rebuild_fragmented_packets(packets)

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
        previous_was_fragment = False

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
                or previous_was_fragment
            ):
                icmp_conversation.append(icmp_packet)

            previous_was_fragment = icmp_packet.flags_mf

        return {
            "number_comm": num + 1,
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
            try:
                conversation_dict["Incomplete"].pop('src_comm')
                conversation_dict["Incomplete"].pop('dst_comm')
            except KeyError:
                pass
        return conversation_dict

    @staticmethod
    def _get_icmp_pairs_and_info(packets):
        icmp_pairs = []
        icmp_unpaired = []
        processed = []

        for i, packet in enumerate(packets):
            if packet in processed:
                continue

            elif (
                    packet.icmp_type == "ECHO REQUEST"
                    and i + 1 <= len(packets) - 1
                    and packets[i + 1].icmp_type == "ECHO REPLY"
            ):
                icmp_pairs.append([packet, packets[i + 1]])
                processed += [packet, packets[i + 1]]
            else:
                icmp_unpaired.append(packet)

        return {
            "Pairs": icmp_pairs,
            "Complete": len(icmp_unpaired) == 0
        }

    @staticmethod
    def _find_and_rebuild_fragmented_packets(packets):
        fragmented = False
        fragments = []
        rebuilt_packets = []
        all_fragments = []

        for packet in packets:
            if packet.flags_mf:
                fragments.append(packet)
                all_fragments.append(packet)
                fragmented = True
            elif fragmented and packet.flags_mf:
                fragments.append(packet)
                all_fragments.append(packet)
            elif fragmented and not packet.flags_mf:
                fragments.append(packet)
                all_fragments.append(packet)
                rebuilt_packets.append({
                    "packet": ICMP._build_fragmented_packet(fragments),
                    "fragments": fragments.copy()
                })
                fragmented = False
                fragments = []

        new_packets = []
        for packet in packets:
            if packet in all_fragments:
                continue
            else:
                new_packets.append(packet)

        for rebuilt_packet in rebuilt_packets:
            new_packets.append(rebuilt_packet['packet'])
        new_packets.sort(key=lambda f: f.frame_number)

        return new_packets


    @staticmethod
    def _build_fragmented_packet(fragments):
        packet_header_bytes = ""
        final_packet = None
        for fragment in fragments:
            packet_header_bytes += FrameHandler.get_fragmeted_ipv4_data(fragment.hexa_frame)
            if not fragment.flags_mf:
                final_packet = fragment

        ethernet_header = FrameHandler.parse_ethernet_ii_header(final_packet.hexa_frame)
        ipv4_header = FrameHandler.parse_ipv4_header(final_packet.hexa_frame)

        new_frame_bytes = bytes.fromhex(ethernet_header + ipv4_header + packet_header_bytes)
        new_frame_bytes = b''.join([bytes([byte]) for byte in new_frame_bytes])

        return FrameFactory.create_frame(final_packet.frame_number - 1, None, new_frame_bytes)